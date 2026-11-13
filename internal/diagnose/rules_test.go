package diagnose

import (
	"strings"
	"testing"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// The messages in these tests are the ones the kubelet, scheduler and controllers write, copied from Kubernetes
// 1.37 and containerd 2.x.

func TestHealthyNamespaceHasNoFindings(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 2)
	s.Pods = []kube.Pod{pod("web-rs-a", "web"), pod("web-rs-b", "web")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 2)}
	r := Diagnose(s)
	if len(r.Findings) != 0 {
		t.Fatalf("healthy namespace: %+v", r.Findings)
	}
	if r.Checked.Pods != 2 || r.Checked.Services != 1 {
		t.Errorf("checked %+v", r.Checked)
	}
}

func TestImageTagNotFound(t *testing.T) {
	s := snap()
	deployment(s, "web", 3, 0)
	for _, n := range []string{"web-rs-a", "web-rs-b", "web-rs-c"} {
		p := pod(n, "web")
		waiting(&p, "ImagePullBackOff", `Back-off pulling image "registry.example.com/shop/web:1.4.2"`)
		s.Pods = append(s.Pods, p)
		s.Events = append(s.Events, event("Pod", n, "Failed", `Failed to pull image "registry.example.com/shop/web:1.4.2": rpc error: code = NotFound desc = failed to pull and unpack image "registry.example.com/shop/web:1.4.2": failed to resolve reference "registry.example.com/shop/web:1.4.2": registry.example.com/shop/web:1.4.2: not found`, time.Minute))
	}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD101", "Deployment shop/web", "registry.example.com/shop/web:1.4.2 does not exist", "0 of 3 replicas ready")
	if f.Severity != Critical || len(f.Affects) != 4 || f.Affects[3] != (kube.Ref{Kind: "Service", Namespace: "shop", Name: "web"}) {
		t.Errorf("severity %s affects %v", f.Severity, f.Affects)
	}
	if !strings.Contains(f.Evidence[1].Detail, "not found") {
		t.Errorf("the pull error event should be evidence: %+v", f.Evidence)
	}
}

func TestImageRepositoryMissingOrPrivate(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "doesnotexist/web:1"
	waiting(&p, "ErrImagePull", "")
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Failed", `Failed to pull image "doesnotexist/web:1": failed to pull and unpack image "docker.io/doesnotexist/web:1": failed to resolve reference "docker.io/doesnotexist/web:1": pull access denied, repository does not exist or may require authorization: server message: insufficient_scope: authorization failed`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD102", "Pod shop/web", "does not exist, or it is private", "it answered pull access denied")
	if !strings.Contains(f.Fix, "imagePullSecrets") {
		t.Errorf("fix should mention imagePullSecrets: %s", f.Fix)
	}
}

func TestRegistryAnswers403(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "ghcr.io/acme/missing:1.0.0"
	waiting(&p, "ErrImagePull", "")
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Failed", `Failed to pull image "ghcr.io/acme/missing:1.0.0": failed to pull and unpack image "ghcr.io/acme/missing:1.0.0": failed to resolve reference "ghcr.io/acme/missing:1.0.0": failed to authorize: failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token?scope=repository%3Aacme%2Fmissing%3Apull&service=ghcr.io: 403 Forbidden`, 0)}
	expect(t, only(t, Diagnose(s)), "KD102", "Pod shop/web", "refused to serve image ghcr.io/acme/missing:1.0.0 (it answered 403 forbidden)")
}

func TestCrashLoopCaughtWhileRunning(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Status.ContainerStatuses[0].RestartCount = 4
	p.Status.ContainerStatuses[0].LastTerminationState = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}}
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"error: DATABASE_URL is not set"}}}
	expect(t, only(t, Diagnose(s)), "KD110", "Pod shop/web", "DATABASE_URL")

	p.Status.ContainerStatuses[0].RestartCount = 1 // one restart while running is not yet a loop
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestNodeProblemsInANamespaceScanOnlyWhenTheyRunItsPods(t *testing.T) {
	s := snap()
	s.Nodes = append(s.Nodes, node("node-2", "8", "32Gi"))
	s.Nodes[1].Status.Conditions = append(s.Nodes[1].Status.Conditions, kube.Condition{Type: "DiskPressure", Status: "True", Message: "ephemeral-storage low"})
	s.Pods = []kube.Pod{pod("web", "")} // on node-1
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("node-2 runs no pod of this namespace: %+v", r.Findings)
	}
	s.Namespaces = nil // an all-namespaces scan reports every node
	expect(t, only(t, Diagnose(s)), "KD191", "Node node-2", "DiskPressure")
}

func TestRegistryUnreachable(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "registry.internal/web:1"
	waiting(&p, "ImagePullBackOff", "")
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Failed", `Failed to pull image "registry.internal/web:1": failed to resolve reference "registry.internal/web:1": failed to do request: Head "https://registry.internal/v2/web/manifests/1": dial tcp: lookup registry.internal on 10.96.0.10:53: no such host`, 0)}
	expect(t, only(t, Diagnose(s)), "KD103", "Pod shop/web", "cannot reach the registry")
}

func TestInvalidImageName(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "Registry.Example.com/Web:latest"
	waiting(&p, "InvalidImageName", `Failed to apply default image tag "Registry.Example.com/Web:latest": couldn't parse image name`)
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD104", "Pod shop/web", "not a valid image reference")
}

func TestCrashLoopQuotesTheErrorLine(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	crashed(&p, 1, "Error", 6)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true,
		Lines: []string{"starting web 1.4.2", "loading config", "error: DATABASE_URL is not set", "exiting"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "Deployment shop/web", "exits with code 1", `"error: DATABASE_URL is not set"`)
	if !strings.Contains(f.Evidence[1].Command, "--previous") || !strings.Contains(f.Evidence[1].Detail, "DATABASE_URL") {
		t.Errorf("log evidence: %+v", f.Evidence)
	}
}

func TestCrashLoopExitZeroExplainsLongRunningContainers(t *testing.T) {
	s := snap()
	p := pod("web", "")
	crashed(&p, 0, "Completed", 4)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "Pod shop/web", "finishes with code 0")
	if !strings.Contains(f.Fix, "Job") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestOOMKilled(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "64Mi"}
	crashed(&p, 137, "OOMKilled", 3)
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD111", "Pod shop/web", "64Mi memory limit", "OOMKilled")
}

func TestOOMKilledWhileRunningIsAWarning(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Status.ContainerStatuses[0].RestartCount = 2
	p.Status.ContainerStatuses[0].LastTerminationState = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD111", "Pod shop/web", "OOMKilled")
	if f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}
}

func TestLivenessProbeOnTheWrongPort(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/healthz", Port: port(9090)}}
	crashed(&p, 137, "Error", 5)
	s.Pods = []kube.Pod{p}
	e1 := event("Pod", "web", "Unhealthy", `Liveness probe failed: Get "http://10.244.0.7:9090/healthz": dial tcp 10.244.0.7:9090: connect: connection refused`, time.Minute)
	e1.InvolvedObject.FieldPath = "spec.containers{web}"
	e2 := event("Pod", "web", "Killing", "Container web failed liveness probe, will be restarted", 2*time.Minute)
	e2.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e1, e2}
	f := only(t, Diagnose(s))
	expect(t, f, "KD112", "Pod shop/web", "GET /healthz on port 9090", "declares port 8080")
}

func TestReadinessProbeFailing(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 0)
	for _, n := range []string{"web-rs-a", "web-rs-b"} {
		p := pod(n, "web")
		p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/ready", Port: named("http")}}
		notReady(&p)
		s.Pods = append(s.Pods, p)
		s.Events = append(s.Events, event("Pod", n, "Unhealthy", "Readiness probe failed: HTTP probe failed with statuscode: 404", 0))
	}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	f := only(t, Diagnose(s))
	expect(t, f, "KD120", "Deployment shop/web", "fails its readiness probe (GET /ready on port http)")
	if len(f.Affects) != 3 {
		t.Errorf("affects %v", f.Affects)
	}
}

func TestMissingConfigMapForEnv(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].EnvFrom = []kube.EnvFromSource{{ConfigMapRef: &kube.NameRef{Name: "app-config"}}}
	waiting(&p, "CreateContainerConfigError", `configmap "app-config" not found`)
	s.Pods = []kube.Pod{p}
	s.ConfigMaps = []kube.KeySet{keys("shop", "kube-root-ca.crt", "ca.crt")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD130", "Pod shop/web", "needs ConfigMap app-config, which does not exist")
	if len(f.Evidence) != 2 || f.Evidence[1].Command != "kubectl get configmap app-config -n shop" {
		t.Errorf("evidence %+v", f.Evidence)
	}
}

func TestMissingSecretKey(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Env = []kube.EnvVar{{Name: "DB_PASSWORD", ValueFrom: &kube.EnvVarSource{SecretKeyRef: &kube.KeyRef{Name: "db", Key: "password"}}}}
	waiting(&p, "CreateContainerConfigError", "couldn't find key password in Secret shop/db")
	s.Pods = []kube.Pod{p}
	s.Secrets = []kube.KeySet{keys("shop", "db", "pass", "user")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD132", "Pod shop/web", "reads key password from Secret db")
	if !strings.Contains(f.Evidence[1].What, "keys pass, user, not password") {
		t.Errorf("evidence %+v", f.Evidence)
	}
}

func TestMissingConfigMapVolume(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Status.Phase = "Pending"
	waiting(&p, "ContainerCreating", "")
	p.Spec.Volumes = []kube.Volume{{Name: "config", ConfigMap: &kube.ConfigMapVolumeSource{Name: "nginx-conf"}}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "FailedMount", `MountVolume.SetUp failed for volume "config" : configmap "nginx-conf" not found`, 0)}
	expect(t, only(t, Diagnose(s)), "KD130", "Pod shop/web", "a volume of the pod needs ConfigMap nginx-conf")
}

func TestUnschedulableInsufficientCPU(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.NodeName = ""
	p.Spec.Containers[0].Resources.Requests = map[string]string{"cpu": "64"}
	p.Status.Phase = "Pending"
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 Insufficient cpu. preemption: 0/1 nodes are available: 1 No preemption victims found for incoming pod."}}
	p.Status.ContainerStatuses = nil
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD140", "Pod shop/web", "requests 64 cpu", "node-1, has 8 allocatable")
}

func TestUnschedulableNodeSelector(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.NodeName, p.Spec.NodeSelector = "", map[string]string{"disktype": "ssd"}
	p.Status.Phase = "Pending"
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."}}
	p.Status.ContainerStatuses = nil
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD141", "Pod shop/web", "disktype=ssd")
}

func TestUnschedulableMixedReasons(t *testing.T) {
	s := snap()
	s.Nodes = append(s.Nodes, node("gpu-1", "32", "128Gi"), node("gpu-2", "32", "128Gi"))
	p := pod("web", "")
	p.Spec.NodeName = ""
	p.Spec.Containers[0].Resources.Requests = map[string]string{"cpu": "16"}
	p.Status.Phase = "Pending"
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/3 nodes are available: 1 Insufficient cpu, 2 node(s) had untolerated taint {nvidia.com/gpu: present}. preemption: 0/3 nodes are available: 1 No preemption victims found for incoming pod, 2 Preemption is not helpful for scheduling."}}
	p.Status.ContainerStatuses = nil
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD142", "Pod shop/web", "2 nodes have taint nvidia.com/gpu: present", "1 node has too little free cpu")
}

func TestPodWaitsForPVCWithMissingStorageClass(t *testing.T) {
	s := snap()
	s.StorageClasses = []kube.StorageClass{{Metadata: kube.ObjectMeta{Name: "standard", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}}, Provisioner: "rancher.io/local-path"}}
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Spec.StorageClassName = strp("fast-ssd")
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	s.Events = []kube.Event{event("PersistentVolumeClaim", "data", "ProvisioningFailed", `storageclass.storage.k8s.io "fast-ssd" not found`, 0)}
	p := pod("db", "")
	p.Spec.NodeName = ""
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	p.Status.Phase = "Pending"
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."}}
	p.Status.ContainerStatuses = nil
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD150", "PersistentVolumeClaim shop/data", "StorageClass fast-ssd, which does not exist", "standard (default)")
	if len(f.Affects) != 1 || f.Affects[0].Name != "db" {
		t.Errorf("the waiting pod should be listed under the claim: %v", f.Affects)
	}
}

func TestPVCWithNoDefaultStorageClass(t *testing.T) {
	s := snap()
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	expect(t, only(t, Diagnose(s)), "KD151", "PersistentVolumeClaim shop/data", "no default one")
}

func TestServiceSelectorMatchesNoPods(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Metadata.Labels = map[string]string{"app": "webapp"}
	s.Pods = []kube.Pod{p}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD160", "Service shop/web", "selects pods with app=web", "closest are app=webapp")
}

func TestServiceSelectorMatchingAScaledDownWorkloadIsFine(t *testing.T) {
	s := snap()
	deployment(s, "web", 0, 0)
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Fatalf("%+v", r.Findings)
	}
}

func TestServiceNamedTargetPortMissing(t *testing.T) {
	s := snap()
	s.Pods = []kube.Pod{pod("web", "")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("web"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD161", "Service shop/web", `named port "web"`, "http (8080)")
}

func TestServiceNumericTargetPortNotDeclared(t *testing.T) {
	s := snap()
	s.Pods = []kube.Pod{pod("web", "")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, port(80))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD164", "Service shop/web", "to port 80", "declare only port 8080")
	if f.Severity != Warning {
		t.Errorf("an undeclared port may be intended: severity %s", f.Severity)
	}
}

func TestNetworkPolicyDeniesAllIngressToAService(t *testing.T) {
	s := snap()
	s.Pods = []kube.Pod{pod("web", "")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	var np kube.NetworkPolicy
	np.Metadata = kube.ObjectMeta{Name: "default-deny", Namespace: "shop"}
	np.Spec.PolicyTypes = []string{"Ingress"}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	f := only(t, Diagnose(s))
	expect(t, f, "KD163", "NetworkPolicy shop/default-deny", "allows no ingress", "Service web")

	allow := np
	allow.Metadata.Name = "allow-web"
	allow.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	allow.Spec.Ingress = []kube.NetworkPolicyRule{{}}
	s.NetworkPolicies = append(s.NetworkPolicies, allow)
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("an allowing policy makes the deny-all intended: %+v", r.Findings)
	}
}

func TestQuotaExhausted(t *testing.T) {
	s := snap()
	deployment(s, "web", 3, 1)
	s.Workloads[1].Status.Replicas = 1
	s.Pods = []kube.Pod{pod("web-rs-a", "web")}
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate", `Error creating: pods "web-rs-x7k2q" is forbidden: exceeded quota: pod-limit, requested: pods=1, used: pods=2, limited: pods=2`, 0)}
	expect(t, only(t, Diagnose(s)), "KD170", "Deployment shop/web", "ResourceQuota pod-limit is used up", "limit pods=2")
}

func TestServiceAccountMissing(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	s.Workloads[1].Status.Replicas = 0
	s.ServiceAccounts = []kube.ServiceAccount{{Metadata: kube.ObjectMeta{Name: "default", Namespace: "shop"}}}
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate", `Error creating: pods "web-rs-" is forbidden: error looking up service account shop/web-sa: serviceaccount "web-sa" not found`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD171", "Deployment shop/web", "ServiceAccount web-sa, which does not exist")
	if len(f.Evidence) != 2 {
		t.Errorf("the missing ServiceAccount should be evidence: %+v", f.Evidence)
	}
}

func TestPodSecurityRejects(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	s.Workloads[1].Status.Replicas = 0
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate", `Error creating: pods "web-rs-9ckx2" is forbidden: violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false (container "web" must set securityContext.allowPrivilegeEscalation=false), runAsNonRoot != true (pod or container "web" must set securityContext.runAsNonRoot=true)`, 0)}
	expect(t, only(t, Diagnose(s)), "KD172", "Deployment shop/web", `PodSecurity level restricted:latest`, "allowPrivilegeEscalation")
}

func TestInitContainerFails(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.InitContainers = []kube.Container{{Name: "migrate", Image: "registry.example.com/shop/migrate:3"}}
	p.Status.Phase = "Pending"
	notReady(&p)
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "migrate", RestartCount: 4,
		State:                kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		LastTerminationState: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 2, Reason: "Error"}}}}
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "PodInitializing"}}
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "migrate", Previous: true, Lines: []string{"migrating", "FATAL: password authentication failed for user \"app\""}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD115", "Pod shop/web", "container migrate exits with code 2", "password authentication failed")
	if !strings.Contains(f.Evidence[0].Command, "initContainerStatuses") {
		t.Errorf("init container evidence should read initContainerStatuses: %s", f.Evidence[0].Command)
	}
}

func TestCommandNotFound(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Command = []string{"webserver"}
	crashed(&p, 128, "StartError", 3)
	p.Status.ContainerStatuses[0].LastTerminationState.Terminated.Message = `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: exec: "webserver": executable file not found in $PATH: unknown`
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD114", "Pod shop/web", `runs "webserver", which is not in image`)
}

func TestExecFormatError(t *testing.T) {
	s := snap()
	p := pod("web", "")
	crashed(&p, 255, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"exec /usr/local/bin/web: exec format error"}}}
	expect(t, only(t, Diagnose(s)), "KD113", "Pod shop/web", "another CPU architecture")
}

func TestFailedJobPod(t *testing.T) {
	s := snap()
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "report", Namespace: "shop"}
	j.Status.Failed = 4
	j.Status.Conditions = []kube.Condition{{Type: "Failed", Status: "True", Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}}
	s.Jobs = []kube.Job{j}
	p := pod("report-x1", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "report", Controller: yes()}}
	p.Status.Phase = "Failed"
	notReady(&p)
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 3, Reason: "Error"}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "Job shop/report", "exited with code 3")

	s.Pods = nil // the failed pods were cleaned up: the Job's condition is all that is left
	expect(t, only(t, Diagnose(s)), "KD180", "Job shop/report", "BackoffLimitExceeded")
}

func TestNodeNotReady(t *testing.T) {
	s := snap()
	s.Nodes[0].Status.Conditions[0] = kube.Condition{Type: "Ready", Status: "Unknown", Reason: "NodeStatusUnknown", Message: "Kubelet stopped posting node status."}
	s.Pods = []kube.Pod{pod("web", "")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD190", "Node node-1", "stopped reporting")
	if len(f.Affects) != 1 {
		t.Errorf("affects %v", f.Affects)
	}
}

func TestRolloutWithReadyReplicasIsAWarning(t *testing.T) {
	s := snap()
	deployment(s, "web", 3, 2)
	p := pod("web-rs-c", "web")
	waiting(&p, "ImagePullBackOff", "")
	s.Pods = []kube.Pod{pod("web-rs-a", "web"), pod("web-rs-b", "web"), p}
	s.Events = []kube.Event{event("Pod", "web-rs-c", "Failed", `Failed to pull image "registry.example.com/shop/web:1.4.2": not found`, 0)}
	f := only(t, Diagnose(s))
	if f.Severity != Warning || !strings.Contains(f.Cause, "2 of 3 replicas ready") {
		t.Errorf("severity %s cause %s", f.Severity, f.Cause)
	}
}

func TestAbsenceIsNotClaimedWhenTheListWasNotRead(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].EnvFrom = []kube.EnvFromSource{{ConfigMapRef: &kube.NameRef{Name: "app-config"}}}
	waiting(&p, "CreateContainerConfigError", `configmap "app-config" not found`)
	s.Pods = []kube.Pod{p}
	s.Gaps = []snapshot.Gap{{Resource: "configmaps", Namespace: "shop", Error: "forbidden"}}
	f := only(t, Diagnose(s))
	if f.Rule != "KD130" || len(f.Evidence) != 1 {
		t.Errorf("without the ConfigMap list, the kubelet's message is the only evidence: %+v", f.Evidence)
	}
}
