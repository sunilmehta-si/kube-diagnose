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

func TestProbeCommandNotInTheImage(t *testing.T) {
	const noCurl = `OCI runtime exec failed: exec failed: unable to start container process: exec: "curl": executable file not found in $PATH: unknown`
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{Exec: &kube.ExecAction{Command: []string{"curl", "-f", "http://localhost:8080/healthz"}}}
	crashed(&p, 137, "Error", 3)
	s.Pods = []kube.Pod{p}
	e1 := event("Pod", "web", "Unhealthy", "Liveness probe failed: "+noCurl, time.Minute)
	e1.InvolvedObject.FieldPath = "spec.containers{web}"
	e2 := event("Pod", "web", "Killing", "Container web failed liveness probe, will be restarted", 2*time.Minute)
	e2.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e1, e2}
	f := only(t, Diagnose(s))
	expect(t, f, "KD112", "Pod shop/web", "liveness probe runs curl, which is not in image registry.example.com/shop/web:1.4.2")
	if !strings.Contains(f.Fix, "httpGet") {
		t.Errorf("fix: %s", f.Fix)
	}

	// The same for a readiness probe, which leaves the container out of its Services instead.
	s = snap()
	p = pod("web", "")
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{Exec: &kube.ExecAction{Command: []string{"curl", "-f", "http://localhost:8080/ready"}}}
	notReady(&p)
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Unhealthy", "Readiness probe errored and resulted in unknown state: rpc error: code = Unknown desc = failed to exec in container: failed to start exec \"5f2c\": "+noCurl, 0)}
	expect(t, only(t, Diagnose(s)), "KD120", "Pod shop/web", "readiness probe runs curl, which is not in image")

	// A probe that fails for another reason keeps its own explanation.
	s.Events = []kube.Event{event("Pod", "web", "Unhealthy", "Readiness probe failed: curl: (7) Failed to connect to localhost port 8080", 0)}
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "not in image") {
		t.Errorf("a refused connection is not a missing command: %s", f.Cause)
	}
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

// TestJustExitedContainers covers the moment between a container's exit and the kubelet's back-off: the state is
// terminated, the pod phase still Running or Pending. The fault suite's first run on kind caught all four of these.
func TestJustExitedContainers(t *testing.T) {
	exited := func(p *kube.Pod, code int32, reason string) {
		notReady(p)
		p.Status.ContainerStatuses[0].RestartCount = 4
		term := &kube.ContainerStateTerminated{ExitCode: code, Reason: reason}
		p.Status.ContainerStatuses[0].State = kube.ContainerState{Terminated: term}
		p.Status.ContainerStatuses[0].LastTerminationState = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: code, Reason: reason}}
	}
	s := snap()
	p := pod("web", "")
	exited(&p, 1, "Error")
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Lines: []string{"starting web", "error: DATABASE_URL is not set"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "Pod shop/web", "DATABASE_URL")
	if !strings.Contains(f.Evidence[0].Command, "state.terminated") || strings.Contains(f.Evidence[1].Command, "--previous") {
		t.Errorf("a container that just exited is described by its current state and log: %+v", f.Evidence)
	}

	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Lines: []string{"unable to retrieve container logs for containerd://81d11b66"}}}
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "unable to retrieve") || len(f.Evidence) != 1 {
		t.Errorf("the kubelet's note that a log is gone is not the app's log: %s", f.Cause)
	}

	p = pod("web", "")
	p.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "32Mi"}
	exited(&p, 137, "OOMKilled")
	s.Pods, s.Logs = []kube.Pod{p}, nil
	expect(t, only(t, Diagnose(s)), "KD111", "Pod shop/web", "32Mi memory limit")

	p = pod("web", "")
	exited(&p, 255, "Error")
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Lines: []string{"exec /bin/sleep: exec format error"}}}
	expect(t, only(t, Diagnose(s)), "KD113", "Pod shop/web", "another CPU architecture")

	p = pod("web", "")
	p.Status.Phase = "Pending"
	p.Spec.InitContainers = []kube.Container{{Name: "wait-for-db", Image: "busybox"}}
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "wait-for-db", RestartCount: 4,
		State: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 2, Reason: "Error"}}}}
	notReady(&p)
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "PodInitializing"}}
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "wait-for-db", Lines: []string{"FATAL: cannot reach db:5432"}}}
	expect(t, only(t, Diagnose(s)), "KD115", "Pod shop/web", "db:5432")

	p = pod("web", "")
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 1}}
	notReady(&p)
	s.Pods, s.Logs = []kube.Pod{p}, nil
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a first exit with no restart yet is not a crash loop: %+v", r.Findings)
	}
}

func TestRegistryRateLimit(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "docker.io/library/nginx:1.29"
	waiting(&p, "ErrImagePull", "")
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Failed", `Failed to pull image "docker.io/library/nginx:1.29": failed to pull and unpack image "docker.io/library/nginx:1.29": failed to copy: httpReadSeeker: failed open: unexpected status code https://registry-1.docker.io/v2/library/nginx/manifests/sha256:4f1d: 429 Too Many Requests - Server message: toomanyrequests: You have reached your unauthenticated pull rate limit. https://www.docker.com/increase-rate-limit`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD105", "Pod shop/web", "rate-limiting pulls of image docker.io/library/nginx:1.29")
	if !strings.Contains(f.Fix, "imagePullSecrets") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestImagePullSecretMissing(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "ghcr.io/acme/web:2.0"
	p.Spec.ImagePullSecrets = []kube.LocalObjectReference{{Name: "ghcr-creds"}}
	waiting(&p, "ImagePullBackOff", "")
	s.Pods = []kube.Pod{p}
	s.Secrets = []kube.KeySet{keys("shop", "default-token", "token")}
	s.Events = []kube.Event{
		event("Pod", "web", "Failed", `Failed to pull image "ghcr.io/acme/web:2.0": failed to resolve reference "ghcr.io/acme/web:2.0": failed to authorize: failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token: 401 Unauthorized`, 0),
		event("Pod", "web", "FailedToRetrieveImagePullSecret", "Unable to retrieve some image pull secrets (ghcr-creds); attempting to pull the image may not succeed.", time.Minute),
	}
	f := only(t, Diagnose(s))
	expect(t, f, "KD106", "Pod shop/web", "imagePullSecret ghcr-creds, which does not exist")
	if len(f.Evidence) != 4 {
		t.Errorf("evidence: %+v", f.Evidence)
	}

	s.Secrets = append(s.Secrets, kube.KeySet{Namespace: "shop", Name: "ghcr-creds", Type: "kubernetes.io/dockerconfigjson", Keys: []string{".dockerconfigjson"}})
	expect(t, only(t, Diagnose(s)), "KD102", "Pod shop/web", "it answered 401 unauthorized")

	s.Gaps = []snapshot.Gap{{Resource: "secrets", Error: "forbidden"}}
	s.Secrets = nil
	expect(t, only(t, Diagnose(s)), "KD102", "Pod shop/web", "refused")
}

func TestImagePullSecretWrongType(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "ghcr.io/acme/web:2.0"
	p.Spec.ImagePullSecrets = []kube.LocalObjectReference{{Name: "ghcr-creds"}}
	waiting(&p, "ErrImagePull", "")
	s.Pods = []kube.Pod{p}
	s.Secrets = []kube.KeySet{{Namespace: "shop", Name: "ghcr-creds", Type: "Opaque", Keys: []string{"password", "username"}}}
	s.Events = []kube.Event{event("Pod", "web", "Failed", `Failed to pull image "ghcr.io/acme/web:2.0": failed to authorize: 403 Forbidden`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD107", "Pod shop/web", "imagePullSecret ghcr-creds has type Opaque")
	if !strings.Contains(f.Evidence[len(f.Evidence)-1].What, "keys password, username") {
		t.Errorf("evidence: %+v", f.Evidence)
	}
}

func TestPostStartHookFails(t *testing.T) {
	s := snap()
	p := pod("web", "")
	crashed(&p, 137, "Error", 3)
	s.Pods = []kube.Pod{p}
	e1 := event("Pod", "web", "FailedPostStartHook", `Exec lifecycle hook ([sh -c /opt/warm-cache.sh]) for Container "web" in Pod "web_shop(5f1c)" failed - error: command 'sh -c /opt/warm-cache.sh' exited with 127: sh: /opt/warm-cache.sh: not found, message: "sh: /opt/warm-cache.sh: not found\n"`, 0)
	e1.InvolvedObject.FieldPath = "spec.containers{web}"
	e2 := event("Pod", "web", "FailedPostStartHook", "PostStartHook failed", 0)
	e2.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e1, e2}
	f := only(t, Diagnose(s))
	expect(t, f, "KD116", "Pod shop/web", "postStart hook fails", "/opt/warm-cache.sh: not found")
}

func TestRunAsNonRootWithARootImage(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Image = "nginx:1.29"
	waiting(&p, "CreateContainerConfigError", `container has runAsNonRoot and image will run as root (pod: "web_shop(5f1c)", container: web)`)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD117", "Pod shop/web", "must run as a non-root user (runAsNonRoot), but image nginx:1.29 runs as root")

	waiting(&p, "CreateContainerConfigError", `container has runAsNonRoot and image has non-numeric user (appuser), cannot verify user is non-root (pod: "web_shop(5f1c)", container: web)`)
	s.Pods = []kube.Pod{p}
	f = only(t, Diagnose(s))
	expect(t, f, "KD117", "Pod shop/web", `names its user "appuser"`)
	if !strings.Contains(f.Fix, "numeric UID of appuser") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestReadOnlyRootFilesystem(t *testing.T) {
	s := snap()
	p := pod("web", "")
	ro := true
	p.Spec.Containers[0].SecurityContext = &kube.SecurityContext{ReadOnlyRootFilesystem: &ro}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{
		"/docker-entrypoint.sh: Configuration complete; ready for start up",
		`nginx: [emerg] mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)`}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD118", "Pod shop/web", "read-only root filesystem")
	if !strings.Contains(f.Fix, "/var/cache/nginx/client_temp") {
		t.Errorf("fix should name the path: %s", f.Fix)
	}

	s.Logs[0].Lines = []string{"mkdir: can't create directory '/data/cache': Read-only file system"}
	if f = only(t, Diagnose(s)); !strings.Contains(f.Fix, "emptyDir at /data/cache") {
		t.Errorf("busybox message: %s", f.Fix)
	}

	p.Spec.Containers[0].SecurityContext = nil // the same log without the setting is an ordinary crash
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD110", "Pod shop/web", "Read-only file system")
}

func TestEvictions(t *testing.T) {
	evict := func(msg string) *snapshot.Snapshot {
		s := snap()
		p := pod("web", "")
		p.Status.Phase, p.Status.Reason, p.Status.Message = "Failed", "Evicted", msg
		s.Pods = []kube.Pod{p}
		return s
	}
	expect(t, only(t, Diagnose(evict(`Container web exceeded its local ephemeral storage limit "500Mi". `))), "KD193", "Pod shop/web",
		"container web was evicted for writing more to its local disk than its 500Mi ephemeral-storage limit")
	expect(t, only(t, Diagnose(evict("Pod ephemeral local storage usage exceeds the total limit of containers 1Gi."))), "KD193", "Pod shop/web", "limit (1Gi)")
	// The kubelet's message ends with a space, as recorded on Kubernetes 1.37 in the fault suite.
	expect(t, only(t, Diagnose(evict("Pod ephemeral local storage usage exceeds the total limit of containers 10Mi. "))), "KD193", "Pod shop/web", "limit (10Mi)")
	expect(t, only(t, Diagnose(evict("The node was low on resource: ephemeral-storage. Threshold quantity: 3Gi, available: 1Gi. Container web was using 2Gi, request is 0, has larger consumption of ephemeral-storage. "))),
		"KD192", "Pod shop/web", "the node ran low on ephemeral-storage")
}

func unschedulablePod(msg string) kube.Pod {
	p := pod("web", "")
	p.Spec.NodeName = ""
	p.Status.Phase = "Pending"
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable", Message: msg}}
	p.Status.ContainerStatuses = nil
	return p
}

func TestUnschedulableSpreadAndAffinity(t *testing.T) {
	s := snap()
	s.Pods = []kube.Pod{unschedulablePod("0/1 nodes are available: 1 node(s) didn't match pod topology spread constraints. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.")}
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web", "1 node fails its topology spread constraints")
	s.Pods = []kube.Pod{unschedulablePod("0/3 nodes are available: 3 node(s) didn't match pod anti-affinity rules. preemption: 0/3 nodes are available: 3 No preemption victims found for incoming pod.")}
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web", "3 nodes fail its pod anti-affinity rules")
	s.Pods = []kube.Pod{unschedulablePod("0/2 nodes are available: 2 node(s) didn't match pod topology spread constraints (missing required label). preemption: 0/2 nodes are available: 2 Preemption is not helpful for scheduling.")}
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web", "lack the label the constraint's topologyKey names")
}

func TestUnschedulableHostPort(t *testing.T) {
	s := snap()
	p := unschedulablePod("0/1 nodes are available: 1 node(s) didn't have free ports for the requested pod ports. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.")
	p.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "http", ContainerPort: 8080, HostPort: 80}}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD145", "Pod shop/web", "1 node has hostPort 80 in use already")
}

func TestUnschedulableVolumeNodeAffinity(t *testing.T) {
	s := snap()
	p := unschedulablePod("0/3 nodes are available: 1 Insufficient memory, 2 node(s) had volume node affinity conflict. preemption: 0/3 nodes are available: 1 No preemption victims found for incoming pod, 2 Preemption is not helpful for scheduling.")
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	s.Pods = []kube.Pod{p}
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Spec.VolumeName = "pvc-7f3a"
	pvc.Status.Phase = "Bound"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	f := only(t, Diagnose(s))
	expect(t, f, "KD154", "Pod shop/web", "2 nodes are outside the node or zone that volume pvc-7f3a (claim data) is pinned to", "1 node has too little free memory")
}

func TestMultiAttach(t *testing.T) {
	s := snap()
	p := pod("db", "")
	p.Status.Phase = "Pending"
	waiting(&p, "ContainerCreating", "")
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "db", "FailedAttachVolume", `Multi-Attach error for volume "pvc-7f3a" Volume is already used by pod(s) db-5c9f-old, exclusively attached to one node and can't be attached to another`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD155", "Pod shop/db", "volume pvc-7f3a can be attached to one node at a time and is still in use by pod db-5c9f-old")
	if !strings.Contains(f.Fix, "Recreate") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.Events = []kube.Event{event("Pod", "db", "FailedAttachVolume", `Multi-Attach error for volume "pvc-7f3a" Volume is already exclusively attached to one node and can't be attached to another`, 0)}
	expect(t, only(t, Diagnose(s)), "KD155", "Pod shop/db", "still attached elsewhere")
}

func TestLimitRangeRejects(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 0)
	s.Workloads[1].Status.Replicas = 0
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate", `Error creating: pods "web-rs-8kq2v" is forbidden: [maximum memory usage per Container is 512Mi, but limit is 1Gi, minimum cpu usage per Container is 100m, but request is 50m]`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD174", "Deployment shop/web", "maximum memory usage per Container is 512Mi, but limit is 1Gi; minimum cpu usage per Container is 100m, but request is 50m")
}

func TestPriorityClassMissing(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	s.Workloads[1].Status.Replicas = 0
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate", `Error creating: pods "web-rs-" is forbidden: no PriorityClass with name business-critical was found`, 0)}
	expect(t, only(t, Diagnose(s)), "KD175", "Deployment shop/web", "PriorityClass business-critical, which does not exist")
}

func TestRuntimeClassMissing(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	s.Workloads[1].Status.Replicas = 0
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate", `Error creating: pods "web-rs-x7k2p" is forbidden: pod rejected: RuntimeClass "gvisor" not found`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD183", "Deployment shop/web", "RuntimeClass gvisor, which does not exist")
	if !strings.Contains(f.Fix, "remove runtimeClassName") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestPodWaitsForAMissingScheduler(t *testing.T) {
	s := snap()
	p := pod("train", "")
	p.Spec.NodeName, p.Spec.SchedulerName = "", "volcano"
	p.Status.Phase, p.Status.Conditions, p.Status.ContainerStatuses = "Pending", nil, nil
	p.Metadata.CreationTimestamp = t0.Add(-10 * time.Minute)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD148", "Pod shop/train", "asks for scheduler volcano and no scheduler has looked at it in 10m0s")

	p.Metadata.CreationTimestamp = t0.Add(-30 * time.Second) // too new to tell
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("young pod: %+v", r.Findings)
	}
	p.Metadata.CreationTimestamp = t0.Add(-10 * time.Minute)
	p.Spec.SchedulerName = "default-scheduler"
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("default scheduler: %+v", r.Findings)
	}
}

func hpa(name string, conditions ...kube.Condition) kube.HorizontalPodAutoscaler {
	var h kube.HorizontalPodAutoscaler
	h.Metadata = kube.ObjectMeta{Name: name, Namespace: "shop"}
	h.Spec.ScaleTargetRef.Kind, h.Spec.ScaleTargetRef.Name = "Deployment", "web"
	h.Spec.MaxReplicas = 5
	h.Status.Conditions = conditions
	return h
}

func TestHPACannotReadMetrics(t *testing.T) {
	s := snap()
	s.HPAs = []kube.HorizontalPodAutoscaler{hpa("web", kube.Condition{Type: "ScalingActive", Status: "False", Reason: "FailedGetResourceMetric",
		Message: "the HPA was unable to compute the replica count: failed to get cpu utilization: unable to get metrics for resource cpu: unable to fetch metrics from resource metrics API: the server could not find the requested resource (get pods.metrics.k8s.io)"})}
	f := only(t, Diagnose(s))
	expect(t, f, "KD176", "HorizontalPodAutoscaler shop/web", "metrics API (metrics-server) is not answering")
	if f.Severity != Warning || f.Affects[0].Name != "web" {
		t.Errorf("%+v", f)
	}

	s.HPAs[0].Status.Conditions[0].Message = "the HPA was unable to compute the replica count: failed to get cpu utilization: missing request for cpu in container web of Pod web-6f9c-x2k4f"
	expect(t, only(t, Diagnose(s)), "KD176", "HorizontalPodAutoscaler shop/web", "container web sets no cpu request")

	s.HPAs[0].Status.Conditions[0] = kube.Condition{Type: "ScalingActive", Status: "True", Reason: "ValidMetricFound"}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("working HPA: %+v", r.Findings)
	}
}

func TestHPAHeldAtMaximum(t *testing.T) {
	s := snap()
	h := hpa("web", kube.Condition{Type: "ScalingActive", Status: "True", Reason: "ValidMetricFound"},
		kube.Condition{Type: "ScalingLimited", Status: "True", Reason: "TooManyReplicas", Message: "the desired replica count is more than the maximum replica count"})
	h.Status.CurrentReplicas = 5
	s.HPAs = []kube.HorizontalPodAutoscaler{h}
	expect(t, only(t, Diagnose(s)), "KD177", "HorizontalPodAutoscaler shop/web", "maxReplicas of 5, so the workload runs at 5 replicas")
}

func TestHPATargetMissing(t *testing.T) {
	s := snap()
	s.HPAs = []kube.HorizontalPodAutoscaler{hpa("web", kube.Condition{Type: "AbleToScale", Status: "False", Reason: "FailedGetScale",
		Message: `the HPA controller was unable to get the target's current scale: deployments.apps "web" not found`})}
	f := only(t, Diagnose(s))
	expect(t, f, "KD178", "HorizontalPodAutoscaler shop/web", "scales Deployment web, which does not exist")
	if len(f.Evidence) != 2 || f.Evidence[1].Command != "kubectl get deployment web -n shop" {
		t.Errorf("evidence %+v", f.Evidence)
	}
}

func TestPDBAllowsNoDisruptions(t *testing.T) {
	s := snap()
	var b kube.PodDisruptionBudget
	b.Metadata = kube.ObjectMeta{Name: "web", Namespace: "shop"}
	b.Spec.MinAvailable = &kube.IntOrString{Int: 2}
	b.Status.DisruptionsAllowed, b.Status.CurrentHealthy, b.Status.DesiredHealthy, b.Status.ExpectedPods = 0, 2, 2, 2
	s.PDBs = []kube.PodDisruptionBudget{b}
	expect(t, only(t, Diagnose(s)), "KD185", "PodDisruptionBudget shop/web", "allows 0 disruptions with all 2 of its pods healthy (minAvailable 2)")

	s.PDBs[0].Status.CurrentHealthy = 1 // at zero because a pod is unhealthy: that pod is the problem
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	s.PDBs[0].Status.CurrentHealthy, s.PDBs[0].Status.DisruptionsAllowed = 2, 1
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func ingress(name, svc string, port int32, portName string) kube.Ingress {
	var ing kube.Ingress
	ing.Metadata = kube.ObjectMeta{Name: name, Namespace: "shop"}
	b := &kube.IngressServiceBackend{Name: svc}
	b.Port.Number, b.Port.Name = port, portName
	rule := kube.IngressRule{Host: "shop.example.com"}
	rule.HTTP = &struct {
		Paths []kube.HTTPIngressPath `json:"paths"`
	}{Paths: []kube.HTTPIngressPath{{Path: "/api", Backend: kube.IngressBackend{Service: b}}}}
	ing.Spec.Rules = []kube.IngressRule{rule}
	return ing
}

// defaultIngressClass gives the cluster an IngressClass marked default, so backend tests have a served Ingress.
func defaultIngressClass(s *snapshot.Snapshot) {
	s.IngressClasses = []kube.IngressClass{{Metadata: kube.ObjectMeta{Name: "nginx",
		Annotations: map[string]string{"ingressclass.kubernetes.io/is-default-class": "true"}}}}
}

func TestIngressBackendServiceMissing(t *testing.T) {
	s := snap()
	defaultIngressClass(s)
	s.Pods = []kube.Pod{pod("web", "")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Ingresses = []kube.Ingress{ingress("shop", "web-api", 80, "")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD165", "Ingress shop/shop", "Service web-api (for shop.example.com/api), which does not exist")

	s.Ingresses = []kube.Ingress{ingress("shop", "web", 80, "")}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestIngressBackendPortMissing(t *testing.T) {
	s := snap()
	defaultIngressClass(s)
	s.Pods = []kube.Pod{pod("web", "")}
	svc := service("web", map[string]string{"app": "web"}, named("http"))
	svc.Spec.Ports[0].Name = "http"
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Ingresses = []kube.Ingress{ingress("shop", "web", 8080, "")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD166", "Ingress shop/shop", "port 8080 of Service web (for shop.example.com/api), which has ports http (80)")

	s.Ingresses = []kube.Ingress{ingress("shop", "web", 0, "https")}
	expect(t, only(t, Diagnose(s)), "KD166", "Ingress shop/shop", `port "https" of Service web`)

	s.Ingresses = []kube.Ingress{ingress("shop", "web", 0, "http")}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestIngressClassMissing(t *testing.T) {
	s := snap()
	s.Pods = []kube.Pod{pod("web", "")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	ing := ingress("shop", "web", 80, "")
	class := "nginx-internal"
	ing.Spec.IngressClassName = &class
	s.Ingresses = []kube.Ingress{ing}
	s.IngressClasses = []kube.IngressClass{{Metadata: kube.ObjectMeta{Name: "nginx"}}}
	expect(t, only(t, Diagnose(s)), "KD167", "Ingress shop/shop", "asks for IngressClass nginx-internal, which does not exist (the cluster has nginx)")

	s.Ingresses[0].Spec.IngressClassName = nil
	expect(t, only(t, Diagnose(s)), "KD167", "Ingress shop/shop", "names no IngressClass and none is marked default")

	s.IngressClasses[0].Metadata.Annotations = map[string]string{"ingressclass.kubernetes.io/is-default-class": "true"}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("default class: %+v", r.Findings)
	}
	s.IngressClasses = nil
	s.Ingresses[0].Metadata.Annotations = map[string]string{"kubernetes.io/ingress.class": "nginx"}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("legacy annotation: %+v", r.Findings)
	}
	s.Ingresses[0].Metadata.Annotations = nil
	s.Gaps = []snapshot.Gap{{Resource: "ingressclasses.networking.k8s.io", Error: "forbidden"}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("unread class list: %+v", r.Findings)
	}
}

// TestPostStartHookFailsWithTheBareKubeletEvent uses the events Kubernetes 1.37 wrote in the fault suite: the event
// says only "PostStartHook failed", so the hook is named from the pod spec.
func TestPostStartHookFailsWithTheBareKubeletEvent(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Lifecycle = &kube.Lifecycle{PostStart: &kube.LifecycleHandler{Exec: &kube.ExecAction{Command: []string{"sh", "-c", "/opt/warm-cache.sh"}}}}
	crashed(&p, 137, "Error", 4)
	s.Pods = []kube.Pod{p}
	e1 := event("Pod", "web", "FailedPostStartHook", "PostStartHook failed", 0)
	e1.InvolvedObject.FieldPath = "spec.containers{web}"
	e2 := event("Pod", "web", "Killing", "FailedPostStartHook", 0)
	e2.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e1, e2}
	f := only(t, Diagnose(s))
	expect(t, f, "KD116", "Pod shop/web", "postStart hook (sh -c /opt/warm-cache.sh) fails")
}

func TestImageNeverPulled(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Containers[0].ImagePullPolicy = "Never"
	waiting(&p, "ErrImageNeverPull", `Container image "registry.example.com/shop/web:1.4.2" is not present with pull policy of Never`)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD108", "Deployment shop/web", "registry.example.com/shop/web:1.4.2 is not on node-1", "imagePullPolicy is Never")
}

func TestInitContainerNeverFinishes(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.InitContainers = []kube.Container{{Name: "wait-for-db", Image: "busybox"}}
	p.Status.Phase = "Pending"
	waiting(&p, "PodInitializing", "")
	started := t0.Add(-5 * time.Minute)
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "wait-for-db", State: kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: started}}}}
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "wait-for-db", Lines: []string{"waiting for db:5432", "waiting for db:5432"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD119", "Deployment shop/web", "init container wait-for-db has run for 5m0s", "waiting for db:5432")

	// When it loops on a lookup of a Service name, the missing Service is named.
	s.Logs[0].Lines = []string{"waiting for db:5432", "wget: bad address 'db:5432'"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD119", "Deployment shop/web", "it waits for db, and there is no Service db in namespace shop")

	// Init containers that have run for a short while are just starting.
	p.Status.InitContainerStatuses[0].State.Running.StartedAt = t0.Add(-30 * time.Second)
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("an init container 30 s in is not stuck: %+v", r.Findings)
	}
}

func TestCrashOnAMissingService(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true,
		Lines: []string{"starting", `panic: dial tcp: lookup payments on 10.96.0.10:53: no such host`}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD121", "Deployment shop/web", "cannot resolve payments", "no Service payments in namespace shop")

	// With the Service there, the lookup failure is DNS trouble of another kind, left to the crash rule.
	s.Services = []kube.Service{service("payments", map[string]string{"app": "payments"}, port(8080))}
	if f := Diagnose(s).Findings[0]; f.Rule != "KD110" {
		t.Errorf("with Service payments present: %s %s", f.Rule, f.Cause)
	}
}

func TestPortAlreadyInUse(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Containers = append(p.Spec.Containers, kube.Container{Name: "metrics", Image: "registry.example.com/shop/metrics:2",
		Ports: []kube.ContainerPort{{Name: "metrics", ContainerPort: 8080}}})
	p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, kube.ContainerStatus{Name: "metrics",
		State:                kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		LastTerminationState: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}}, RestartCount: 3})
	notReady(&p)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "metrics", Previous: true, Lines: []string{"listen tcp :8080: bind: address already in use"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD122", "Deployment shop/web", "port 8080 is already in use", "container web of the same pod also listens on 8080")
}

func TestServiceOfAWorkloadScaledToZero(t *testing.T) {
	s := snap()
	deployment(s, "web", 0, 0)
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	var ing kube.Ingress
	ing.Metadata = kube.ObjectMeta{Name: "shop", Namespace: "shop"}
	ing.Spec.DefaultBackend = &kube.IngressBackend{Service: &kube.IngressServiceBackend{Name: "web"}}
	ing.Spec.DefaultBackend.Service.Port.Number = 80
	s.Ingresses = []kube.Ingress{ing}
	s.IngressClasses = []kube.IngressClass{{Metadata: kube.ObjectMeta{Name: "nginx", Annotations: map[string]string{"ingressclass.kubernetes.io/is-default-class": "true"}}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD160", "Service shop/web", "Ingress shop sends traffic", "Deployment web is scaled to 0 replicas")
	if f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}
	// Running replicas that have not made pods yet are left to the controller findings.
	deployment(s, "web", 2, 0)
	s.Workloads = s.Workloads[2:]
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a workload with replicas: %+v", r.Findings)
	}
}

func TestPDBSelectsNoPods(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 1)
	s.Pods = []kube.Pod{pod("web-rs-a", "web")}
	var b kube.PodDisruptionBudget
	b.Metadata = kube.ObjectMeta{Name: "web", Namespace: "shop"}
	b.Spec.MinAvailable = &kube.IntOrString{Int: 1}
	b.Spec.Selector = &kube.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}}
	s.PDBs = []kube.PodDisruptionBudget{b}
	f := only(t, Diagnose(s))
	expect(t, f, "KD186", "PodDisruptionBudget shop/web", "selects pods with app=frontend", "the closest pod labels are app=web")

	s.PDBs[0].Spec.Selector.MatchLabels["app"] = "web"
	s.PDBs[0].Status.ExpectedPods, s.PDBs[0].Status.CurrentHealthy, s.PDBs[0].Status.DesiredHealthy, s.PDBs[0].Status.DisruptionsAllowed = 1, 1, 1, 0
	if f := only(t, Diagnose(s)); f.Rule != "KD185" {
		t.Errorf("a budget that covers the pod: %s", f.Rule)
	}
}

func TestLoadBalancerWithoutAnAddress(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 1)
	s.Pods = []kube.Pod{pod("web-rs-a", "web")}
	svc := service("web", map[string]string{"app": "web"}, named("http"))
	svc.Spec.Type = "LoadBalancer"
	svc.Metadata.CreationTimestamp = t0.Add(-10 * time.Minute)
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD168", "Service shop/web", "no external address for 10m0s", "nothing in the cluster provisions load balancers")

	s.Events = []kube.Event{event("Service", "web", "SyncLoadBalancerFailed", `Error syncing load balancer: failed to ensure load balancer: googleapi: Error 403: QUOTA_EXCEEDED`, time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD168", "Service shop/web", "fails to create one", "QUOTA_EXCEEDED")

	s.Services[0].Metadata.CreationTimestamp = t0.Add(-30 * time.Second)
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a new Service waits for its address: %+v", r.Findings)
	}
}

func TestIngressTLSSecret(t *testing.T) {
	s := snap()
	defaultIngressClass(s)
	deployment(s, "web", 1, 1)
	s.Pods = []kube.Pod{pod("web-rs-a", "web")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	ing := ingress("shop", "web", 80, "")
	ing.Spec.TLS = []kube.IngressTLS{{Hosts: []string{"shop.example.com"}, SecretName: "shop-tls"}}
	s.Ingresses = []kube.Ingress{ing}
	expect(t, only(t, Diagnose(s)), "KD169", "Ingress shop/shop", "Secret shop-tls, which does not exist", "shop.example.com")

	s.Secrets = []kube.KeySet{{Namespace: "shop", Name: "shop-tls", Type: "Opaque", Keys: []string{"cert.pem", "key.pem"}}}
	expect(t, only(t, Diagnose(s)), "KD169", "Ingress shop/shop", "which has no tls.crt and tls.key")

	s.Secrets = []kube.KeySet{{Namespace: "shop", Name: "shop-tls", Type: "kubernetes.io/tls", Keys: []string{"tls.crt", "tls.key"}}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a good TLS Secret: %+v", r.Findings)
	}
}

func TestStatefulSetGoverningService(t *testing.T) {
	s := snap()
	var replicas int32 = 1
	ss := kube.Workload{Kind: "StatefulSet", Metadata: kube.ObjectMeta{Name: "db", Namespace: "shop"}}
	ss.Spec.Replicas, ss.Spec.ServiceName = &replicas, "db-headless"
	ss.Spec.Template.Metadata.Labels = map[string]string{"app": "web"}
	ss.Status.Replicas, ss.Status.ReadyReplicas = 1, 1
	s.Workloads = []kube.Workload{ss}
	p := pod("db-0", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "StatefulSet", Name: "db", Controller: yes()}}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD182", "StatefulSet shop/db", "Service db-headless does not exist", "db-0.db-headless.shop.svc does not resolve")

	svc := service("db-headless", map[string]string{"app": "web"}, named("http"))
	svc.Spec.ClusterIP = "10.96.4.20"
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("db-headless", 1)}
	expect(t, only(t, Diagnose(s)), "KD182", "StatefulSet shop/db", "is not headless (it has clusterIP 10.96.4.20)")

	s.Services[0].Spec.ClusterIP = "None"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a headless governing Service: %+v", r.Findings)
	}
}

func TestClaimAccessModeNotSupported(t *testing.T) {
	s := snap()
	var sc kube.StorageClass
	sc.Metadata = kube.ObjectMeta{Name: "standard", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}}
	sc.Provisioner, sc.VolumeBindingMode = "rancher.io/local-path", "WaitForFirstConsumer"
	s.StorageClasses = []kube.StorageClass{sc}
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "shared", Namespace: "shop"}
	pvc.Spec.AccessModes = []string{"ReadWriteMany"}
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	p := pod("web", "")
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "shared"}}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("PersistentVolumeClaim", "shared", "ProvisioningFailed",
		`failed to provision volume with StorageClass "standard": NodePath only supports ReadWriteOnce and ReadWriteOncePod (1.22+) access modes`, time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD156", "PersistentVolumeClaim shop/shared", "asks for access mode ReadWriteMany", "the default StorageClass standard", "NodePath only supports")
}

func TestNetworkPolicyBlocksDNS(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.Services = []kube.Service{service("db", map[string]string{"app": "db"}, port(5432))}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"wget: bad address 'db:5432'"}}}
	var np kube.NetworkPolicy
	np.Metadata = kube.ObjectMeta{Name: "egress-db-only", Namespace: "shop"}
	np.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	np.Spec.PolicyTypes = []string{"Egress"}
	tcp5432 := kube.IntOrString{Int: 5432}
	rule := kube.NetworkPolicyRule{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"app": "db"}}}}}
	rule.Ports = append(rule.Ports, struct {
		Port *kube.IntOrString `json:"port,omitempty"`
	}{Port: &tcp5432})
	np.Spec.Egress = []kube.NetworkPolicyRule{rule}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	f := Diagnose(s).Findings[0]
	expect(t, f, "KD123", "Deployment shop/web", "cannot resolve db", "NetworkPolicy egress-db-only restricts its egress")

	// Allowing port 53 lets DNS out: the crash is something else.
	dns := kube.IntOrString{Int: 53}
	s.NetworkPolicies[0].Spec.Egress = append(s.NetworkPolicies[0].Spec.Egress, kube.NetworkPolicyRule{})
	s.NetworkPolicies[0].Spec.Egress[1].Ports = append(s.NetworkPolicies[0].Spec.Egress[1].Ports, struct {
		Port *kube.IntOrString `json:"port,omitempty"`
	}{Port: &dns})
	if f := Diagnose(s).Findings[0]; f.Rule == "KD123" {
		t.Errorf("DNS is allowed: %s", f.Cause)
	}
}

func TestCrashOnARefusedServiceWithNoPods(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	db := service("db", map[string]string{"app": "db"}, port(5432))
	db.Spec.ClusterIP = "10.96.12.7"
	s.Services = []kube.Service{db}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"wget: can't connect to remote host (10.96.12.7): Connection refused"}}}
	f := Diagnose(s).Findings[0]
	expect(t, f, "KD124", "Deployment shop/web", "Service db refuses its connection", "no pod has its selector's labels app=db")

	s.Logs[0].Lines = []string{`psql: error: connection to server at "db" (10.96.12.7), port 5432 failed: Connection refused`}
	expect(t, Diagnose(s).Findings[0], "KD124", "Deployment shop/web", "Service db refuses its connection")

	// A Service with a ready pod refuses for another reason: the crash rule quotes the log.
	q := pod("db-1", "")
	q.Metadata.Labels = map[string]string{"app": "db"}
	s.Pods = append(s.Pods, q)
	if f := Diagnose(s).Findings[0]; f.Rule != "KD110" {
		t.Errorf("with a ready db pod: %s %s", f.Rule, f.Cause)
	}
}

func TestCronJobRunsFailingAreOneFinding(t *testing.T) {
	s := snap()
	for _, run := range []string{"backup-29001", "backup-29002"} {
		var j kube.Job
		j.Metadata = kube.ObjectMeta{Name: run, Namespace: "shop", OwnerReferences: []kube.OwnerReference{{Kind: "CronJob", Name: "backup", Controller: yes()}}}
		j.Status.Failed = 1
		j.Status.Conditions = []kube.Condition{{Type: "Failed", Status: "True", Reason: "BackoffLimitExceeded"}}
		s.Jobs = append(s.Jobs, j)
		p := pod(run+"-x", "")
		p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: run, Controller: yes()}}
		p.Status.Phase = "Failed"
		notReady(&p)
		p.Status.ContainerStatuses[0].State = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 2, Reason: "Error"}}
		s.Pods = append(s.Pods, p)
	}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "CronJob shop/backup", "exited with code 2")
	if len(f.Affects) != 2 {
		t.Errorf("affects %v", f.Affects)
	}
}

func TestImageWithoutTheNodesPlatform(t *testing.T) {
	s := snap()
	s.Nodes[0].Metadata.Labels["kubernetes.io/arch"], s.Nodes[0].Metadata.Labels["kubernetes.io/os"] = "amd64", "linux"
	p := pod("web", "")
	p.Spec.Containers[0].Image = "docker.io/arm64v8/busybox:1.37.0"
	waiting(&p, "ErrImagePull", "")
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Failed", `Failed to pull image "docker.io/arm64v8/busybox:1.37.0": rpc error: code = NotFound desc = failed to pull and unpack image "docker.io/arm64v8/busybox:1.37.0": no match for platform in manifest: not found`, 0)}
	expect(t, only(t, Diagnose(s)), "KD109", "Pod shop/web", "has no build for linux/amd64")
}

func TestSidecarIsNotAnInitContainerThatNeverFinishes(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.InitContainers = []kube.Container{{Name: "proxy", Image: "busybox", RestartPolicy: "Always"}, {Name: "wait-for-db", Image: "busybox"}}
	p.Status.Phase = "Pending"
	waiting(&p, "PodInitializing", "")
	started := t0.Add(-10 * time.Minute)
	running := kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: started}}
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "proxy", Ready: true, State: running}, {Name: "wait-for-db", State: running}}
	s.Pods = []kube.Pod{p}
	// The sidecar has run as long as the init container after it, and it is the init container that holds the pod.
	expect(t, only(t, Diagnose(s)), "KD119", "Deployment shop/web", "init container wait-for-db has run for 10m0s")

	// A sidecar alone in a pending pod is not stuck: something after it holds the pod, and this rule cannot say what.
	p.Spec.InitContainers = p.Spec.InitContainers[:1]
	p.Status.InitContainerStatuses = p.Status.InitContainerStatuses[:1]
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a running sidecar is not a stuck init container: %+v", r.Findings)
	}
}

func TestSidecarThatKeepsCrashing(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.InitContainers = []kube.Container{{Name: "proxy", Image: "registry.example.com/shop/proxy:2", RestartPolicy: "Always"}}
	p.Status.Phase = "Pending"
	notReady(&p)
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "proxy", RestartCount: 5,
		State:                kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "CrashLoopBackOff"}},
		LastTerminationState: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 1, Reason: "Error"}}}}
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "PodInitializing"}}
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "proxy", Previous: true, Lines: []string{"error: upstream address is not set"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "Pod shop/web", "sidecar container proxy exits with code 1", "upstream address is not set")
	if !strings.Contains(f.Fix, "restartPolicy: Always") || !strings.Contains(f.Evidence[0].Command, "initContainerStatuses") {
		t.Errorf("fix %q, evidence %q", f.Fix, f.Evidence[0].Command)
	}
}

func TestPodHeldByASchedulingGate(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.NodeName = ""
	p.Spec.SchedulingGates = []kube.SchedulingGate{{Name: "example.com/quota-check"}}
	p.Status.Phase, p.Status.ContainerStatuses = "Pending", nil
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "SchedulingGated", Message: "Scheduling is blocked due to non-empty scheduling gates"}}
	p.Metadata.CreationTimestamp = t0.Add(-12 * time.Minute)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD146", "Deployment shop/web", "waited 12m0s behind scheduling gate example.com/quota-check", "0 of 1 replicas ready")
	if !strings.Contains(f.Fix, "example.com/quota-check") {
		t.Errorf("fix should name the gate: %s", f.Fix)
	}

	// Kueue's gate: the pod waits for admission, and its queue is named.
	p.Spec.SchedulingGates = []kube.SchedulingGate{{Name: "kueue.x-k8s.io/admission"}}
	p.Metadata.Labels["kueue.x-k8s.io/queue-name"] = "team-a"
	s.Pods = []kube.Pod{p}
	f = only(t, Diagnose(s))
	expect(t, f, "KD146", "Deployment shop/web", "Kueue has not admitted it", "LocalQueue team-a")
	if !strings.Contains(f.Evidence[1].Command, "workloads.kueue.x-k8s.io") {
		t.Errorf("evidence should point at the Workloads: %+v", f.Evidence)
	}

	// A controller that gates pods releases them within seconds: a young gated pod is not a finding.
	p.Metadata.CreationTimestamp = t0.Add(-20 * time.Second)
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a pod gated for 20 s: %+v", r.Findings)
	}
}

// creating returns a pod that is on its node with every container still waiting in ContainerCreating.
func creating(name, owner string) kube.Pod {
	p := pod(name, owner)
	p.Status.Phase = "Pending"
	waiting(&p, "ContainerCreating", "")
	return p
}

func TestPodSandboxCannotBeCreated(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	s.Pods = []kube.Pod{creating("web-rs-a", "web")}
	s.Events = []kube.Event{event("Pod", "web-rs-a", "FailedCreatePodSandBox", `Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox "0c1f2a": plugin type="calico" failed (add): error getting ClusterInformation: connection is unauthorized: Unauthorized`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD134", "Deployment shop/web", "network plugin calico on node node-1 fails to set up the pod's network", "connection is unauthorized")
	if strings.Contains(f.Cause, "rpc error") {
		t.Errorf("the gRPC wrapper should be dropped from the cause: %s", f.Cause)
	}

	// The node's pod IP range is used up.
	s.Events = []kube.Event{event("Pod", "web-rs-a", "FailedCreatePodSandBox", `Failed to create pod sandbox: rpc error: code = Unknown desc = failed to setup network for sandbox "0c1f2a": plugin type="ptp" failed (add): failed to allocate for range 0: no IP addresses available in range set: 10.244.1.1-10.244.1.254`, time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD134", "Deployment shop/web", "node node-1 cannot give the pod an IP address")

	// Anything else is quoted as the runtime reported it.
	s.Events = []kube.Event{event("Pod", "web-rs-a", "FailedCreatePodSandBox", `Failed to create pod sandbox: rpc error: code = Unknown desc = failed to create containerd task: failed to create shim task: OCI runtime create failed: unable to start container process`, time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD134", "Deployment shop/web", "node node-1 cannot create the pod's sandbox", "OCI runtime create failed")

	// A sandbox failure that was retried and passed is history: the container has started.
	p := pod("web-rs-a", "web")
	s.Pods = []kube.Pod{p}
	s.Workloads = nil
	deployment(s, "web", 1, 1)
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a running pod with an old sandbox event: %+v", r.Findings)
	}
}
