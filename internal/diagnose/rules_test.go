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

// TestOOMKillReportedAsError is what the fault suite recorded once on Kubernetes 1.37 with containerd 2: a container
// that runs out of memory as it starts, reported with exit code 137 and reason Error.
func TestOOMKillReportedAsError(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "32Mi"}
	crashed(&p, 137, "Error", 5)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD111", "Pod shop/web", "killed by SIGKILL (exit 137)", "32Mi memory limit", "reported the kill as Error, not OOMKilled")

	// Without a memory limit nothing points at memory: it stays a crash with the signal explained.
	p.Spec.Containers[0].Resources.Limits = nil
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD110", "Pod shop/web", "killed by SIGKILL")
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

	// The request came from a LimitRange default, not the pod template.
	s.Pods[0].Metadata.Annotations = map[string]string{"kubernetes.io/limit-ranger": "LimitRanger plugin set: cpu, memory request for container web; memory limit for container web"}
	f := only(t, Diagnose(s))
	expect(t, f, "KD140", "Pod shop/web", "requests 64 cpu", "sets no cpu request for container web: the namespace's LimitRange gave it its default")
	if !strings.Contains(f.Fix, "defaultRequest for cpu") {
		t.Errorf("fix %q", f.Fix)
	}
	if limitRangerSet(s.Pods[0], "memory") != "web" || limitRangerSet(s.Pods[0], "ephemeral-storage") != "" {
		t.Errorf("limitRangerSet misreads the annotation")
	}
	s.Pods[0].Metadata.Annotations["kubernetes.io/limit-ranger"] = "LimitRanger plugin set: cpu limit for container web"
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "LimitRange") {
		t.Errorf("a defaulted limit is not a defaulted request: %s", f.Cause)
	}
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

func TestQuotaStopsAStatefulSetsClaim(t *testing.T) {
	s := snap()
	var replicas int32 = 1
	ss := kube.Workload{Kind: "StatefulSet", Metadata: kube.ObjectMeta{Name: "db", Namespace: "shop"}}
	ss.Spec.Replicas, ss.Spec.ServiceName = &replicas, "db"
	s.Workloads = []kube.Workload{ss}
	headless := service("db", nil, port(5432))
	headless.Spec.ClusterIP = "None"
	s.Services = []kube.Service{headless}
	s.EndpointSlices = []kube.EndpointSlice{slice("db", 1)}
	s.Events = []kube.Event{event("StatefulSet", "db", "FailedCreate", `create Claim data-db-0 for Pod db-0 in StatefulSet db failed error: persistentvolumeclaims "data-db-0" is forbidden: exceeded quota: storage, requested: requests.storage=1Gi, used: requests.storage=0, limited: requests.storage=100Mi`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD170", "StatefulSet shop/db", "cannot create PersistentVolumeClaim data-db-0 from its volumeClaimTemplates", "ResourceQuota storage is used up", "limit requests.storage=100Mi")
	if !strings.Contains(f.Fix, "volumeClaimTemplates") {
		t.Errorf("fix %q", f.Fix)
	}
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
	f := only(t, Diagnose(evict(`Usage of EmptyDir volume "cache" exceeds the limit "10Mi". `)))
	expect(t, f, "KD193", "Pod shop/web", "emptyDir volume cache holds more than its 10Mi sizeLimit")
	if f.Title != "emptyDir volume exceeded its size limit" || !strings.Contains(f.Fix, "sizeLimit of emptyDir volume cache") {
		t.Errorf("title %q fix %q", f.Title, f.Fix)
	}
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

	s.Services[0].Spec.ClusterIP, s.Services[0].Spec.Ports[0].Port = "None", 8080 // headless, so its port is the pods' port
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

func TestServiceAccountTokenNotMounted(t *testing.T) {
	no := false
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.ServiceAccountName = "operator"
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.ServiceAccounts = []kube.ServiceAccount{{Metadata: kube.ObjectMeta{Name: "operator", Namespace: "shop"}, AutomountServiceAccountToken: &no}}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{
		`E1116 08:12:01.000000       1 main.go:40] error building in-cluster config: open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory`}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD125", "Deployment shop/web", "its ServiceAccount operator sets automountServiceAccountToken: false")

	// The pod's own setting, with busybox's wording.
	s.ServiceAccounts = nil
	p.Spec.AutomountServiceAccountToken = &no
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{`cat: can't open '/var/run/secrets/kubernetes.io/serviceaccount/token': No such file or directory`}
	expect(t, only(t, Diagnose(s)), "KD125", "Deployment shop/web", "the pod sets automountServiceAccountToken: false")

	// With the token mounted, a missing file is something else, and stays a crash.
	p.Spec.AutomountServiceAccountToken = nil
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD110", "Deployment shop/web")
}

func TestServiceAccountLacksRBACPermission(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.ServiceAccountName = "operator"
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"starting informers",
		`F1116 08:12:01.000000       1 main.go:52] failed to list *v1.ConfigMap: configmaps is forbidden: User "system:serviceaccount:shop:operator" cannot list resource "configmaps" in API group "" in the namespace "shop"`}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD126", "Deployment shop/web", "refuses its ServiceAccount operator: it may not list configmaps in namespace shop")
	if !strings.Contains(f.Fix, "kubectl create role operator-configmaps -n shop --verb=list --resource=configmaps") ||
		!strings.Contains(f.Fix, "--serviceaccount=shop:operator") {
		t.Errorf("fix: %s", f.Fix)
	}

	// A cluster-scoped denial for a resource in an API group.
	s.Logs[0].Lines = []string{`Error from server (Forbidden): nodes.metrics.k8s.io is forbidden: User "system:serviceaccount:shop:operator" cannot list resource "nodes" in API group "metrics.k8s.io" at the cluster scope`}
	f = only(t, Diagnose(s))
	expect(t, f, "KD126", "Deployment shop/web", "it may not list nodes.metrics.k8s.io across the cluster")
	if !strings.Contains(f.Fix, "kubectl create clusterrole operator-nodes --verb=list --resource=nodes.metrics.k8s.io") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestPausedDeployment(t *testing.T) {
	s := snap()
	deployment(s, "web", 3, 0)
	s.Workloads = s.Workloads[:1] // created paused: no ReplicaSet, no pods
	s.Workloads[0].Spec.Paused = true
	s.Workloads[0].Status = kube.WorkloadStatus{Conditions: []kube.Condition{{Type: "Progressing", Status: "Unknown", Reason: "DeploymentPaused", Message: "Deployment is paused"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD184", "Deployment shop/web", "is paused", "0 of its 3 replicas run the current pod template and 0 are ready")
	if f.Severity != Critical || f.Evidence[0].Detail != "Deployment is paused" || !strings.Contains(f.Fix, "kubectl rollout resume deployment/web -n shop") {
		t.Errorf("%s %+v %s", f.Severity, f.Evidence, f.Fix)
	}

	// Paused halfway through a rollout: the old pods still serve.
	s.Workloads[0].Status = kube.WorkloadStatus{Replicas: 3, UpdatedReplicas: 1, ReadyReplicas: 3}
	if f := only(t, Diagnose(s)); f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}

	// Paused with every replica current and ready is how a Deployment waits for its next change: not a problem.
	s.Workloads[0].Status = kube.WorkloadStatus{Replicas: 3, UpdatedReplicas: 3, ReadyReplicas: 3}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestNetworkPolicyBlocksAServiceConnection(t *testing.T) {
	build := func() *snapshot.Snapshot {
		s := snap()
		deployment(s, "web", 1, 0)
		p := pod("web-rs-a", "web")
		crashed(&p, 1, "Error", 3)
		db := pod("db", "")
		db.Metadata.Labels = map[string]string{"app": "db"}
		db.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "pg", ContainerPort: 5432}}
		s.Pods = []kube.Pod{p, db}
		svc := service("db", map[string]string{"app": "db"}, named("pg"))
		svc.Spec.Ports[0].Port = 5432
		svc.Spec.ClusterIP = "10.96.40.12"
		s.Services = []kube.Service{svc}
		s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"Connecting to db (10.96.40.12:5432)", "wget: download timed out"}}}
		return s
	}
	dns := kube.IntOrString{Int: 53}
	egressDNSOnly := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "egress-dns-only", Namespace: "shop"}}
	egressDNSOnly.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	egressDNSOnly.Spec.PolicyTypes = []string{"Egress"}
	egressDNSOnly.Spec.Egress = []kube.NetworkPolicyRule{{Ports: []kube.NetworkPolicyPort{{Port: &dns}}}}

	s := build()
	s.NetworkPolicies = []kube.NetworkPolicy{egressDNSOnly}
	f := only(t, Diagnose(s))
	expect(t, f, "KD127", "Deployment shop/web", "connection to Service db times out", "NetworkPolicy egress-dns-only allows no egress traffic between them on port 5432")

	// Go's wording, by cluster IP, and a block on the backends' ingress instead.
	s = build()
	s.Logs[0].Lines = []string{`error: dial tcp 10.96.40.12:5432: i/o timeout`}
	ingress := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "db-from-api", Namespace: "shop"}}
	ingress.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "db"}}
	ingress.Spec.Ingress = []kube.NetworkPolicyRule{{From: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"app": "api"}}}}}}
	s.NetworkPolicies = []kube.NetworkPolicy{ingress}
	f = only(t, Diagnose(s))
	expect(t, f, "KD127", "Deployment shop/web", "NetworkPolicy db-from-api allows no ingress traffic")
	if !strings.Contains(f.Fix, "allows pods with app=web on port 5432") {
		t.Errorf("fix: %s", f.Fix)
	}

	// A rule that allows the client by label, by named port, lifts the block.
	s.NetworkPolicies[0].Spec.Ingress[0].From[0].PodSelector.MatchLabels["app"] = "web"
	pg := kube.IntOrString{Str: "pg", IsName: true}
	s.NetworkPolicies[0].Spec.Ingress[0].Ports = []kube.NetworkPolicyPort{{Port: &pg}}
	if f := only(t, Diagnose(s)); f.Rule == "KD127" {
		t.Errorf("the policy allows the client: %s", f.Cause)
	}

	// A peer chosen by namespace selector may be this namespace: the rule claims only what it can prove.
	s.NetworkPolicies[0].Spec.Ingress[0].From = []kube.NetworkPolicyPeer{{NamespaceSelector: &kube.LabelSelector{}}}
	s.NetworkPolicies[0].Spec.Ingress[0].Ports = nil
	if f := only(t, Diagnose(s)); f.Rule == "KD127" {
		t.Errorf("namespace selector: %s", f.Cause)
	}
}

func TestPodStuckTerminating(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 1)
	p := pod("web-rs-a", "web")
	due := t0.Add(-15 * time.Minute)
	p.Metadata.DeletionTimestamp = &due
	p.Metadata.Finalizers = []string{"example.com/backup"}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD194", "Deployment shop/web", "still terminating 15m0s after its grace period ended", "finalizer example.com/backup has not been removed")
	if f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}

	// On a node that is down, the kubelet cannot confirm the pod stopped.
	p.Metadata.Finalizers = nil
	s.Pods = []kube.Pod{p}
	s.Nodes[0].Status.Conditions[0].Status = "Unknown"
	var got *Finding
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD194" {
			got = &f
		}
	}
	if got == nil {
		t.Fatal("no KD194 for a pod on a node that is down")
	}
	expect(t, *got, "KD194", "Deployment shop/web", "its node node-1 is not ready")

	// Within its grace period, or just past it, a terminating pod is just stopping.
	s.Nodes[0].Status.Conditions[0].Status = "True"
	due = t0.Add(-30 * time.Second)
	p.Metadata.DeletionTimestamp = &due
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestReadinessGateNotMet(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	start := t0.Add(-10 * time.Minute)
	p.Status.StartTime = &start
	p.Spec.ReadinessGates = []kube.PodReadinessGate{{ConditionType: "target-health.elbv2.k8s.aws/web-tg"}}
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "True"}, {Type: "Ready", Status: "False", Reason: "ReadinessGatesNotReady"},
		{Type: "ContainersReady", Status: "True"}}
	s.Pods = []kube.Pod{p}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	f := only(t, Diagnose(s))
	expect(t, f, "KD128", "Deployment shop/web", "no controller has set its readiness gate target-health.elbv2.k8s.aws/web-tg (never set)")
	if len(f.Affects) != 2 {
		t.Errorf("the Service should be listed as affected: %v", f.Affects)
	}

	// Set, but False.
	p.Status.Conditions = append(p.Status.Conditions, kube.Condition{Type: "target-health.elbv2.k8s.aws/web-tg", Status: "False"})
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD128", "Deployment shop/web", "readiness gate target-health.elbv2.k8s.aws/web-tg (False) is not True")

	// A pod that started a moment ago is waiting for the controller as designed.
	start = t0.Add(-20 * time.Second)
	p.Status.StartTime = &start
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 1 || r.Findings[0].Rule != "KD162" {
		t.Errorf("a young pod has no KD128 (its Service has no ready pods, which KD162 reports): %+v", r.Findings)
	}
}

func TestHostPathMissingOnTheNode(t *testing.T) {
	s := snap()
	deployment(s, "agent", 1, 0)
	s.Pods = []kube.Pod{creating("agent-rs-a", "agent")}
	s.Events = []kube.Event{event("Pod", "agent-rs-a", "FailedMount", `MountVolume.SetUp failed for volume "logs" : hostPath type check failed: /var/log/app is not a directory`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD135", "Deployment shop/agent", "hostPath /var/log/app, which is not a directory on node node-1")
	if !strings.Contains(f.Fix, "DirectoryOrCreate") || !strings.Contains(f.Evidence[1].Command, `@.name=="logs"`) {
		t.Errorf("fix %s evidence %+v", f.Fix, f.Evidence)
	}

	// The kubelet of Kubernetes 1.37, as the fault suite recorded it.
	s.Events = []kube.Event{event("Pod", "agent-rs-a", "FailedMount", `MountVolume.SetUp failed for volume "state" : hostPath type check failed, /var/lib/agent-state is not a directory, unable to determine its type: path "/var/lib/agent-state" does not exist`, time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD135", "Deployment shop/agent", "hostPath /var/lib/agent-state, which is not a directory on node node-1")
}

func TestClaimNamesAVolumeItCannotBindTo(t *testing.T) {
	type claimRef = kube.ClaimReference
	build := func() *snapshot.Snapshot {
		s := snap()
		var pvc kube.PersistentVolumeClaim
		pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop", UID: "new-uid"}
		pvc.Spec.StorageClassName = strp("")
		pvc.Spec.VolumeName = "data-pv"
		pvc.Spec.Resources.Requests = map[string]string{"storage": "10Gi"}
		pvc.Status.Phase = "Pending"
		s.PVCs = []kube.PersistentVolumeClaim{pvc}
		var pv kube.PersistentVolume
		pv.Metadata.Name = "data-pv"
		pv.Spec.Capacity = map[string]string{"storage": "10Gi"}
		pv.Status.Phase = "Available"
		s.PVs = []kube.PersistentVolume{pv}
		return s
	}

	s := build()
	s.PVs[0].Spec.ClaimRef = &claimRef{Namespace: "shop", Name: "old-data"}
	f := only(t, Diagnose(s))
	expect(t, f, "KD157", "PersistentVolumeClaim shop/data", "reserved for claim shop/old-data (Available)")

	// Released, still holding the deleted claim's UID: the case after a reinstall.
	s = build()
	s.PVs[0].Status.Phase = "Released"
	s.PVs[0].Spec.ClaimRef = &claimRef{Namespace: "shop", Name: "data", UID: "old-uid"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD157", "PersistentVolumeClaim shop/data", "which is Released: it still holds the UID of the deleted claim")
	if !strings.Contains(f.Fix, "/spec/claimRef/uid") {
		t.Errorf("fix: %s", f.Fix)
	}

	s = build()
	s.PVs = nil
	expect(t, only(t, Diagnose(s)), "KD157", "PersistentVolumeClaim shop/data", "PersistentVolume data-pv, which does not exist")

	s = build()
	s.PVs[0].Spec.StorageClassName = "manual"
	expect(t, only(t, Diagnose(s)), "KD157", "PersistentVolumeClaim shop/data", `asks for StorageClass "" and the volume has "manual"`)

	s = build()
	s.PVs[0].Spec.Capacity["storage"] = "5Gi"
	expect(t, only(t, Diagnose(s)), "KD157", "PersistentVolumeClaim shop/data", "which holds 5Gi, less than the 10Gi")

	// A volume that fits is just binding.
	if r := Diagnose(build()); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestStaticVolumeClassNeedsNoStorageClassObject(t *testing.T) {
	s := snap()
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Spec.StorageClassName = strp("manual")
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	var pv kube.PersistentVolume
	pv.Metadata.Name = "data-pv"
	pv.Spec.StorageClassName = "manual"
	pv.Status.Phase = "Bound"
	s.PVs = []kube.PersistentVolume{pv}
	// "manual" names no StorageClass, but static volumes carry it: KD150 would be a false alarm.
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestRegistryTLSProblems(t *testing.T) {
	pullFails := func(msg string) Finding {
		s := snap()
		p := pod("web", "")
		p.Spec.Containers[0].Image = "registry.corp.internal:5000/shop/web:1"
		waiting(&p, "ErrImagePull", "")
		s.Pods = []kube.Pod{p}
		s.Events = []kube.Event{event("Pod", "web", "Failed", msg, 0)}
		return only(t, Diagnose(s))
	}
	f := pullFails(`Failed to pull image "registry.corp.internal:5000/shop/web:1": rpc error: code = Unknown desc = failed to pull and unpack image "registry.corp.internal:5000/shop/web:1": failed to resolve reference "registry.corp.internal:5000/shop/web:1": failed to do request: Head "https://registry.corp.internal:5000/v2/shop/web/manifests/1": tls: failed to verify certificate: x509: certificate signed by unknown authority`)
	expect(t, f, "KD103", "Pod shop/web", "does not accept the TLS certificate of registry registry.corp.internal:5000", "x509: certificate signed by unknown authority")
	if !strings.Contains(f.Fix, "/etc/containerd/certs.d/registry.corp.internal:5000/ca.crt") {
		t.Errorf("fix: %s", f.Fix)
	}
	f = pullFails(`Failed to pull image "registry.corp.internal:5000/shop/web:1": failed to resolve reference "registry.corp.internal:5000/shop/web:1": failed to do request: Head "https://registry.corp.internal:5000/v2/shop/web/manifests/1": http: server gave HTTP response to HTTPS client`)
	expect(t, f, "KD103", "Pod shop/web", "registry registry.corp.internal:5000 speaks plain HTTP")
}

func TestSuspendedJob(t *testing.T) {
	s := snap()
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "train", Namespace: "shop", CreationTimestamp: t0.Add(-30 * time.Minute)}
	j.Spec.Suspend = yes()
	j.Status.Conditions = []kube.Condition{{Type: "Suspended", Status: "True", Reason: "JobSuspended", LastTransitionTime: t0.Add(-20 * time.Minute)}}
	s.Jobs = []kube.Job{j}
	f := only(t, Diagnose(s))
	expect(t, f, "KD187", "Job shop/train", "suspended for 20m0s")
	if f.Severity != Info {
		t.Errorf("a Job suspended by hand is information: %s", f.Severity)
	}

	s.Jobs[0].Metadata.Labels = map[string]string{"kueue.x-k8s.io/queue-name": "team-a"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD187", "Job shop/train", "waited 20m0s for Kueue to admit it from LocalQueue team-a")
	if f.Severity != Warning || !strings.Contains(f.Fix, "Do not unsuspend it by hand") {
		t.Errorf("%s %s", f.Severity, f.Fix)
	}

	s.Jobs[0].Status.Conditions[0].LastTransitionTime = t0.Add(-30 * time.Second)
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("just suspended: %+v", r.Findings)
	}
}

func TestExtendedResourceNoNodeAdvertises(t *testing.T) {
	s := snap()
	p := pod("train", "")
	p.Spec.NodeName = ""
	p.Spec.Containers[0].Resources.Requests = map[string]string{"nvidia.com/gpu": "1"}
	p.Status.Phase, p.Status.ContainerStatuses = "Pending", nil
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 Insufficient nvidia.com/gpu. preemption: 0/1 nodes are available: 1 No preemption victims found for incoming pod."}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD140", "Pod shop/train", "requests nvidia.com/gpu, and no node advertises any (1 node checked): the device plugin")
	if !strings.Contains(f.Fix, "NVIDIA device plugin") {
		t.Errorf("fix: %s", f.Fix)
	}

	// With a GPU node that is full, it is the usual shortage.
	s.Nodes = append(s.Nodes, node("gpu-1", "8", "32Gi"))
	s.Nodes[1].Status.Allocatable["nvidia.com/gpu"] = "2"
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "device plugin") {
		t.Errorf("a full GPU node is not a missing device plugin: %s", f.Cause)
	}
}

func TestCSIDriverNotRunning(t *testing.T) {
	s := snap()
	deployment(s, "db", 1, 0)
	s.Pods = []kube.Pod{creating("db-rs-a", "db")}
	s.Events = []kube.Event{event("Pod", "db-rs-a", "FailedMount", `MountVolume.MountDevice failed for volume "pvc-1a2b" : kubernetes.io/csi: attacher.MountDevice failed to create newCsiDriverClient: driver name ebs.csi.aws.com not found in the list of registered CSI drivers`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD136", "Deployment shop/db", "CSI driver ebs.csi.aws.com, which is not registered on node node-1")

	s.Events = []kube.Event{event("Pod", "db-rs-a", "FailedAttachVolume", `AttachVolume.Attach failed for volume "pvc-1a2b" : timed out waiting for external-attacher of ebs.csi.aws.com CSI driver to attach volume vol-0abc`, time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD136", "Deployment shop/db", "no attacher for it answered")
}

func TestLivenessProbeTimesOut(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/healthz", Port: named("http")}}
	crashed(&p, 137, "Error", 6)
	s.Pods = []kube.Pod{p}
	e1 := event("Pod", "web", "Unhealthy", `Liveness probe failed: Get "http://10.244.0.7:8080/healthz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`, time.Minute)
	e1.InvolvedObject.FieldPath = "spec.containers{web}"
	e2 := event("Pod", "web", "Killing", "Container web failed liveness probe, will be restarted", 2*time.Minute)
	e2.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e1, e2}
	f := only(t, Diagnose(s))
	expect(t, f, "KD112", "Pod shop/web", "liveness probe times out", "within the probe's 1s timeoutSeconds")

	s.Pods[0].Spec.Containers[0].LivenessProbe.TimeoutSeconds = 3
	expect(t, only(t, Diagnose(s)), "KD112", "Pod shop/web", "3s timeoutSeconds")
}

func TestInitContainerWaitsForAServiceWithNoReadyPods(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.InitContainers = []kube.Container{{Name: "wait-for-db", Image: "busybox"}}
	p.Status.Phase = "Pending"
	waiting(&p, "PodInitializing", "")
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "wait-for-db", State: kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: t0.Add(-6 * time.Minute)}}}}
	s.Pods = []kube.Pod{p}
	db := service("db", map[string]string{"app": "db"}, port(5432))
	db.Spec.ClusterIP = "10.96.7.7"
	s.Services = []kube.Service{db}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "wait-for-db", Lines: []string{"wget: can't connect to remote host (10.96.7.7): Connection refused"}}}
	// The Service's own finding, that it selects no pod, is listed too: it says why the Service is empty.
	r := Diagnose(s)
	if len(r.Findings) != 2 || r.Findings[1].Rule != "KD160" {
		t.Fatalf("%+v", r.Findings)
	}
	expect(t, r.Findings[0], "KD119", "Deployment shop/web", "it waits for Service db, which has no ready pods")
}

func TestVolumeResizeFailed(t *testing.T) {
	s := snap()
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Spec.Resources.Requests = map[string]string{"storage": "100Gi"}
	pvc.Status.Phase, pvc.Status.Capacity = "Bound", map[string]string{"storage": "50Gi"}
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	s.Events = []kube.Event{event("PersistentVolumeClaim", "data", "VolumeResizeFailed", `resize volume "pvc-1a2b" by resizer "ebs.csi.aws.com" failed: rpc error: code = Internal desc = Could not resize volume "vol-0abc": You've reached the maximum modification rate per volume limit. Wait at least 6 hours between modifications per EBS volume.`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD158", "PersistentVolumeClaim shop/data", "asks for 100Gi but its volume still has 50Gi", "maximum modification rate")

	// Grown, with an old failure event: done.
	s.PVCs[0].Status.Capacity["storage"] = "100Gi"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

// TestLivenessProbeThatCannotRun is what Kubernetes 1.37 with containerd 2 does when an exec probe's command is not in
// the image, as the fault suite recorded it: the probe errors, the kubelet ignores the result, and the container
// runs on with no restart.
func TestLivenessProbeThatCannotRun(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 1)
	p := pod("web-rs-a", "web")
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{Exec: &kube.ExecAction{Command: []string{"curl", "-f", "http://localhost:8080/"}}}
	s.Pods = []kube.Pod{p}
	e := event("Pod", "web-rs-a", "Unhealthy", `Liveness probe errored and resulted in unknown state: rpc error: code = Unknown desc = failed to exec in container: failed to start exec "e14b": OCI runtime exec failed: exec failed: unable to start container process: exec: "curl": executable file not found in $PATH: unknown`, time.Minute)
	e.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e}
	f := only(t, Diagnose(s))
	expect(t, f, "KD129", "Deployment shop/web", "liveness probe runs curl, which is not in image", "checks nothing")
	if f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}
}

func TestPodBoundToAMissingNode(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.NodeName = "worker-9"
	p.Status = kube.PodStatus{Phase: "Pending"}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD240", "Deployment shop/web", "spec.nodeName worker-9", "no such node (it has node-1)")

	// A node list the user may not read proves nothing.
	s.Gaps = []snapshot.Gap{{Resource: "nodes", Error: "forbidden"}}
	s.Nodes = nil
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD240" {
			t.Errorf("KD240 without the node list: %+v", f)
		}
	}
}

func TestExternalNameWithAnIPAddress(t *testing.T) {
	s := snap()
	svc := service("legacy-db", nil, port(5432))
	svc.Spec.Type, svc.Spec.ExternalName = "ExternalName", "10.20.0.15"
	s.Services = []kube.Service{svc}
	f := only(t, Diagnose(s))
	expect(t, f, "KD260", "Service shop/legacy-db", "externalName 10.20.0.15, an IP address", "CNAME")
	if !strings.Contains(f.Fix, "EndpointSlice") {
		t.Errorf("fix %q", f.Fix)
	}
	s.Services[0].Spec.ExternalName = "db.example.com"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a DNS name is what ExternalName takes: %+v", r.Findings)
	}
}

func TestNetworkPolicySelectsNoPods(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 1)
	s.Pods = []kube.Pod{pod("web-rs-a", "web")}
	var np kube.NetworkPolicy
	np.Metadata = kube.ObjectMeta{Name: "web-ingress", Namespace: "shop"}
	np.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "webapp"}}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	f := only(t, Diagnose(s))
	expect(t, f, "KD262", "NetworkPolicy shop/web-ingress", "selects pods with app=webapp", "restricts nothing", "closest pod labels are app=web")

	// A CronJob's pods exist only while it runs; its template counts.
	var cj kube.CronJob
	cj.Metadata = kube.ObjectMeta{Name: "report", Namespace: "shop"}
	cj.Spec.JobTemplate.Spec.Template.Metadata.Labels = map[string]string{"app": "webapp"}
	s.CronJobs = []kube.CronJob{cj}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("the policy selects the CronJob's pods: %+v", r.Findings)
	}
	// An empty selector selects every pod.
	s.CronJobs = nil
	s.NetworkPolicies[0].Spec.PodSelector = kube.LabelSelector{}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("an empty selector: %+v", r.Findings)
	}
	// CronJobs not read: a template we cannot see might match.
	s.NetworkPolicies[0].Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "webapp"}}
	s.Gaps = []snapshot.Gap{{Resource: "cronjobs.batch", Namespace: "shop", Error: "forbidden"}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("unread CronJobs: %+v", r.Findings)
	}
}

func TestIngressesClaimTheSameHostAndPath(t *testing.T) {
	s := snap()
	defaultIngressClass(s)
	deployment(s, "web", 1, 1)
	s.Pods = []kube.Pod{pod("web-rs-a", "web")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http")), service("web-v2", map[string]string{"app": "web"}, named("http"))}
	s.Services[0].Spec.Ports[0].Port, s.Services[1].Spec.Ports[0].Port = 80, 80
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1), slice("web-v2", 1)}
	older, newer := ingress("shop", "web", 80, ""), ingress("shop-v2", "web-v2", 80, "")
	older.Metadata.CreationTimestamp, newer.Metadata.CreationTimestamp = t0.Add(-48*time.Hour), t0.Add(-time.Hour)
	s.Ingresses = []kube.Ingress{newer, older}
	f := only(t, Diagnose(s))
	expect(t, f, "KD263", "Ingress shop/shop-v2", "shop.example.com/api to Service web-v2:80, which Ingress shop, created earlier, sends to Service web:80", "ingress-nginx keeps the oldest rule")

	// Created in the same second: the names break the tie, and neither is called earlier.
	s.Ingresses[0].Metadata.CreationTimestamp = s.Ingresses[1].Metadata.CreationTimestamp
	expect(t, only(t, Diagnose(s)), "KD263", "Ingress shop/shop-v2", "which Ingress shop sends to Service web:80")
	s.Ingresses[0].Metadata.CreationTimestamp = t0.Add(-time.Hour)

	// The same backend twice is redundant, not a conflict.
	s.Ingresses[0] = ingress("shop-v2", "web", 80, "")
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("same backend: %+v", r.Findings)
	}
	// Different classes are different controllers.
	s.Ingresses[0] = newer
	s.Ingresses[0].Spec.IngressClassName = strp("internal")
	s.IngressClasses = append(s.IngressClasses, kube.IngressClass{Metadata: kube.ObjectMeta{Name: "internal"}})
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("different classes: %+v", r.Findings)
	}
}

func TestStatefulSetWaitsForItsFirstPod(t *testing.T) {
	s := snap()
	var replicas int32 = 3
	ss := kube.Workload{Kind: "StatefulSet", Metadata: kube.ObjectMeta{Name: "db", Namespace: "shop"}}
	ss.Spec.Replicas, ss.Spec.ServiceName = &replicas, "db"
	ss.Spec.Template.Metadata.Labels = map[string]string{"app": "web"}
	ss.Status.Replicas = 1
	s.Workloads = []kube.Workload{ss}
	headless := service("db", map[string]string{"app": "web"}, named("http"))
	headless.Spec.ClusterIP, headless.Spec.Ports[0].Port = "None", 8080
	s.Services = []kube.Service{headless}
	s.EndpointSlices = []kube.EndpointSlice{slice("db", 0)}
	p := pod("db-0", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "StatefulSet", Name: "db", Controller: yes()}}
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{Exec: &kube.ExecAction{Command: []string{"cat", "/tmp/ready"}}}
	notReady(&p)
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "db-0", "Unhealthy", "Readiness probe failed: cat: can't open '/tmp/ready': No such file or directory", 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD120", "StatefulSet shop/db", "has 0 of 3 replicas ready", "creates its pods in order", "db-1, db-2 are not created yet")

	// Parallel creates them all at once: a missing pod is not waiting for this one.
	s.Workloads[0].Spec.PodManagementPolicy = "Parallel"
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "in order") {
		t.Errorf("Parallel: %s", f.Cause)
	}
}

func TestServiceWithoutSelectorOrEndpoints(t *testing.T) {
	s := snap()
	s.Services = []kube.Service{service("payments", nil, port(8080))}
	f := only(t, Diagnose(s))
	expect(t, f, "KD264", "Service shop/payments", "has no selector", "no EndpointSlice: connections to it fail")
	if !strings.Contains(f.Fix, "kubernetes.io/service-name: payments") {
		t.Errorf("fix %q", f.Fix)
	}
	s.EndpointSlices = []kube.EndpointSlice{slice("payments", 0)}
	expect(t, only(t, Diagnose(s)), "KD264", "Service shop/payments", "1 EndpointSlice with no ready address")
	s.EndpointSlices = []kube.EndpointSlice{slice("payments", 1)}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("hand-managed endpoints: %+v", r.Findings)
	}

	// A slice made for it by hand without the label that links it: the slice and the label are named.
	unlinked := slice("payments", 1)
	unlinked.Metadata.Name, unlinked.Metadata.Labels = "payments-1", nil
	s.EndpointSlices = []kube.EndpointSlice{unlinked}
	f = only(t, Diagnose(s))
	expect(t, f, "KD264", "Service shop/payments", "EndpointSlice payments-1, named for it, lacks the label kubernetes.io/service-name: payments")
	if !strings.Contains(f.Fix, "kubectl label endpointslice payments-1 -n shop kubernetes.io/service-name=payments") || len(f.Evidence) != 3 {
		t.Errorf("fix %q, %d evidence", f.Fix, len(f.Evidence))
	}
	// An unlabelled slice named for something else is not tied to this Service.
	unlinked.Metadata.Name = "billing-1"
	s.EndpointSlices = []kube.EndpointSlice{unlinked}
	expect(t, only(t, Diagnose(s)), "KD264", "Service shop/payments", "no EndpointSlice: connections to it fail")

	s.EndpointSlices = nil
	s.Gaps = []snapshot.Gap{{Resource: "endpointslices.discovery.k8s.io", Namespace: "shop", Error: "forbidden"}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("unread EndpointSlices: %+v", r.Findings)
	}
}

func TestClaimWaitsForAPodThatBypassesTheScheduler(t *testing.T) {
	s := snap()
	s.StorageClasses = []kube.StorageClass{{Metadata: kube.ObjectMeta{Name: "standard", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}},
		Provisioner: "rancher.io/local-path", VolumeBindingMode: "WaitForFirstConsumer"}}
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	s.Events = []kube.Event{event("PersistentVolumeClaim", "data", "WaitForFirstConsumer", "waiting for first consumer to be created before binding", 0)}
	deployment(s, "db", 1, 0)
	p := pod("db-rs-a", "db")
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	waiting(&p, "ContainerCreating", "")
	p.Status.Phase, p.Status.Conditions = "Pending", nil
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD159", "Deployment shop/db", "claim data's StorageClass standard", "sets nodeName node-1, which bypasses the scheduler")

	// Once the scheduler has picked a node, the claim's wait is the provisioner's.
	s.PVCs[0].Metadata.Annotations = map[string]string{"volume.kubernetes.io/selected-node": "node-1"}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD159" {
			t.Errorf("selected-node set: %+v", f)
		}
	}
}

func TestCommandIsOneString(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].Command = []string{"sleep 3600"}
	crashed(&p, 128, "StartError", 3)
	p.Status.ContainerStatuses[0].LastTerminationState.Terminated.Message = `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: exec: "sleep 3600": executable file not found in $PATH: unknown`
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD201", "Pod shop/web", `command is the single string "sleep 3600"`, "spaces included")
	if !strings.Contains(f.Fix, `["sleep", "3600"]`) {
		t.Errorf("the fix should give the command as a list: %s", f.Fix)
	}

	// A shell line goes to sh -c, not split on spaces.
	p.Spec.Containers[0].Command = []string{"echo hi && sleep 3600"}
	p.Status.ContainerStatuses[0].LastTerminationState.Terminated.Message = `exec: "echo hi && sleep 3600": executable file not found in $PATH: unknown`
	f = only(t, Diagnose(s))
	if f.Rule != "KD201" || !strings.Contains(f.Fix, `["sh", "-c", "echo hi && sleep 3600"]`) {
		t.Errorf("a shell line should be run by sh -c: %s %s", f.Rule, f.Fix)
	}

	// No command: the image runs args as the command.
	p.Spec.Containers[0].Command, p.Spec.Containers[0].Args = nil, []string{"sleep 3600"}
	p.Status.ContainerStatuses[0].LastTerminationState.Terminated.Message = `exec: "sleep 3600": executable file not found in $PATH: unknown`
	expect(t, only(t, Diagnose(s)), "KD201", "Pod shop/web", `args is the single string "sleep 3600"`)

	// A plain missing command, without spaces, stays KD114.
	p.Spec.Containers[0].Command, p.Spec.Containers[0].Args = []string{"webserver"}, nil
	p.Status.ContainerStatuses[0].LastTerminationState.Terminated.Message = `exec: "webserver": executable file not found in $PATH: unknown`
	expect(t, only(t, Diagnose(s)), "KD114", "Pod shop/web", `runs "webserver"`)
}

func TestProbeSpeaksHTTPSToPlainHTTP(t *testing.T) {
	s := snap()
	p := pod("web", "")
	notReady(&p)
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/", Port: port(8080), Scheme: "HTTPS"}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Unhealthy", `Readiness probe failed: Get "https://10.244.0.7:8080/": http: server gave HTTP response to HTTPS client`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD202", "Pod shop/web", "readiness probe uses scheme HTTPS", "plain HTTP on port 8080", "never becomes ready")

	// A liveness probe with the same mistake restarts the container.
	p = pod("web", "")
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/", Port: port(8080), Scheme: "HTTPS"}}
	crashed(&p, 137, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Unhealthy", `Liveness probe failed: Get "https://10.244.0.7:8080/": http: server gave HTTP response to HTTPS client`, time.Minute),
		event("Pod", "web", "Killing", "Container web failed liveness probe, will be restarted", time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD202", "Pod shop/web", "liveness probe uses scheme HTTPS", "restarts the container (4 restarts)")
}

func TestProbeNamesAPortTheContainerLacks(t *testing.T) {
	s := snap()
	p := pod("api", "")
	notReady(&p)
	p.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "http", ContainerPort: 8080}}
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/", Port: named("health")}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "api", "Unhealthy", `Readiness probe errored: couldn't find port: health in {...}`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD203", "Pod shop/api", `readiness probe names port "health"`, "declares ports http (8080)", "never becomes ready")
	if f.Severity != Critical || len(f.Evidence) != 3 {
		t.Errorf("a readiness probe that cannot run is critical, with the event, the probe and the ports: %s %d", f.Severity, len(f.Evidence))
	}

	// A liveness probe that cannot run checks nothing: a warning, on an otherwise healthy pod.
	p = pod("api", "")
	p.Spec.Containers[0].Ports = nil
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{TCPSocket: &kube.TCPSocketAction{Port: named("health")}}
	s.Pods, s.Events = []kube.Pod{p}, nil
	f = only(t, Diagnose(s))
	expect(t, f, "KD203", "Pod shop/api", `liveness probe names port "health"`, "declares no ports", "checks nothing")
	if f.Severity != Warning {
		t.Errorf("a liveness probe that checks nothing is a warning: %s", f.Severity)
	}

	// A declared name is fine.
	p.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "health", ContainerPort: 8080}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a probe on a declared port name is fine: %+v", r.Findings)
	}
}

func TestMemoryBackedEmptyDirFillsTheLimit(t *testing.T) {
	s := snap()
	p := pod("cache", "")
	p.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "32Mi"}
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "cache", MountPath: "/cache"}}
	p.Spec.Volumes = []kube.Volume{{Name: "cache", EmptyDir: &kube.EmptyDirVolumeSource{Medium: "Memory"}}}
	crashed(&p, 137, "OOMKilled", 5)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD204", "Pod shop/cache", "writes to emptyDir cache at /cache", "medium Memory", "count against its 32Mi memory limit", "outlive each restart")

	// The runtime sometimes reports the kill as Error with exit 137; the volume is still the reason.
	crashed(&p, 137, "Error", 5)
	expect(t, only(t, Diagnose(s)), "KD204", "Pod shop/cache", "medium Memory")

	// On the node's disk, the same volume is not the reason: an ordinary OOM kill.
	crashed(&p, 137, "OOMKilled", 5)
	p.Spec.Volumes[0].EmptyDir.Medium = ""
	expect(t, only(t, Diagnose(s)), "KD111", "Pod shop/cache", "32Mi memory limit")
}

func TestAnotherPodHoldsTheReadWriteOncePodClaim(t *testing.T) {
	s := snap()
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Spec.AccessModes = []string{"ReadWriteOncePod"}
	pvc.Status.Phase = "Bound"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	vol := []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	first := pod("db-1", "db")
	first.Spec.Volumes = vol
	second := pod("db-2", "db")
	second.Spec.NodeName = ""
	second.Spec.Volumes = vol
	second.Status.Phase = "Pending"
	second.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 node has pod using PersistentVolumeClaim with the same name and ReadWriteOncePod access mode. preemption: 0/1 nodes are available: 1 No preemption victims found for incoming pod."}}
	second.Status.ContainerStatuses = nil
	s.Pods = []kube.Pod{first, second}
	f := only(t, Diagnose(s))
	expect(t, f, "KD147", "ReplicaSet shop/db-rs", "PersistentVolumeClaim data", "ReadWriteOncePod", "pod db-1 already does")
	if !strings.Contains(f.Fix, "ReplicaSet db-rs") {
		t.Errorf("the fix should name the workload: %s", f.Fix)
	}
}

func TestNodeForbidsTheSysctl(t *testing.T) {
	s := snap()
	p := pod("web-x7k2p", "web")
	p.Status.Phase, p.Status.Reason = "Failed", "SysctlForbidden"
	p.Status.Message = `Pod was rejected: forbidden sysctl: "net.core.somaxconn" not allowlisted`
	p.Status.Conditions, p.Status.ContainerStatuses = nil, nil
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD232", "ReplicaSet shop/web-rs", "sysctl net.core.somaxconn", "SysctlForbidden", "not on the kubelet's allowlist on node node-1")
	if !strings.Contains(f.Fix, "--allowed-unsafe-sysctls=net.core.somaxconn") {
		t.Errorf("the fix should name the kubelet flag with the sysctl: %s", f.Fix)
	}
}

func TestNodeRejectsAPodThatBypassedTheScheduler(t *testing.T) {
	s := snap()
	p := pod("batch-2xq9z", "batch")
	p.Spec.NodeName = "kd-faults-control-plane"
	p.Status.Phase, p.Status.Reason = "Failed", "OutOfcpu"
	p.Status.Message = "Pod was rejected: Node didn't have enough resource: cpu, requested: 1000000, used: 950, capacity: 4000"
	p.Status.Conditions, p.Status.ContainerStatuses = nil, nil
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD241", "ReplicaSet shop/batch-rs", "node kd-faults-control-plane does not have enough cpu", "asks for 1000000, 950 of the node's 4000", "OutOfcpu", "spec.nodeName")

	// A scheduled pod rejected in a race is not blamed on nodeName.
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "True"}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	if f.Rule != "KD241" || strings.Contains(f.Cause, "nodeName") {
		t.Errorf("a scheduled pod should not be said to skip the scheduler: %s %s", f.Rule, f.Cause)
	}
}

func TestCommandRefersToAnUndefinedVariable(t *testing.T) {
	s := snap()
	p := pod("worker-6d9f7-abcde", "worker")
	c := &p.Spec.Containers[0]
	c.Command = []string{"sleep", "$(SLEEP_SECONDS)"}
	c.Env = []kube.EnvVar{{Name: "SLEEP_SECOND", Value: "30"}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"sleep: invalid number '$(SLEEP_SECONDS)'"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD205", "ReplicaSet shop/worker-rs", "command uses $(SLEEP_SECONDS)", "define no SLEEP_SECONDS", "image's ENV", "invalid number")

	// Under sh -c the shell runs the name as a command; the variable comes from args here.
	c.Command, c.Args = []string{"sh", "-c"}, []string{"exec server --port $(APP_PORT)"}
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{"sh: APP_PORT: not found", "server: missing value for --port"}
	expect(t, only(t, Diagnose(s)), "KD205", "ReplicaSet shop/worker-rs", "args uses $(APP_PORT)")

	// A Service named app makes the kubelet define APP_PORT: not this rule.
	s.Services = []kube.Service{service("app", map[string]string{"app": "other"}, port(8080))}
	s.Pods = []kube.Pod{p}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD205" {
			t.Errorf("a Service link variable was called undefined: %s", f.Cause)
		}
	}
	s.Services = nil

	// Defined through envFrom with a prefix: not this rule.
	c.EnvFrom = []kube.EnvFromSource{{Prefix: "APP_", ConfigMapRef: &kube.NameRef{Name: "settings"}}}
	s.ConfigMaps = []kube.KeySet{keys("shop", "settings", "PORT")}
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD205" {
		t.Errorf("a variable from envFrom with a prefix was called undefined: %s", f.Cause)
	}

	// An envFrom source the snapshot cannot list: no claim.
	c.EnvFrom = []kube.EnvFromSource{{SecretRef: &kube.NameRef{Name: "unlisted"}}}
	s.ConfigMaps = nil
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD205" {
		t.Errorf("claimed an undefined variable with an unlisted envFrom source: %s", f.Cause)
	}
}

func TestProbeChecksAHostOtherThanThePod(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	notReady(&p)
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Host: "127.0.0.1", Path: "/healthz", Port: port(8080)}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", p.Metadata.Name, "Unhealthy", `Readiness probe failed: Get "http://127.0.0.1:8080/healthz": dial tcp 127.0.0.1:8080: connect: connection refused`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD206", "ReplicaSet shop/web-rs", "readiness probe sets host", "on the node itself", "port 8080", "never becomes ready")
	if !strings.Contains(f.Fix, "httpHeaders") {
		t.Errorf("fix %q", f.Fix)
	}

	// A liveness probe aimed at another address kills the container.
	p = pod("web-5c7d9-qwert", "web")
	crashed(&p, 137, "Error", 5)
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{TCPSocket: &kube.TCPSocketAction{Host: "10.0.0.9", Port: port(8080)}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{
		event("Pod", p.Metadata.Name, "Unhealthy", "Liveness probe failed: dial tcp 10.0.0.9:8080: i/o timeout", time.Minute),
		event("Pod", p.Metadata.Name, "Killing", "Container web failed liveness probe, will be restarted", time.Minute),
	}
	expect(t, only(t, Diagnose(s)), "KD206", "ReplicaSet shop/web-rs", "connects to host 10.0.0.9, not the pod", "5 restarts")

	// host set to the pod's own IP is the default spelled out: not this rule.
	p = pod("web-5c7d9-qwert", "web")
	notReady(&p)
	p.Status.PodIP = "10.244.0.7"
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Host: "10.244.0.7", Path: "/healthz", Port: port(8080)}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", p.Metadata.Name, "Unhealthy", `Readiness probe failed: HTTP probe failed with statuscode: 503`, time.Minute)}
	if f := only(t, Diagnose(s)); f.Rule == "KD206" {
		t.Errorf("a probe on the pod's own IP was blamed on its host: %s", f.Cause)
	}
}

func TestHeadlessServiceMapsAPortItCannotMap(t *testing.T) {
	s := snap()
	p := pod("peer-0", "peer")
	s.Pods = []kube.Pod{p}
	svc := service("peers", p.Metadata.Labels, port(8080))
	svc.Spec.ClusterIP = "None"
	svc.Spec.Ports[0].Port = 80
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("peers", 1)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD265", "Service shop/peers", "headless (clusterIP: None)", "port 80 to targetPort 8080", "reaches the pods on port 80", "SRV")
	if f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}

	// A named targetPort that resolves to the same number, and a Service with a cluster IP: nothing to say.
	svc.Spec.Ports[0].Port, svc.Spec.Ports[0].TargetPort = 8080, named("http")
	s.Services = []kube.Service{svc}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a headless Service whose named port is its port: %v", r.Findings)
	}
	svc.Spec.ClusterIP, svc.Spec.Ports[0].Port, svc.Spec.Ports[0].TargetPort = "10.96.0.12", 80, port(8080)
	s.Services = []kube.Service{svc}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a Service with a cluster IP maps its port: %v", r.Findings)
	}
}

func TestPodSubdomainWithoutAHeadlessService(t *testing.T) {
	s := snap()
	p := pod("train-0-x8k2q", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "train", Controller: yes()}}
	p.Spec.Hostname, p.Spec.Subdomain = "train-0", "workers"
	crashed(&p, 1, "Error", 0)
	p.Status.Phase = "Running"
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"waiting for peers", "nslookup: can't resolve 'train-1.workers'", "server can't find train-1.workers: NXDOMAIN"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD266", "Job shop/train", "cannot resolve train-1.workers", "there is no Service workers in namespace shop")
	if f.Severity != Critical || !strings.Contains(f.Fix, "headless Service named workers") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// Running and healthy: the name it was given does not exist, a warning.
	p = pod("train-0-x8k2q", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "train", Controller: yes()}}
	p.Spec.Hostname, p.Spec.Subdomain = "train-0", "workers"
	s.Pods, s.Logs = []kube.Pod{p}, nil
	svc := service("workers", map[string]string{"app": "web"}, port(8080))
	svc.Spec.ClusterIP = "10.96.3.3"
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("workers", 1)}
	f = only(t, Diagnose(s))
	expect(t, f, "KD266", "Job shop/train", "train-0.workers.shop.svc", "Service workers is not headless")
	if f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}

	// Headless but selecting other pods.
	svc.Spec.ClusterIP, svc.Spec.Ports[0].Port = "None", 8080
	svc.Spec.Selector = map[string]string{"app": "other"}
	s.Services = []kube.Service{svc}
	s.EndpointSlices = nil
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD266" && !strings.Contains(f.Cause, "does not select the pod") {
			t.Errorf("cause %s", f.Cause)
		}
	}

	// Served: nothing to say. A StatefulSet's pods are left to KD182.
	svc.Spec.Selector = map[string]string{"app": "web"}
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("workers", 1)}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a served subdomain: %v", r.Findings)
	}
	s.Services, s.EndpointSlices = nil, nil
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "StatefulSet", Name: "db", Controller: yes()}}
	s.Pods = []kube.Pod{p}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD266" {
			t.Errorf("a StatefulSet pod: %s", f.Cause)
		}
	}
}

func TestRuntimeClassHandlerMissingOnTheNode(t *testing.T) {
	s := snap()
	p := pod("infer-7b9c4-p2x8d", "infer")
	p.Spec.RuntimeClassName = "nvidia"
	p.Status.Phase = "Pending"
	p.Status.ContainerStatuses = []kube.ContainerStatus{{Name: "web", State: kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "ContainerCreating"}}}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", p.Metadata.Name, "FailedCreatePodSandBox",
		`Failed to create pod sandbox: rpc error: code = Unknown desc = failed to get sandbox runtime: no runtime for "nvidia" is configured`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD196", "ReplicaSet shop/infer-rs", "RuntimeClass nvidia", "handler nvidia is not configured", "node node-1")
	if !strings.Contains(f.Fix, "scheduling.nodeSelector") || len(f.Evidence) != 2 {
		t.Errorf("fix %q, %d evidence", f.Fix, len(f.Evidence))
	}
}

func TestSeccompProfileIsNotOnTheNode(t *testing.T) {
	s := snap()
	p := pod("api-5d7f8-k2m9q", "api")
	notReady(&p)
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "CreateContainerError",
		Message: `failed to generate container "c0ffee" spec: failed to generate seccomp spec opts: cannot load seccomp profile "/var/lib/kubelet/seccomp/profiles/hardened.json": open /var/lib/kubelet/seccomp/profiles/hardened.json: no such file or directory`}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD207", "ReplicaSet shop/api-rs", "Localhost seccomp profile /var/lib/kubelet/seccomp/profiles/hardened.json", "not on node node-1")
	if !strings.Contains(f.Fix, "RuntimeDefault") {
		t.Errorf("fix %q", f.Fix)
	}

	// A profile that is there but cannot be parsed says why.
	p.Status.ContainerStatuses[0].State.Waiting.Message = `failed to generate seccomp spec opts: cannot load seccomp profile "/var/lib/kubelet/seccomp/profiles/hardened.json": permission denied`
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD207", "ReplicaSet shop/api-rs", "cannot load (permission denied)")
}

func TestNodeRejectsAPodForAnotherOS(t *testing.T) {
	s := snap()
	n := node("kd-faults-control-plane", "4", "16Gi")
	n.Metadata.Labels["kubernetes.io/os"] = "linux"
	s.Nodes = []kube.Node{n}
	p := pod("agent-win", "")
	p.Spec.NodeName = "kd-faults-control-plane"
	p.Spec.OS = &struct {
		Name string `json:"name"`
	}{Name: "windows"}
	p.Status.Phase, p.Status.Reason = "Failed", "PodOSNotSupported"
	p.Status.Message = "Pod was rejected: Failed to admit pod as the OS field doesn't match node OS"
	p.Status.Conditions, p.Status.ContainerStatuses = []kube.Condition{{Type: "PodScheduled", Status: "True"}}, nil
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD244", "Pod shop/agent-win", "spec.os.name windows does not match node kd-faults-control-plane, which runs linux", "scheduler does not compare spec.os", "PodOSNotSupported")
	if !strings.Contains(f.Fix, "nodeSelector kubernetes.io/os") {
		t.Errorf("fix %q", f.Fix)
	}

	// The label check, skipped by nodeName.
	p.Spec.OS = nil
	p.Spec.NodeSelector = map[string]string{"kubernetes.io/os": "windows"}
	p.Status.Reason = "PodOSSelectorNodeLabelDoesNotMatch"
	p.Status.Message = "Pod was rejected: Failed to admit pod as the `kubernetes.io/os` label doesn't match node label"
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD244", "Pod shop/agent-win", "kubernetes.io/os node selector", "spec.nodeName")
}

func TestNetworkPolicyAllowsAPortNameThePodsLack(t *testing.T) {
	s := snap()
	p := pod("web-1", "web")
	s.Pods = []kube.Pod{p}
	var np kube.NetworkPolicy
	np.Metadata = kube.ObjectMeta{Name: "allow-metrics", Namespace: "shop"}
	np.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	metrics := named("metrics")
	np.Spec.Ingress = []kube.NetworkPolicyRule{{Ports: []kube.NetworkPolicyPort{{Port: &metrics}}}}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	f := only(t, Diagnose(s))
	expect(t, f, "KD268", "NetworkPolicy shop/allow-metrics", `allows ingress on port "metrics"`, "1 pod it selects declare the named ports http (8080)", "allows nothing")
	if f.Severity != Warning || !strings.Contains(f.Fix, "name: metrics") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// The pods name the port: nothing to say. A number is not a name.
	np.Spec.Ingress[0].Ports[0].Port = &kube.IntOrString{Str: "http", IsName: true}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a declared port name: %v", r.Findings)
	}
	n := port(9090)
	np.Spec.Ingress[0].Ports[0].Port = &n
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a port number: %v", r.Findings)
	}
}

func TestNetworkPolicyBlocksTheAPIServer(t *testing.T) {
	s := snap()
	p := pod("operator-6c9d-xk2pq", "operator")
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{
		"Connecting to kubernetes.default.svc (10.96.0.1:443)", "wget: download timed out"}}}
	var np kube.NetworkPolicy
	np.Metadata = kube.ObjectMeta{Name: "egress-dns-only", Namespace: "shop"}
	np.Spec.PolicyTypes = []string{"Egress"}
	dns := port(53)
	np.Spec.Egress = []kube.NetworkPolicyRule{{Ports: []kube.NetworkPolicyPort{{Port: &dns}}}}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	f := only(t, Diagnose(s))
	expect(t, f, "KD267", "ReplicaSet shop/operator-rs", "API server (kubernetes.default.svc) times out", "NetworkPolicy egress-dns-only", "6443", "download timed out")
	if !strings.Contains(f.Fix, "ipBlock") {
		t.Errorf("fix %q", f.Fix)
	}

	// The cluster IP, as client-go reports it.
	s.Logs[0].Lines = []string{`Get "https://10.96.0.1:443/api?timeout=32s": dial tcp 10.96.0.1:443: i/o timeout`}
	expect(t, only(t, Diagnose(s)), "KD267", "ReplicaSet shop/operator-rs", "API server (10.96.0.1)")

	// A rule with an ipBlock on 6443 might allow it: no claim.
	api := port(6443)
	np.Spec.Egress = append(np.Spec.Egress, kube.NetworkPolicyRule{To: []kube.NetworkPolicyPeer{{IPBlock: &struct {
		CIDR string `json:"cidr"`
	}{CIDR: "172.18.0.2/32"}}}, Ports: []kube.NetworkPolicyPort{{Port: &api}}})
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	if f := only(t, Diagnose(s)); f.Rule == "KD267" {
		t.Errorf("claimed a block with an ipBlock rule on 6443: %s", f.Cause)
	}
}

func TestPreStopHookOutlastsTheGracePeriod(t *testing.T) {
	s := snap()
	p := pod("web-1", "web")
	p.Spec.Containers[0].Lifecycle = &kube.Lifecycle{PreStop: &kube.LifecycleHandler{Exec: &kube.ExecAction{Command: []string{"sh", "-c", "sleep 45; nginx -s quit"}}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD208", "ReplicaSet shop/web-rs", "preStop hook waits 45 s", "terminationGracePeriodSeconds is 30", "before the app gets SIGTERM")
	if f.Severity != Warning || !strings.Contains(f.Fix, "75") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// The sleep handler, against a set grace period.
	g := int64(20)
	p.Spec.TerminationGracePeriodSeconds = &g
	p.Spec.Containers[0].Lifecycle.PreStop = &kube.LifecycleHandler{Sleep: &struct {
		Seconds int64 `json:"seconds"`
	}{Seconds: 20}}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD208", "ReplicaSet shop/web-rs", "waits 20 s", "is 20")

	// Shorter than the grace period, or a hook whose length cannot be read: nothing to say.
	g = 60
	s.Pods = []kube.Pod{p}
	for _, h := range []*kube.LifecycleHandler{p.Spec.Containers[0].Lifecycle.PreStop, {Exec: &kube.ExecAction{Command: []string{"/app/drain"}}}} {
		p.Spec.Containers[0].Lifecycle.PreStop = h
		s.Pods = []kube.Pod{p}
		if r := Diagnose(s); len(r.Findings) != 0 {
			t.Errorf("hook %+v: %v", h, r.Findings)
		}
	}
	for cmd, want := range map[string]int64{"sleep 5": 5, "exec sleep 12": 12, "/bin/sleep 7": 7, "sleep 3s && kill 1": 3} {
		got, ok := preStopSeconds(&kube.LifecycleHandler{Exec: &kube.ExecAction{Command: []string{"/bin/sh", "-c", cmd}}})
		if !ok || got != want {
			t.Errorf("preStopSeconds(%q) = %d %v, want %d", cmd, got, ok, want)
		}
	}
}

func TestGRPCProbeCannotPass(t *testing.T) {
	s := snap()
	p := pod("api-7c4d-qq2x9", "api")
	notReady(&p)
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{GRPC: &kube.GRPCAction{Port: 8080}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", p.Metadata.Name, "Unhealthy", `Readiness probe failed: timeout: failed to connect service "10.244.0.9:8080" within 1s: context deadline exceeded`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD209", "ReplicaSet shop/api-rs", "port 8080 (the container calls it http)", "nothing there speaks gRPC", "never becomes ready")
	if !strings.Contains(f.Fix, "httpGet") {
		t.Errorf("fix %q", f.Fix)
	}

	// A gRPC server without the health service, on a liveness probe.
	p = pod("api-7c4d-qq2x9", "api")
	crashed(&p, 137, "Error", 4)
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{GRPC: &kube.GRPCAction{Port: 9000}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{
		event("Pod", p.Metadata.Name, "Unhealthy", "Liveness probe failed: error: this server does not implement the grpc health protocol (grpc.health.v1.Health): unknown service grpc.health.v1.Health", time.Minute),
		event("Pod", p.Metadata.Name, "Killing", "Container web failed liveness probe, will be restarted", time.Minute),
	}
	f = only(t, Diagnose(s))
	expect(t, f, "KD209", "ReplicaSet shop/api-rs", "does not implement grpc.health.v1.Health", "4 restarts")
	if !strings.Contains(f.Fix, "health.NewServer") {
		t.Errorf("fix %q", f.Fix)
	}
}

func TestCPURequestWithoutItsMillicoreSuffix(t *testing.T) {
	s := snap()
	s.Nodes = []kube.Node{node("node-1", "4", "16Gi")}
	p := pod("api-7d9f-k2x8q", "api")
	p.Spec.Containers[0].Resources.Requests = map[string]string{"cpu": "500", "memory": "256Mi"}
	p.Status.Phase, p.Status.ContainerStatuses = "Pending", nil
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 Insufficient cpu. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD140", "ReplicaSet shop/api-rs", "requests 500 cpu", "cpu: 500, which is 500 whole cores", "500m is half of a core")
	if !strings.Contains(f.Fix, "as 500m") {
		t.Errorf("fix %q", f.Fix)
	}

	// A LimitRange's default of 64 cores is not the pod's own slip, and 8 cores is a request someone may mean: no hint.
	p.Spec.Containers[0].Resources.Requests["cpu"] = "8"
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "whole cores") {
		t.Errorf("hinted at a slip for cpu: 8: %s", f.Cause)
	}
}

func TestMemoryLimitWithoutAUnit(t *testing.T) {
	s := snap()
	p := pod("api-7d9f-k2x8q", "api")
	p.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "512"}
	notReady(&p)
	p.Status.ContainerStatuses[0].RestartCount = 3
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
	p.Status.ContainerStatuses[0].LastTerminationState = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 128, Reason: "StartError",
		Message: "failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: container init was OOM-killed (memory limit too low?)"}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD210", "ReplicaSet shop/api-rs", "memory: 512, which Kubernetes reads as 512 bytes")
	if !strings.Contains(f.Fix, "512Mi") {
		t.Errorf("fix %q", f.Fix)
	}

	// Killed as OOMKilled instead: the same answer, not "raise the limit".
	p.Status.ContainerStatuses[0].LastTerminationState.Terminated = &kube.ContainerStateTerminated{ExitCode: 137, Reason: "OOMKilled"}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD210", "ReplicaSet shop/api-rs", "512 bytes")

	// On kind the pod never gets that far: the token volume, sized by the limit, cannot be written.
	q := pod("api-7d9f-m4n2b", "api")
	q.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "512"}
	q.Status.Phase = "Pending"
	q.Status.ContainerStatuses = []kube.ContainerStatus{{Name: "web", State: kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "ContainerCreating"}}}}
	s.Pods = []kube.Pod{q}
	s.Events = []kube.Event{event("Pod", q.Metadata.Name, "FailedMount",
		`MountVolume.SetUp failed for volume "kube-api-access-dm9rj" : write /var/lib/kubelet/pods/2354/volumes/kubernetes.io~projected/kube-api-access-dm9rj/..2026_11_20/ca.crt: no space left on device`, time.Minute)}
	f = only(t, Diagnose(s))
	expect(t, f, "KD210", "ReplicaSet shop/api-rs", "memory: 512", "no space left on device", "never starts")
	s.Events = nil

	// A real limit with a unit, or a large bare number of bytes, is left to the OOM rule.
	p.Spec.Containers[0].Resources.Limits["memory"] = "536870912"
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD210" {
		t.Errorf("512 MiB in bytes called a unit slip: %s", f.Cause)
	}
}

func TestReadinessProbeHasNotRunYet(t *testing.T) {
	s := snap()
	p := pod("api-7d9f-k2x8q", "api")
	notReady(&p)
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: t0.Add(-4 * time.Minute)}}
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/ready", Port: port(8080)}, InitialDelaySeconds: 600}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD211", "ReplicaSet shop/api-rs", "has run for 4m0s", "initialDelaySeconds 600 (10m0s)")
	if f.Severity != Warning || !strings.Contains(f.Fix, "startupProbe") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// The delay has passed, or it is short: not this rule.
	p.Status.ContainerStatuses[0].State.Running.StartedAt = t0.Add(-11 * time.Minute)
	s.Pods = []kube.Pod{p}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD211" {
			t.Errorf("after the delay: %s", f.Cause)
		}
	}
	p.Status.ContainerStatuses[0].State.Running.StartedAt = t0.Add(-30 * time.Second)
	p.Spec.Containers[0].ReadinessProbe.InitialDelaySeconds = 60
	s.Pods = []kube.Pod{p}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD211" {
			t.Errorf("a one-minute delay: %s", f.Cause)
		}
	}
}

func TestExternalNameServiceThatDoesNotResolve(t *testing.T) {
	s := snap()
	p := pod("api-7d9f-k2x8q", "api")
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"connecting to db", "wget: bad address 'db:5432'"}}}
	var db kube.Service
	db.Metadata = kube.ObjectMeta{Name: "db", Namespace: "shop"}
	db.Spec.Type, db.Spec.ExternalName = "ExternalName", "orders-db.prod.internal"
	s.Services = []kube.Service{db}
	f := only(t, Diagnose(s))
	expect(t, f, "KD270", "ReplicaSet shop/api-rs", "db does not resolve", "CNAME to orders-db.prod.internal", "bad address")
	if !strings.Contains(f.Fix, "nslookup orders-db.prod.internal") {
		t.Errorf("fix %q", f.Fix)
	}

	// A ClusterIP Service that resolves is not this rule; nor is a name that is no Service (KD121).
	db.Spec.Type, db.Spec.ExternalName = "ClusterIP", ""
	s.Services = []kube.Service{db}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD270" {
			t.Errorf("a ClusterIP Service: %s", f.Cause)
		}
	}
}

func TestPodDNSSettingsLeaveOutClusterDNS(t *testing.T) {
	s := snap()
	p := pod("api-7d9f-k2x8q", "api")
	p.Spec.DNSPolicy = "None"
	p.Spec.DNSConfig = &struct {
		Nameservers []string `json:"nameservers,omitempty"`
		Searches    []string `json:"searches,omitempty"`
	}{Nameservers: []string{"1.1.1.1"}, Searches: []string{"corp.example"}}
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.Services = []kube.Service{service("payments", map[string]string{"app": "pay"}, port(8080))}
	payments := pod("payments-1", "payments")
	payments.Metadata.Labels = map[string]string{"app": "pay"}
	s.Pods = append(s.Pods, payments)
	s.EndpointSlices = []kube.EndpointSlice{slice("payments", 1)}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"wget: bad address 'payments:8080'"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD269", "ReplicaSet shop/api-rs", "payments does not resolve", "dnsPolicy None", "nameservers 1.1.1.1, search domains corp.example")
	if !strings.Contains(f.Fix, "shop.svc.cluster.local") {
		t.Errorf("fix %q", f.Fix)
	}

	// An outside name that does not resolve is not this rule.
	s.Logs[0].Lines = []string{"wget: bad address 'api.partner.example'"}
	if f := only(t, Diagnose(s)); f.Rule == "KD269" {
		t.Errorf("an outside name: %s", f.Cause)
	}
}

func TestServicePortProtocolDiffersFromThePods(t *testing.T) {
	s := snap()
	p := pod("dns-1", "dns")
	p.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "dns", ContainerPort: 53, Protocol: "UDP"}}
	s.Pods = []kube.Pod{p}
	svc := service("dns", map[string]string{"app": "web"}, port(53))
	svc.Spec.Ports[0].Port = 53
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("dns", 1)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD271", "Service shop/dns", "port 53 is TCP", "declare its target port 53 as UDP only", "UDP traffic to the Service never reaches them")
	if f.Severity != Warning || !strings.Contains(f.Fix, "protocol UDP") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// Both protocols declared, or the Service's protocol matches: nothing to say.
	p.Spec.Containers[0].Ports = append(p.Spec.Containers[0].Ports, kube.ContainerPort{Name: "dns-tcp", ContainerPort: 53})
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("both protocols declared: %v", r.Findings)
	}
}

func TestIngressServesAHostItsTLSDoesNotCover(t *testing.T) {
	s := snap()
	defaultIngressClass(s)
	deployment(s, "web", 1, 1)
	s.Pods = []kube.Pod{pod("web-rs-a", "web")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Secrets = []kube.KeySet{{Namespace: "shop", Name: "shop-tls", Type: "kubernetes.io/tls", Keys: []string{"tls.crt", "tls.key"}}}
	ing := ingress("shop", "web", 80, "")
	api := ing.Spec.Rules[0]
	api.Host = "api.shop.example.com"
	ing.Spec.Rules = append(ing.Spec.Rules, api)
	ing.Spec.TLS = []kube.IngressTLS{{Hosts: []string{"www.shop.example.com", "api.shop.example.com"}, SecretName: "shop-tls"}}
	s.Ingresses = []kube.Ingress{ing}
	f := only(t, Diagnose(s))
	expect(t, f, "KD272", "Ingress shop/shop", "TLS for www.shop.example.com, api.shop.example.com", "also serve shop.example.com", "default certificate")

	// A wildcard covers one label; a host covered exactly is fine.
	ing.Spec.TLS = []kube.IngressTLS{{Hosts: []string{"*.shop.example.com", "shop.example.com"}, SecretName: "shop-tls"}}
	s.Ingresses = []kube.Ingress{ing}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("covered hosts: %v", r.Findings)
	}
	for tls, host := range map[string]string{"*.example.com": "a.b.example.com", "*.shop.example.com": "shop.example.com"} {
		if tlsCovers(tls, host) {
			t.Errorf("%s should not cover %s", tls, host)
		}
	}
}

func TestReplicasShareAReadWriteOnceClaim(t *testing.T) {
	s := snap()
	deployment(s, "web", 3, 3)
	s.Workloads[0].Spec.Template.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "uploads"}}}
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "uploads", Namespace: "shop"}
	pvc.Spec.AccessModes = []string{"ReadWriteOnce"}
	pvc.Status.Phase = "Bound"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	s.Pods = []kube.Pod{pod("web-1", "web"), pod("web-2", "web"), pod("web-3", "web")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD287", "Deployment shop/web", "runs 3 replicas", "PersistentVolumeClaim uploads, which is ReadWriteOnce", "Multi-Attach")
	if f.Severity != Warning || !strings.Contains(f.Fix, "volumeClaimTemplates") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// One replica, or a ReadWriteMany claim: nothing to say.
	s.PVCs[0].Spec.AccessModes = []string{"ReadWriteMany"}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("ReadWriteMany: %v", r.Findings)
	}
	s.PVCs[0].Spec.AccessModes = []string{"ReadWriteOnce"}
	one := int32(1)
	s.Workloads[0].Spec.Replicas = &one
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("one replica: %v", r.Findings)
	}
}

func TestJobFailedAtOnceByItsPodFailurePolicy(t *testing.T) {
	s := snap()
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "migrate", Namespace: "shop"}
	j.Status.Conditions = []kube.Condition{{Type: "Failed", Status: "True", Reason: "PodFailurePolicy",
		Message: "Container migrate for pod shop/migrate-x2k9p failed with exit code 3 matching FailJob rule at index 0"}}
	s.Jobs = []kube.Job{j}
	p := pod("migrate-x2k9p", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "migrate", Controller: yes()}}
	p.Status.Phase = "Failed"
	p.Status.ContainerStatuses = []kube.ContainerStatus{{Name: "web", State: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 3, Reason: "Error"}}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "Job shop/migrate", "exited with code 3", "podFailurePolicy matched that exit", "without the retries", "matching FailJob rule at index 0")
	if !strings.Contains(f.Fix, "Ignore or Count") {
		t.Errorf("fix %q", f.Fix)
	}

	// Failed by its backoff limit: no word about a policy.
	s.Jobs[0].Status.Conditions[0].Reason = "BackoffLimitExceeded"
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "podFailurePolicy") {
		t.Errorf("a backoff failure: %s", f.Cause)
	}
}

func TestOOMKilledAtALimitRangeDefault(t *testing.T) {
	s := snap()
	p := pod("worker-5f7d-x2k9p", "worker")
	p.Metadata.Annotations = map[string]string{"kubernetes.io/limit-ranger": "LimitRanger plugin set: cpu, memory request for container web; cpu, memory limit for container web"}
	p.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "16Mi"}
	crashed(&p, 137, "OOMKilled", 4)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD111", "ReplicaSet shop/worker-rs", "more than its 16Mi memory limit", "sets no memory limit for web", "LimitRange gave it its default")
	if !strings.Contains(f.Fix, "LimitRange") || len(f.Evidence) < 4 {
		t.Errorf("fix %q, %d evidence", f.Fix, len(f.Evidence))
	}

	// A limit the pod template set itself: the LimitRange is not blamed, even if it defaulted the request.
	p.Metadata.Annotations["kubernetes.io/limit-ranger"] = "LimitRanger plugin set: memory request for container web"
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "LimitRange") {
		t.Errorf("the pod's own limit was blamed on a LimitRange: %s", f.Cause)
	}
}

func TestReadyPodsHeldUnavailableByMinReadySeconds(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 2)
	s.Workloads[0].Spec.MinReadySeconds = 3600
	s.Pods = []kube.Pod{pod("web-1", "web"), pod("web-2", "web")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD288", "Deployment shop/web", "2 of 2 pods ready but only 0 available", "minReadySeconds is 3600", "1h0m0s")
	if f.Severity != Warning || !strings.Contains(f.Fix, "not a timeout") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// Available once the wait has passed, or a short wait: nothing to say.
	s.Workloads[0].Status.AvailableReplicas = 2
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("available pods: %v", r.Findings)
	}
	s.Workloads[0].Status.AvailableReplicas = 0
	s.Workloads[0].Spec.MinReadySeconds = 10
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a ten-second wait: %v", r.Findings)
	}
}

func TestCommandUsesAShellVariableWithNoShell(t *testing.T) {
	s := snap()
	p := pod("worker-6d9f7-abcde", "worker")
	c := &p.Spec.Containers[0]
	c.Command = []string{"sleep", "$SLEEP_SECONDS"}
	c.Env = []kube.EnvVar{{Name: "SLEEP_SECONDS", Value: "3600"}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"sleep: invalid number '$SLEEP_SECONDS'"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD213", "ReplicaSet shop/worker-rs", "command uses $SLEEP_SECONDS", "runs without a shell", "expands only $(SLEEP_SECONDS)", "invalid number")
	if !strings.HasPrefix(f.Fix, "Write it as $(SLEEP_SECONDS)") {
		t.Errorf("fix %q", f.Fix)
	}

	// The braced form in args, for a variable the container does not define.
	c.Command, c.Args, c.Env = []string{"/app/server"}, []string{"--port=${PORT}"}, nil
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{`invalid value "${PORT}" for flag -port: parse error`}
	f = only(t, Diagnose(s))
	expect(t, f, "KD213", "ReplicaSet shop/worker-rs", "args uses ${PORT}")
	if !strings.HasPrefix(f.Fix, "Define PORT") {
		t.Errorf("fix %q", f.Fix)
	}

	// Under sh -c the shell expands it: not this rule.
	c.Command, c.Args = []string{"/bin/sh", "-c"}, []string{"exec server --port=$PORT"}
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{"server: bad port $PORT"}
	if f := only(t, Diagnose(s)); f.Rule == "KD213" {
		t.Errorf("a shell command: %s", f.Cause)
	}
}

func TestVolumeMountHidesTheCommand(t *testing.T) {
	s := snap()
	p := pod("api-7d9f-k2x8q", "api")
	c := &p.Spec.Containers[0]
	c.Command = []string{"/app/server", "--port=8080"}
	c.VolumeMounts = []kube.VolumeMount{{Name: "data", MountPath: "/app"}}
	p.Spec.Volumes = []kube.Volume{{Name: "data", EmptyDir: &kube.EmptyDirVolumeSource{}}}
	notReady(&p)
	p.Status.ContainerStatuses[0].RestartCount = 3
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
	p.Status.ContainerStatuses[0].LastTerminationState = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 128, Reason: "StartError",
		Message: `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: exec: "/app/server": stat /app/server: no such file or directory`}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD214", "ReplicaSet shop/api-rs", "runs /app/server", "volume data (an emptyDir, which starts empty) is mounted at /app", "replaces everything the image has there")
	if !strings.Contains(f.Fix, "/app/data") {
		t.Errorf("fix %q", f.Fix)
	}

	// The same error with no volume over the command is the plain "not in the image".
	c.VolumeMounts = []kube.VolumeMount{{Name: "data", MountPath: "/var/cache"}}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD114", "ReplicaSet shop/api-rs", "not in image")
}

func TestAppListensOnLocalhostOnly(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	notReady(&p)
	c := &p.Spec.Containers[0]
	c.Command = []string{"httpd", "-f", "-p", "127.0.0.1:8080", "-h", "/www"}
	c.ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/", Port: named("http")}}
	s.Pods = []kube.Pod{p}
	refused := event("Pod", p.Metadata.Name, "Unhealthy", `Readiness probe failed: Get "http://10.244.0.9:8080/": dial tcp 10.244.0.9:8080: connect: connection refused`, time.Minute)
	s.Events = []kube.Event{refused}
	f := only(t, Diagnose(s))
	expect(t, f, "KD215", "ReplicaSet shop/web-rs", "refused on port 8080", "loopback address only (its command binds 127.0.0.1:8080)", "never becomes ready")
	if !strings.Contains(f.Fix, "0.0.0.0") {
		t.Errorf("fix %q", f.Fix)
	}

	// A bind flag, a bind variable, and the server's own log line each show it.
	c.Command = []string{"uvicorn", "app:api", "--host", "localhost", "--port", "8080"}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD215", "ReplicaSet shop/web-rs", "its command sets --host localhost")
	c.Command, c.Env = []string{"node", "server.js"}, []kube.EnvVar{{Name: "HOST", Value: "127.0.0.1"}, {Name: "DB_HOST", Value: "localhost"}}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD215", "ReplicaSet shop/web-rs", "its env sets HOST=127.0.0.1")
	c.Env = []kube.EnvVar{{Name: "DB_HOST", Value: "localhost"}}
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Lines: []string{"Server listening on http://127.0.0.1:8080"}}}
	expect(t, only(t, Diagnose(s)), "KD215", "ReplicaSet shop/web-rs", "its log says")

	// A client setting such as DB_HOST=localhost alone, or another port in the log, is not a bind address.
	s.Logs[0].Lines = []string{"metrics listening on 127.0.0.1:9100"}
	if f := only(t, Diagnose(s)); f.Rule == "KD215" {
		t.Errorf("blamed a client setting or another port: %s", f.Cause)
	}
}

func TestPodRanPastItsActiveDeadline(t *testing.T) {
	s := snap()
	d := int64(20)
	p := pod("report-x7k2p", "report")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "report", Controller: yes()}}
	p.Spec.ActiveDeadlineSeconds = &d
	p.Status.Phase, p.Status.Reason = "Failed", "DeadlineExceeded"
	p.Status.Message = "Pod was active on the node longer than the specified deadline"
	p.Status.ContainerStatuses = []kube.ContainerStatus{{Name: "app", RestartCount: 0,
		State: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 137, Reason: "Error"}}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD195", "Job shop/report", "longer than its spec.activeDeadlineSeconds (20 s)", "DeadlineExceeded", "each attempt")
	if !strings.Contains(f.Fix, "Job's own spec.activeDeadlineSeconds") {
		t.Errorf("fix %q", f.Fix)
	}

	// A bare pod: no word about Jobs, and not mistaken for a crash by its exit code 137.
	p.Metadata.OwnerReferences = nil
	s.Pods = []kube.Pod{p}
	f = only(t, Diagnose(s))
	expect(t, f, "KD195", "Pod shop/report-x7k2p", "stopped the pod")
	if strings.Contains(f.Cause, "Job") {
		t.Errorf("a bare pod's cause mentions a Job: %s", f.Cause)
	}
}

func TestNodeRejectsAPodWhoseLabelsDoNotMatch(t *testing.T) {
	s := snap()
	n := node("kd-faults-control-plane", "4", "16Gi")
	n.Metadata.Labels = map[string]string{"kubernetes.io/hostname": "kd-faults-control-plane", "disktype": "hdd"}
	s.Nodes = []kube.Node{n}
	p := pod("batch-7kq2m", "batch")
	p.Spec.NodeName = "kd-faults-control-plane"
	p.Spec.NodeSelector = map[string]string{"disktype": "ssd", "kubernetes.io/hostname": "kd-faults-control-plane"}
	p.Status.Phase, p.Status.Reason = "Failed", "NodeAffinity"
	p.Status.Message = "Pod was rejected: Predicate NodeAffinity failed: node(s) didn't match Pod's node affinity/selector"
	p.Status.Conditions, p.Status.ContainerStatuses = nil, nil
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD242", "ReplicaSet shop/batch-rs", "names node kd-faults-control-plane in spec.nodeName",
		"nodeSelector disktype=ssd", "the node lacks disktype=ssd)", "NodeAffinity")

	// Affinity instead of a nodeSelector, and a node the snapshot does not hold: no labels to compare.
	p.Spec.NodeSelector = nil
	s.Nodes, s.Pods = nil, []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD242", "ReplicaSet shop/batch-rs", "its node affinity does not match")
	if strings.Contains(f.Cause, "lacks") {
		t.Errorf("no node to compare, yet the cause names missing labels: %s", f.Cause)
	}
}

func TestNodeRejectsAPodWhoseHostPortIsTaken(t *testing.T) {
	s := snap()
	p := pod("agent-5f8wd", "agent")
	p.Spec.NodeName = "kd-faults-control-plane"
	p.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "http", ContainerPort: 8080, HostPort: 8080}}
	p.Status.Phase, p.Status.Reason = "Failed", "NodePorts"
	p.Status.Message = "Pod was rejected: Predicate NodePorts failed: node(s) didn't have free ports for the requested pod ports"
	p.Status.Conditions, p.Status.ContainerStatuses = nil, nil
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD243", "ReplicaSet shop/agent-rs", "asks for host port 8080", "another pod on that node already holds", "NodePorts")
}

func TestDaemonSetMatchesNoNode(t *testing.T) {
	s := snap()
	s.Nodes = []kube.Node{node("node-1", "4", "16Gi")}
	ds := kube.Workload{Kind: "DaemonSet", Metadata: kube.ObjectMeta{Name: "agent", Namespace: "shop", CreationTimestamp: t0.Add(-time.Hour)}}
	ds.Spec.Template.Spec.NodeSelector = map[string]string{"disktype": "ssd"}
	s.Workloads = []kube.Workload{ds}
	f := only(t, Diagnose(s))
	expect(t, f, "KD282", "DaemonSet shop/agent", "requires the labels disktype=ssd", "none of the cluster's 1 node has them", "runs no pods")
	if f.Severity != Warning || !strings.Contains(f.Fix, "kubectl label node NODE disktype=ssd") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// A taint every node has and the pods do not tolerate.
	ds.Spec.Template.Spec.NodeSelector = nil
	s.Nodes[0].Spec.Taints = []kube.Taint{{Key: "dedicated", Value: "gpu", Effect: "NoSchedule"}}
	s.Workloads = []kube.Workload{ds}
	expect(t, only(t, Diagnose(s)), "KD282", "DaemonSet shop/agent", "every node has a taint")

	// Tolerated: the reason is not the nodes.
	ds.Spec.Template.Spec.Tolerations = []kube.Toleration{{Key: "dedicated", Operator: "Exists"}}
	s.Workloads = []kube.Workload{ds}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a DaemonSet that tolerates the taint is not reported: %+v", r.Findings)
	}
}

func TestJobWithParallelismZero(t *testing.T) {
	s := snap()
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "migrate", Namespace: "shop", CreationTimestamp: t0.Add(-10 * time.Minute)}
	zero := int32(0)
	j.Spec.Parallelism = &zero
	s.Jobs = []kube.Job{j}
	f := only(t, Diagnose(s))
	expect(t, f, "KD283", "Job shop/migrate", "parallelism 0", "none in 10m0s", "never complete")
	if !strings.Contains(f.Fix, `"parallelism":1`) {
		t.Errorf("fix %q", f.Fix)
	}

	// A Job that completed before it was paused is fine.
	j.Status.Conditions = []kube.Condition{{Type: "Complete", Status: "True"}}
	s.Jobs = []kube.Job{j}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a completed Job is not reported: %+v", r.Findings)
	}
}

func TestStartupProbeThatCannotPass(t *testing.T) {
	// A startup probe on a port name the container lacks: the container is never marked started, so it never
	// becomes ready, and its readiness probe never runs.
	s := snap()
	p := pod("api", "")
	notReady(&p)
	p.Spec.Containers[0].StartupProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/healthz", Port: named("admin")}}
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/", Port: named("http")}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD203", "Pod shop/api", `startup probe names port "admin"`, "never marked started")
	if f.Severity != Critical {
		t.Errorf("a startup probe that cannot pass keeps the pod out of service: %s", f.Severity)
	}

	// A startup probe that speaks HTTPS to plain HTTP: the kubelet restarts the container before it starts.
	p = pod("api", "")
	p.Spec.Containers[0].StartupProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/", Port: port(8080), Scheme: "HTTPS"}}
	crashed(&p, 143, "Error", 6)
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "api", "Unhealthy", `Startup probe failed: Get "https://10.244.0.9:8080/": http: server gave HTTP response to HTTPS client`, time.Minute),
		event("Pod", "api", "Killing", "Container web failed startup probe, will be restarted", time.Minute)}
	expect(t, only(t, Diagnose(s)), "KD202", "Pod shop/api", "startup probe uses scheme HTTPS", "before it is ever marked started (6 restarts)")
}
