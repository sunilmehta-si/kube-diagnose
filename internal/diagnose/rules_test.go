package diagnose

import (
	"fmt"
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
	if strings.Contains(f.Cause, "differs only") {
		t.Errorf("pass is not password: %s", f.Cause)
	}
	// The key the pod reads, written the environment variable's way; the Secret's key in the file's way.
	s.Pods[0].Status.ContainerStatuses[0].State.Waiting.Message = "couldn't find key DB_PASSWORD in Secret shop/db"
	s.Secrets = []kube.KeySet{keys("shop", "db", "db-password", "db-user")}
	f = only(t, Diagnose(s))
	expect(t, f, "KD132", "Pod shop/web", "reads key DB_PASSWORD from Secret db", "it has db-password, which differs only in case and separators")
	if !strings.Contains(f.Fix, "Read key db-password") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.Pods[0].Status.ContainerStatuses[0].State.Waiting.Message = "couldn't find key db_password in Secret shop/db"
	expect(t, only(t, Diagnose(s)), "KD132", "Pod shop/web", "it has db-password, which differs only in its separators")
	s.Pods[0].Status.ContainerStatuses[0].State.Waiting.Message = "couldn't find key db-pasword in Secret shop/db"
	expect(t, only(t, Diagnose(s)), "KD132", "Pod shop/web", "it has db-password, which differs only in spelling")
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

	// Kubernetes 1.37 writes the event with a capital: "Create Claim ...". The claim is named all the same.
	s.Events[0].Message = "C" + s.Events[0].Message[1:]
	expect(t, only(t, Diagnose(s)), "KD170", "StatefulSet shop/db", "cannot create PersistentVolumeClaim data-db-0 from its volumeClaimTemplates")

	// A LimitRange's PersistentVolumeClaim minimum rejects the claim in the same place.
	s.Events[0].Message = `Create Claim data-db-0 for Pod db-0 in StatefulSet db failed error: persistentvolumeclaims "data-db-0" is forbidden: minimum storage usage per PersistentVolumeClaim is 1Gi, but request is 100Mi`
	f = only(t, Diagnose(s))
	expect(t, f, "KD174", "StatefulSet shop/db", "cannot create PersistentVolumeClaim data-db-0 from its volumeClaimTemplates", "minimum storage usage per PersistentVolumeClaim is 1Gi, but request is 100Mi")
	if !strings.Contains(f.Fix, "--cascade=orphan") {
		t.Errorf("%s: %s", f.Title, f.Fix)
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
	s.Services[0].Spec.Selector = map[string]string{"app": "database"}
	s.EndpointSlices = []kube.EndpointSlice{slice("db-headless", 0)}
	expect(t, only(t, Diagnose(s)), "KD182", "StatefulSet shop/db", "is headless, but it selects pods with app=database and the StatefulSet's pods carry app=web", "db-0.db-headless.shop.svc does not resolve")
	s.Services[0].Spec.Selector = map[string]string{"app": "web"}
	s.EndpointSlices = []kube.EndpointSlice{slice("db-headless", 1)}
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

	// Port 53 allowed to the DNS pods by podSelector alone: that names pods of shop, not kube-system's.
	s.NetworkPolicies[0].Spec.Egress[1].To = []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}}}}
	f = Diagnose(s).Findings[0]
	expect(t, f, "KD123", "Deployment shop/web", "allows port 53 only to pods matching k8s-app=kube-dns", "picks pods of namespace shop alone, while cluster DNS runs in kube-system")
	if !strings.Contains(f.Fix, "kubernetes.io/metadata.name: kube-system") {
		t.Errorf("fix: %s", f.Fix)
	}
	// With the namespaceSelector beside it, DNS gets out.
	s.NetworkPolicies[0].Spec.Egress[1].To[0].NamespaceSelector = &kube.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}}
	if f := Diagnose(s).Findings[0]; f.Rule == "KD123" {
		t.Errorf("DNS is allowed to kube-system: %s", f.Cause)
	}
}

func TestCrashOnARefusedServiceWithNoPods(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	db := service("db", map[string]string{"app": "db"}, port(5432))
	db.Spec.ClusterIP, db.Spec.Ports[0].Port = "10.96.12.7", 5432
	s.Services = []kube.Service{db}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"wget: can't connect to remote host (10.96.12.7): Connection refused"}}}
	f := Diagnose(s).Findings[0]
	expect(t, f, "KD124", "Deployment shop/web", "Service db refuses its connection", "no pod has its selector's labels app=db")

	s.Logs[0].Lines = []string{`psql: error: connection to server at "db" (10.96.12.7), port 5432 failed: Connection refused`}
	expect(t, Diagnose(s).Findings[0], "KD124", "Deployment shop/web", "Service db refuses its connection")

	// A Service with a ready pod whose readiness probe reaches the port refuses for another reason: the crash rule
	// quotes the log.
	q := pod("db-1", "")
	q.Metadata.Labels = map[string]string{"app": "db"}
	q.Spec.Containers[0].ReadinessProbe = &kube.Probe{TCPSocket: &kube.TCPSocketAction{Port: port(5432)}}
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
	// "manual" names no StorageClass, but static volumes carry it: KD150 would be a false alarm. The claim waits
	// because the one volume of that class is taken.
	expect(t, only(t, Diagnose(s)), "KD250", "PersistentVolumeClaim shop/data", "the nearest, data-pv, is bound to another claim")

	// A free volume of the class: the claim is binding.
	s.PVs[0].Status.Phase = "Available"
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
	np.Spec.Egress = append(np.Spec.Egress, kube.NetworkPolicyRule{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "172.18.0.2/32"}}}, Ports: []kube.NetworkPolicyPort{{Port: &api}}})
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

	// The runtime reports the kill as Error, as it did once in the fault suite: the LimitRange is still named.
	crashed(&p, 137, "Error", 4)
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD111", "ReplicaSet shop/worker-rs", "reported the kill as Error, not OOMKilled", "LimitRange gave it its default")
	crashed(&p, 137, "OOMKilled", 4)

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

func TestServiceAlsoSelectsAnotherWorkloadsPods(t *testing.T) {
	s := snap()
	web1, web2 := pod("web-1", "web"), pod("web-2", "web")
	worker := pod("worker-1", "worker")
	worker.Spec.Containers[0].Ports = nil
	s.Pods = []kube.Pod{web1, web2, worker}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, port(8080))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 3)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD273", "Service shop/web", "selects pods with app=web", "matches ReplicaSet worker-rs as well as ReplicaSet web-rs", "1 ready pod do not declare port 8080", "about 1 in 3 connections")
	if f.Severity != Warning || !strings.Contains(f.Fix, "selector only its own pods match") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// A canary that serves the same port, and a named targetPort (which leaves the other pods out), are fine.
	worker.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "http", ContainerPort: 8080}}
	s.Pods = []kube.Pod{web1, web2, worker}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a second workload that serves the port: %v", r.Findings)
	}
	worker.Spec.Containers[0].Ports = nil
	s.Pods = []kube.Pod{web1, web2, worker}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD273" {
			t.Errorf("a named targetPort: %s", f.Cause)
		}
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

func TestPodsCoveredByMoreThanOnePDB(t *testing.T) {
	s := snap()
	s.Pods = []kube.Pod{pod("web-1", "web"), pod("web-2", "web")}
	budget := func(name string, labels map[string]string) kube.PodDisruptionBudget {
		var b kube.PodDisruptionBudget
		b.Metadata = kube.ObjectMeta{Name: name, Namespace: "shop"}
		b.Spec.MaxUnavailable = &kube.IntOrString{Int: 1}
		b.Spec.Selector = &kube.LabelSelector{MatchLabels: labels}
		b.Status.DisruptionsAllowed, b.Status.CurrentHealthy, b.Status.DesiredHealthy, b.Status.ExpectedPods = 1, 2, 1, 2
		return b
	}
	s.PDBs = []kube.PodDisruptionBudget{budget("web", map[string]string{"app": "web"}), budget("team-default", map[string]string{})}
	f := only(t, Diagnose(s))
	expect(t, f, "KD289", "PodDisruptionBudget shop/team-default", "PodDisruptionBudgets team-default and web all select 2 pods", "eviction API refuses a pod that more than one budget covers", "node drain")
	if f.Severity != Warning || len(f.Evidence) != 3 || !strings.Contains(f.Fix, "one budget") {
		t.Errorf("severity %s evidence %d fix %q", f.Severity, len(f.Evidence), f.Fix)
	}

	// Budgets for different pods do not overlap.
	s.PDBs[1].Spec.Selector = &kube.LabelSelector{MatchLabels: map[string]string{"app": "worker"}}
	s.PDBs[1].Status.ExpectedPods = 0
	s.Pods = append(s.Pods, func() kube.Pod {
		p := pod("worker-1", "worker")
		p.Metadata.Labels = map[string]string{"app": "worker"}
		return p
	}())
	s.PDBs[1].Status.ExpectedPods = 1
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("separate budgets: %v", r.Findings)
	}
}

func TestHPASwitchedOffByZeroReplicas(t *testing.T) {
	s := snap()
	s.HPAs = []kube.HorizontalPodAutoscaler{hpa("web", kube.Condition{Type: "AbleToScale", Status: "True", Reason: "SucceededGetScale"},
		kube.Condition{Type: "ScalingActive", Status: "False", Reason: "ScalingDisabled", Message: "scaling is disabled since the replica count of the target is zero"})}
	f := only(t, Diagnose(s))
	expect(t, f, "KD290", "HorizontalPodAutoscaler shop/web", "does not scale Deployment web", "has 0 replicas", "stays at zero")
	if f.Severity != Warning || f.Affects[0] != (kube.Ref{Kind: "Deployment", Namespace: "shop", Name: "web"}) || !strings.Contains(f.Fix, "drop the replicas field") {
		t.Errorf("%+v", f)
	}
}

func TestMoreThanOneHPAControlsTheSamePods(t *testing.T) {
	s := snap()
	amb := kube.Condition{Type: "ScalingActive", Status: "False", Reason: "AmbiguousSelector",
		Message: "pods by selector app=web are controlled by more than one HPA (e.g. [shop/web-cpu shop/web-memory])"}
	s.HPAs = []kube.HorizontalPodAutoscaler{hpa("web-memory", amb), hpa("web-cpu", amb)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD291", "HorizontalPodAutoscaler shop/web-cpu", "HPAs web-cpu and web-memory all scale Deployment web", "none of them scales it")
	if f.Severity != Warning || len(f.Evidence) != 3 || !strings.Contains(f.Fix, "list every metric") {
		t.Errorf("severity %s evidence %d fix %q", f.Severity, len(f.Evidence), f.Fix)
	}

	// Before the controller has said so, two HPAs with one target are reported from their specs.
	s.HPAs = []kube.HorizontalPodAutoscaler{hpa("web-memory"), hpa("web-cpu")}
	expect(t, only(t, Diagnose(s)), "KD291", "HorizontalPodAutoscaler shop/web-cpu", "HPAs web-cpu and web-memory")

	// Different targets whose pods overlap: only the controller's condition shows it.
	other := hpa("api", amb)
	other.Spec.ScaleTargetRef.Name = "api"
	s.HPAs = []kube.HorizontalPodAutoscaler{other}
	expect(t, only(t, Diagnose(s)), "KD291", "HorizontalPodAutoscaler shop/api", "another HPA controls the same pods", "more than one HPA")
}

func TestJobHeldByASidecar(t *testing.T) {
	s := snap()
	p := pod("report-x7k2p", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "report", Controller: yes()}}
	p.Spec.Containers = []kube.Container{{Name: "main", Image: "registry.example.com/shop/report:2.0"}, {Name: "proxy", Image: "registry.example.com/shop/proxy:1.9"}}
	p.Status.Conditions[1].Status = "False"
	p.Status.ContainerStatuses = []kube.ContainerStatus{
		{Name: "main", State: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 0, Reason: "Completed", FinishedAt: t0.Add(-10 * time.Minute)}}},
		{Name: "proxy", Ready: true, State: kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: t0.Add(-11 * time.Minute)}}},
	}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD292", "Job shop/report", "has done its work (1 container main exited 0, 10m0s ago)", "1 container proxy is still running", "the Job never completes")
	if f.Severity != Warning || !strings.Contains(f.Fix, "initContainers with restartPolicy: Always") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// Just finished: the other container may be about to stop too.
	p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = t0.Add(-20 * time.Second)
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("finished 20 seconds ago: %v", r.Findings)
	}

	// The same pod under a Deployment is not a Job waiting to complete.
	p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = t0.Add(-10 * time.Minute)
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "ReplicaSet", Name: "report-rs", Controller: yes()}}
	s.Pods = []kube.Pod{p}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD292" {
			t.Errorf("a Deployment's pod: %s", f.Cause)
		}
	}
}

func TestEnvValueRefersToAVariableDefinedLater(t *testing.T) {
	s := snap()
	p := pod("worker-6d9f7-abcde", "worker")
	c := &p.Spec.Containers[0]
	c.Command = []string{"sh", "-c", `wget -q -T 5 -O /dev/null "$API_URL" || exit 1; sleep 3600`}
	c.Env = []kube.EnvVar{{Name: "API_URL", Value: "http://$(API_HOST):8080/"}, {Name: "API_HOST", Value: "api"}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"wget: bad address '$(API_HOST):8080'"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD216", "ReplicaSet shop/worker-rs", "env API_URL refers to $(API_HOST), which is defined after API_URL in the env list", "holds the text $(API_HOST) unexpanded", "bad address")
	if !strings.HasPrefix(f.Fix, "Move API_HOST above API_URL") {
		t.Errorf("fix %q", f.Fix)
	}

	// Not defined anywhere.
	c.Env = c.Env[:1]
	s.Pods = []kube.Pod{p}
	f = only(t, Diagnose(s))
	expect(t, f, "KD216", "ReplicaSet shop/worker-rs", "which the container's env and envFrom do not define")
	if !strings.HasPrefix(f.Fix, "Define API_HOST in the container's env above API_URL") {
		t.Errorf("fix %q", f.Fix)
	}

	// Defined before it: the kubelet expands it, and the crash is something else.
	c.Env = []kube.EnvVar{{Name: "API_HOST", Value: "api"}, {Name: "API_URL", Value: "http://$(API_HOST):8080/"}}
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD216" {
		t.Errorf("defined before: %s", f.Cause)
	}
}

func TestContainerConnectsToLocalhostForAService(t *testing.T) {
	s := snap()
	p := pod("worker-6d9f7-abcde", "worker")
	p.Metadata.Labels = map[string]string{"app": "worker"}
	c := &p.Spec.Containers[0]
	c.Ports = nil
	c.Env = []kube.EnvVar{{Name: "LOG_LEVEL", Value: "info"}, {Name: "REDIS_URL", Value: "redis://127.0.0.1:6379/0"}}
	crashed(&p, 1, "Error", 4)
	redis := pod("redis-0", "redis")
	redis.Metadata.Labels = map[string]string{"app": "redis"}
	redis.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "redis", ContainerPort: 6379}}
	s.Pods = []kube.Pod{p, redis}
	s.Services = []kube.Service{service("redis", map[string]string{"app": "redis"}, port(6379))}
	s.Services[0].Spec.Ports[0].Port = 6379
	s.EndpointSlices = []kube.EndpointSlice{slice("redis", 1)}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"starting worker", "dial tcp 127.0.0.1:6379: connect: connection refused"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD217", "ReplicaSet shop/worker-rs", "connection to 127.0.0.1:6379 is refused", "localhost is the pod itself", "Service redis, in other pods")
	if f.Fix != "Connect to redis:6379 instead of 127.0.0.1:6379: set it in env REDIS_URL (now redis://127.0.0.1:6379/0)." {
		t.Errorf("fix %q", f.Fix)
	}

	// busybox wget names the port only in its "Connecting to" line.
	s.Logs[0].Lines = []string{"Connecting to localhost:6379 (127.0.0.1:6379)", "wget: can't connect to remote host (127.0.0.1): Connection refused"}
	expect(t, only(t, Diagnose(s)), "KD217", "ReplicaSet shop/worker-rs", "connection to localhost:6379 is refused")

	// A port one of the pod's own containers declares, or one no Service serves, is another problem.
	c.Ports = []kube.ContainerPort{{Name: "cache", ContainerPort: 6379}}
	s.Pods = []kube.Pod{p, redis}
	if f := only(t, Diagnose(s)); f.Rule == "KD217" {
		t.Errorf("the pod's own port: %s", f.Cause)
	}
	c.Ports = nil
	s.Pods = []kube.Pod{p, redis}
	s.Logs[0].Lines = []string{"dial tcp 127.0.0.1:9999: connect: connection refused"}
	if f := only(t, Diagnose(s)); f.Rule == "KD217" {
		t.Errorf("a port no Service serves: %s", f.Cause)
	}
}

func TestContainerConnectsToAPortTheServiceDoesNotExpose(t *testing.T) {
	s := snap()
	client := pod("client-6d9f7-abcde", "client")
	client.Metadata.Labels = map[string]string{"app": "client"}
	client.Spec.Containers[0].Ports = nil
	crashed(&client, 1, "Error", 4)
	s.Pods = []kube.Pod{client, pod("web-1", "web")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, port(8080))}
	s.Services[0].Spec.ClusterIP = "10.96.14.7"
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Logs = []snapshot.Log{{Pod: client.Ref(), Container: "web", Previous: true, Lines: []string{"Connecting to web:8080 (10.96.14.7:8080)", "wget: download timed out"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD218", "ReplicaSet shop/client-rs", "connection to Service web on port 8080 times out", "does not expose 8080", "listens on 80 and forwards to the pods' port 8080")
	if !strings.HasPrefix(f.Fix, "Connect to web:80: 8080 is the pods' port") {
		t.Errorf("fix %q", f.Fix)
	}

	// By cluster IP, refused, on a port that is not the pods' either.
	s.Logs[0].Lines = []string{"dial tcp 10.96.14.7:9090: connect: connection refused"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD218", "ReplicaSet shop/client-rs", "on port 9090 is refused", "it listens on 80")
	if !strings.HasPrefix(f.Fix, "Connect to one of Service web's ports (80)") {
		t.Errorf("fix %q", f.Fix)
	}

	// The Service's own port, or a headless Service (where the pods' port is right), is another problem.
	s.Logs[0].Lines = []string{"dial tcp 10.96.14.7:80: connect: connection refused"}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD218" {
			t.Errorf("the Service's port: %s", f.Cause)
		}
	}
	s.Services[0].Spec.ClusterIP = "None"
	s.Logs[0].Lines = []string{"Connecting to web:9090 (10.244.0.12:9090)", "wget: can't connect to remote host (10.244.0.12): Connection refused"}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD218" {
			t.Errorf("a headless Service: %s", f.Cause)
		}
	}
}

func TestContainerLacksACapabilityItUses(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	c := &p.Spec.Containers[0]
	c.SecurityContext = &kube.SecurityContext{Capabilities: &kube.Capabilities{Drop: []string{"ALL"}}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"chown: /var/cache/app: Operation not permitted"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD219", "ReplicaSet shop/web-rs", "securityContext drops ALL capabilities", "changing a file's owner needs CHOWN", "root too must hold")
	if !strings.HasPrefix(f.Fix, "Add CHOWN under securityContext.capabilities.add, keeping drop: [ALL]") {
		t.Errorf("fix %q", f.Fix)
	}

	// One named capability dropped, and nginx's way of saying it.
	c.SecurityContext.Capabilities.Drop = []string{"NET_BIND_SERVICE"}
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{"nginx: [emerg] bind() to 0.0.0.0:80 failed (1: Operation not permitted)"}
	expect(t, only(t, Diagnose(s)), "KD219", "ReplicaSet shop/web-rs", "securityContext drops NET_BIND_SERVICE", "binding a port below 1024 needs NET_BIND_SERVICE")

	// The capability is added back, or nothing is dropped: the refusal has another cause.
	c.SecurityContext.Capabilities = &kube.Capabilities{Drop: []string{"ALL"}, Add: []string{"NET_BIND_SERVICE"}}
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD219" {
		t.Errorf("added back: %s", f.Cause)
	}
	c.SecurityContext.Capabilities = nil
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD219" {
		t.Errorf("nothing dropped: %s", f.Cause)
	}
}

func TestInitContainerWaitsForItsOwnPod(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.InitContainers = []kube.Container{{Name: "wait-for-web", Image: "busybox"}}
	p.Status.Phase = "Pending"
	waiting(&p, "PodInitializing", "")
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "wait-for-web", State: kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: t0.Add(-5 * time.Minute)}}}}
	s.Pods = []kube.Pod{p}
	web := service("web", map[string]string{"app": "web"}, port(8080))
	web.Spec.ClusterIP = "10.96.20.5"
	s.Services = []kube.Service{web}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "wait-for-web", Lines: []string{"waiting for web", "wget: can't connect to remote host (10.96.20.5): Connection refused"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD220", "Deployment shop/web", "init container wait-for-web waits for Service web", "the only pods behind that Service are Deployment web's own", "each waits for the other")
	if !strings.HasPrefix(f.Fix, "Remove the wait for web from init container wait-for-web") {
		t.Errorf("fix %q", f.Fix)
	}

	// With another workload behind the Service, the init container waits for that one: the plain finding.
	other := pod("web-canary-1", "web-canary")
	notReady(&other)
	s.Pods = []kube.Pod{p, other}
	found := false
	for _, x := range Diagnose(s).Findings {
		if x.Rule == "KD220" {
			t.Errorf("another workload serves it: %s", x.Cause)
		}
		found = found || (x.Rule == "KD119" && strings.Contains(x.Cause, "it waits for Service web, which has no ready pods"))
	}
	if !found {
		t.Errorf("want KD119 naming the Service: %v", Diagnose(s).Findings)
	}
}

func TestProbeFailureSaysWhatTheStatusMeans(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	notReady(&p)
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/ready", Port: port(8080)}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", p.Metadata.Name, "Unhealthy", "Readiness probe failed: HTTP probe failed with statuscode: 404", time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD120", "ReplicaSet shop/web-rs", "so it gets no traffic: the app answers 404, so it does not serve the probe's path")
	if !strings.HasPrefix(f.Fix, "Set the probe's path to one the app serves") {
		t.Errorf("fix %q", f.Fix)
	}
	for code, want := range map[string]string{"401": "needs credentials", "403": "needs credentials", "400": "Host header", "405": "does not accept GET",
		"503": "serves the path and reports itself unhealthy", "418": "the app answers 418"} {
		s.Events = []kube.Event{event("Pod", p.Metadata.Name, "Unhealthy", "Readiness probe failed: HTTP probe failed with statuscode: "+code, time.Minute)}
		expect(t, only(t, Diagnose(s)), "KD120", "ReplicaSet shop/web-rs", want)
	}

	// A liveness probe answered 503 restarts the container; the status is explained the same way.
	q := pod("api-7d9f-k2x8q", "api")
	q.Spec.Containers[0].LivenessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/healthz", Port: port(8080)}}
	crashed(&q, 137, "Error", 6)
	s.Pods = []kube.Pod{q}
	s.Events = []kube.Event{event("Pod", q.Metadata.Name, "Unhealthy", "Liveness probe failed: HTTP probe failed with statuscode: 503", time.Minute),
		event("Pod", q.Metadata.Name, "Killing", "Container web failed liveness probe, will be restarted", time.Minute)}
	f = only(t, Diagnose(s))
	expect(t, f, "KD112", "ReplicaSet shop/api-rs", "restarts it (6 restarts): the app answers 503, so it serves the path and reports itself unhealthy")
	if !strings.Contains(f.Fix, "out of a liveness probe") {
		t.Errorf("fix %q", f.Fix)
	}
}

func TestFlagAndItsValueAreOneArgument(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	c := &p.Spec.Containers[0]
	c.Command = []string{"/usr/local/bin/server"}
	c.Args = []string{"--port 8080", "--verbose"}
	crashed(&p, 2, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"Error: unknown flag: --port 8080", "Usage:", "  server [flags]"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD221", "ReplicaSet shop/web-rs", `its args holds "--port 8080" as one item`, "single argument", `unknown flag: --port 8080`)
	if !strings.HasPrefix(f.Fix, `Write the flag and its value as two items: "--port", "8080" (or one item "--port=8080").`) {
		t.Errorf("fix %q", f.Fix)
	}

	// Other ways of saying it: Go's flag package, glibc's getopt, musl's getopt (which leaves the dashes out) and
	// Python's argparse.
	for _, line := range []string{
		"flag provided but not defined: -port 8080",
		"server: unrecognized option '--port 8080'",
		"server: unrecognized option: port 8080",
		"server: error: unrecognized arguments: --port 8080",
	} {
		s.Logs[0].Lines = []string{line}
		if f := only(t, Diagnose(s)); f.Rule != "KD221" {
			t.Errorf("%q: %s %s", line, f.Rule, f.Cause)
		}
	}

	// In the command itself, after the program's name, with a short flag: no "=" form to offer.
	c.Command, c.Args = []string{"server", "-c /etc/app.conf"}, nil
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{"server: invalid option -- 'c /etc/app.conf'"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD221", "ReplicaSet shop/web-rs", `its command holds "-c /etc/app.conf" as one item`)
	if strings.Contains(f.Fix, "or one item") {
		t.Errorf("fix %q", f.Fix)
	}

	// The log does not quote the item, or the items are already split: another cause.
	s.Logs[0].Lines = []string{"error: cannot open database"}
	if f := only(t, Diagnose(s)); f.Rule == "KD221" {
		t.Errorf("unrelated log: %s", f.Cause)
	}
	c.Command, c.Args = []string{"server"}, []string{"--port", "8080"}
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{"Error: unknown flag: --port 8080"}
	if f := only(t, Diagnose(s)); f.Rule == "KD221" {
		t.Errorf("split items: %s", f.Cause)
	}
}

func TestCommandsInterpreterIsNotInTheImage(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	c := &p.Spec.Containers[0]
	c.Command = []string{"/scripts/run.sh"}
	c.VolumeMounts = []kube.VolumeMount{{Name: "scripts", MountPath: "/scripts"}}
	p.Spec.Volumes = []kube.Volume{{Name: "scripts", ConfigMap: &kube.ConfigMapVolumeSource{Name: "scripts"}}}
	crashed(&p, 255, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.ConfigMaps = []kube.KeySet{keys("shop", "scripts", "run.sh")}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"exec /scripts/run.sh: no such file or directory"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD222", "ReplicaSet shop/web-rs", "cannot run /scripts/run.sh, though the file is there (key run.sh of ConfigMap scripts)", "interpreter named on the script's first line (#!)")
	if !strings.Contains(f.Fix, "#!/bin/sh where there is no bash") || !strings.Contains(f.Fix, "Unix line endings") {
		t.Errorf("fix %q", f.Fix)
	}

	// The key is not in the ConfigMap: the file itself is missing, which is KD230's.
	s.ConfigMaps = []kube.KeySet{keys("shop", "scripts", "start.sh")}
	if f := only(t, Diagnose(s)); f.Rule == "KD222" {
		t.Errorf("missing key: %s", f.Cause)
	}

	// A file of the image: a script, or a binary whose loader the image lacks.
	c.Command, c.VolumeMounts = []string{"/usr/local/bin/server"}, nil
	p.Spec.Volumes = nil
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{"exec /usr/local/bin/server: no such file or directory"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD222", "ReplicaSet shop/web-rs", "cannot run /usr/local/bin/server, though the file is there", "dynamic loader of a binary built for another C library")
	if !strings.Contains(f.Fix, "CGO_ENABLED=0") {
		t.Errorf("fix %q", f.Fix)
	}

	// A file the app opens and does not find is not the runtime's exec line.
	s.Logs[0].Lines = []string{"open /etc/app/config.yaml: no such file or directory"}
	if f := only(t, Diagnose(s)); f.Rule == "KD222" {
		t.Errorf("app's own error: %s", f.Cause)
	}
}

func TestServiceLinkVariableReplacesTheAppsSetting(t *testing.T) {
	s := snap()
	p := pod("worker-5c7d9-qwert", "worker")
	p.Metadata.Labels = map[string]string{"app": "worker"}
	crashed(&p, 1, "Error", 4)
	cache := pod("cache-7d4f8-abcde", "cache")
	cache.Metadata.Labels = map[string]string{"app": "cache"}
	s.Pods = []kube.Pod{cache, p}
	svc := service("cache", map[string]string{"app": "cache"}, port(8080))
	svc.Spec.ClusterIP = "10.96.14.7"
	svc.Spec.Ports[0].Port = 6379
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("cache", 1)}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true,
		Lines: []string{"connecting to cache:tcp://10.96.14.7:6379", "nc: bad port 'tcp://10.96.14.7:6379'"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD223", "ReplicaSet shop/worker-rs", "reading CACHE_PORT as a setting of its own", "for Service cache that includes CACHE_PORT=tcp://10.96.14.7:6379", "expects a port number")
	if !strings.HasPrefix(f.Fix, "Set enableServiceLinks: false in the pod spec") || !strings.Contains(f.Fix, "define CACHE_PORT in the container's env") {
		t.Errorf("fix %q", f.Fix)
	}

	// The container sets the variable itself, or the pod turns service links off: the value did not come from there.
	p.Spec.Containers[0].Env = []kube.EnvVar{{Name: "CACHE_PORT", Value: "6379"}}
	s.Pods = []kube.Pod{cache, p}
	if f := only(t, Diagnose(s)); f.Rule == "KD223" {
		t.Errorf("own value: %s", f.Cause)
	}
	p.Spec.Containers[0].Env = nil
	off := false
	p.Spec.EnableServiceLinks = &off
	s.Pods = []kube.Pod{cache, p}
	if f := only(t, Diagnose(s)); f.Rule == "KD223" {
		t.Errorf("links off: %s", f.Cause)
	}

	// A Service created after the pod gave it no variables, and a headless Service gives none at all.
	p.Spec.EnableServiceLinks = nil
	p.Metadata.CreationTimestamp = t0.Add(-time.Hour)
	s.Pods = []kube.Pod{cache, p}
	s.Services[0].Metadata.CreationTimestamp = t0.Add(-time.Minute)
	if f := only(t, Diagnose(s)); f.Rule == "KD223" {
		t.Errorf("later Service: %s", f.Cause)
	}
	s.Services[0].Metadata.CreationTimestamp = t0.Add(-2 * time.Hour)
	if f := only(t, Diagnose(s)); f.Rule != "KD223" {
		t.Errorf("earlier Service: %s %s", f.Rule, f.Cause)
	}
	s.Services[0].Spec.ClusterIP = "None"
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD223" {
			t.Errorf("headless: %s", f.Cause)
		}
	}
}

func TestNonRootContainerIsDeniedAPathInItsImage(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	uid := int64(1000)
	p.Spec.SecurityContext = &kube.PodSecurityContext{RunAsUser: &uid}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"mkdir: can't create directory '/www': Permission denied"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD224", "ReplicaSet shop/web-rs", "runs as user 1000 and is denied /www, a path of the image itself, not of a volume", "belong to root")
	if !strings.HasPrefix(f.Fix, "Give the app a place it may write: mount an emptyDir at /www") {
		t.Errorf("fix %q", f.Fix)
	}

	// nginx's way of saying it, in a container that only sets runAsNonRoot.
	p.Spec.SecurityContext = nil
	p.Spec.Containers[0].SecurityContext = &kube.SecurityContext{RunAsNonRoot: yes()}
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{`nginx: [emerg] open() "/run/nginx.pid" failed (13: Permission denied)`}
	expect(t, only(t, Diagnose(s)), "KD224", "ReplicaSet shop/web-rs", "runs as a user other than root and is denied /run/nginx.pid")

	// A file of the kernel's, not of the image.
	s.Logs[0].Lines = []string{"sysctl: error setting key 'net.core.somaxconn': open /proc/sys/net/core/somaxconn: permission denied"}
	if f := only(t, Diagnose(s)); f.Rule == "KD224" {
		t.Errorf("/proc: %s", f.Cause)
	}
	s.Logs[0].Lines = []string{`nginx: [emerg] open() "/run/nginx.pid" failed (13: Permission denied)`}

	// The path is on a volume: that is KD137's, with fsGroup as the fix.
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "run", MountPath: "/run"}}
	p.Spec.Volumes = []kube.Volume{{Name: "run", EmptyDir: &kube.EmptyDirVolumeSource{}}}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD137", "ReplicaSet shop/web-rs")

	// Nothing says the container is not root: the denial has another cause.
	p.Spec.Containers[0].VolumeMounts, p.Spec.Volumes, p.Spec.Containers[0].SecurityContext = nil, nil, nil
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD224" {
		t.Errorf("no user set: %s", f.Cause)
	}
	root := int64(0)
	p.Spec.SecurityContext = &kube.PodSecurityContext{RunAsUser: &root}
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD224" {
		t.Errorf("root: %s", f.Cause)
	}
}

func TestServicesPodsRefuseThePortItTargets(t *testing.T) {
	s := snap()
	web := pod("web-7d4f8-abcde", "web")
	web.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "http", ContainerPort: 80}}
	web.Spec.Containers[0].Command = []string{"sh", "-c", "exec httpd -f -p 8080 -h /www"}
	client := pod("client-5c7d9-qwert", "client")
	client.Metadata.Labels = map[string]string{"app": "client"}
	client.Spec.Containers[0].Ports = nil
	crashed(&client, 1, "Error", 4)
	s.Pods = []kube.Pod{client, web}
	svc := service("web", map[string]string{"app": "web"}, port(80))
	svc.Spec.ClusterIP = "10.96.20.5"
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Logs = []snapshot.Log{{Pod: client.Ref(), Container: "web", Previous: true,
		Lines: []string{"Connecting to web (10.96.20.5:80)", "wget: can't connect to remote host (10.96.20.5): Connection refused"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD225", "ReplicaSet shop/client-rs", "Service web refuses its connection on port 80, though the Service has ready pods",
		"forwards port 80 to the pods' port 80", "nothing in pod web-7d4f8-abcde listens there", "no readiness probe checks that port", "names port 8080")
	if !strings.HasPrefix(f.Fix, "Set Service web's targetPort to 8080, the port the app listens on by its command or env") {
		t.Errorf("fix %q", f.Fix)
	}

	// No port in the command to point at.
	web.Spec.Containers[0].Command = []string{"/server"}
	s.Pods = []kube.Pod{client, web}
	f = only(t, Diagnose(s))
	expect(t, f, "KD225", "ReplicaSet shop/client-rs")
	if strings.Contains(f.Cause, "likely where the app listens") || !strings.HasPrefix(f.Fix, "Set Service web's targetPort to the port the app listens on (") {
		t.Errorf("cause %q fix %q", f.Cause, f.Fix)
	}

	// A readiness probe on the target port passes, so something does listen there: not this rule.
	web.Spec.Containers[0].ReadinessProbe = &kube.Probe{TCPSocket: &kube.TCPSocketAction{Port: port(80)}}
	s.Pods = []kube.Pod{client, web}
	if f := only(t, Diagnose(s)); f.Rule == "KD225" {
		t.Errorf("probed port: %s", f.Cause)
	}

	// The client was refused seconds after the server's container started: it may only have been early.
	web.Spec.Containers[0].ReadinessProbe = nil
	client.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt = t0.Add(5 * time.Second)
	s.Pods = []kube.Pod{client, web}
	if f := only(t, Diagnose(s)); f.Rule == "KD225" {
		t.Errorf("early client: %s", f.Cause)
	}
	client.Status.ContainerStatuses[0].LastTerminationState.Terminated.FinishedAt = t0.Add(5 * time.Minute)
	s.Pods = []kube.Pod{client, web}
	expect(t, only(t, Diagnose(s)), "KD225", "ReplicaSet shop/client-rs")

	// No ready pods: the Service refuses for that reason (KD124).
	web.Spec.Containers[0].ReadinessProbe = nil
	notReady(&web)
	s.Pods = []kube.Pod{client, web}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 0)}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD225" {
			t.Errorf("no ready pods: %s", f.Cause)
		}
	}
}

func TestNoPersistentVolumeFitsTheClaim(t *testing.T) {
	build := func() *snapshot.Snapshot {
		s := snap()
		var pvc kube.PersistentVolumeClaim
		pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop", UID: "new-uid"}
		pvc.Spec.StorageClassName = strp("manual")
		pvc.Spec.AccessModes = []string{"ReadWriteOnce"}
		pvc.Spec.Resources.Requests = map[string]string{"storage": "5Gi"}
		pvc.Status.Phase = "Pending"
		s.PVCs = []kube.PersistentVolumeClaim{pvc}
		var pv kube.PersistentVolume
		pv.Metadata.Name = "data-pv"
		pv.Spec.StorageClassName = "manual"
		pv.Spec.Capacity = map[string]string{"storage": "1Gi"}
		pv.Spec.AccessModes = []string{"ReadWriteOnce"}
		pv.Status.Phase = "Available"
		s.PVs = []kube.PersistentVolume{pv}
		s.Events = []kube.Event{event("PersistentVolumeClaim", "data", "ProvisioningFailed", `storageclass.storage.k8s.io "manual" not found`, time.Minute)}
		return s
	}

	// Too small. The controller's own event blames a StorageClass that static volumes do not need.
	s := build()
	f := only(t, Diagnose(s))
	expect(t, f, "KD250", "PersistentVolumeClaim shop/data", `it asks for 5Gi; ReadWriteOnce; storageClassName "manual", a name no StorageClass has`,
		"only an existing PersistentVolume can satisfy it, and none fits", "the nearest, data-pv, holds 1Gi, less than the 5Gi the claim asks for")

	// Other access modes, and a pod that waits for the claim is listed under it.
	s = build()
	s.PVs[0].Spec.Capacity["storage"] = "5Gi"
	s.PVCs[0].Spec.AccessModes = []string{"ReadWriteMany"}
	expect(t, only(t, Diagnose(s)), "KD250", "PersistentVolumeClaim shop/data", "data-pv, offers access mode ReadWriteOnce, not the ReadWriteMany the claim asks for")

	// Volume mode and selector.
	s = build()
	s.PVs[0].Spec.Capacity["storage"] = "5Gi"
	s.PVs[0].Spec.VolumeMode = "Block"
	expect(t, only(t, Diagnose(s)), "KD250", "PersistentVolumeClaim shop/data", "has volumeMode Block, and the claim asks for Filesystem")
	s = build()
	s.PVs[0].Spec.Capacity["storage"] = "5Gi"
	s.PVs[0].Metadata.Labels = map[string]string{"tier": "slow"}
	s.PVCs[0].Spec.Selector = &kube.LabelSelector{MatchLabels: map[string]string{"tier": "fast"}}
	expect(t, only(t, Diagnose(s)), "KD250", "PersistentVolumeClaim shop/data", "has labels tier=slow, which the claim's selector (tier=fast) does not match")

	// Two volumes, both wrong: the one with fewer reasons against it is named, the other counted.
	s = build()
	other := s.PVs[0]
	other.Metadata.Name = "old-pv"
	other.Spec.Capacity = map[string]string{"storage": "1Gi"}
	other.Spec.AccessModes = []string{"ReadOnlyMany"}
	s.PVs = append(s.PVs, other)
	expect(t, only(t, Diagnose(s)), "KD250", "PersistentVolumeClaim shop/data", "the nearest, data-pv, holds 1Gi", "the other volume of class manual, old-pv, does not fit either")

	// No class at all: "" turns provisioning off, and there is no volume without a class.
	s = build()
	s.PVCs[0].Spec.StorageClassName = strp("")
	s.Events = []kube.Event{event("PersistentVolumeClaim", "data", "FailedBinding", "no persistent volumes available for this claim and no storage class is set", time.Minute)}
	f = only(t, Diagnose(s))
	expect(t, f, "KD250", "PersistentVolumeClaim shop/data", `storageClassName "", which turns dynamic provisioning off`, "there is no PersistentVolume without a class")
	if !strings.Contains(f.Fix, "leave storageClassName out to use the default class") {
		t.Errorf("fix %q", f.Fix)
	}

	// A class that a StorageClass does provision is not static: the provisioner's event is the finding.
	s = build()
	s.StorageClasses = []kube.StorageClass{{Metadata: kube.ObjectMeta{Name: "manual"}, Provisioner: "example.com/nfs"}}
	if f := only(t, Diagnose(s)); f.Rule == "KD250" {
		t.Errorf("dynamic class: %s", f.Cause)
	}
}

func TestPersistentVolumeIsReleased(t *testing.T) {
	s := snap()
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop", UID: "new-uid"}
	pvc.Spec.StorageClassName = strp("")
	pvc.Spec.AccessModes = []string{"ReadWriteOnce"}
	pvc.Spec.Resources.Requests = map[string]string{"storage": "5Gi"}
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	var pv kube.PersistentVolume
	pv.Metadata.Name = "data-pv"
	pv.Spec.Capacity = map[string]string{"storage": "5Gi"}
	pv.Spec.AccessModes = []string{"ReadWriteOnce"}
	pv.Spec.PersistentVolumeReclaimPolicy = "Retain"
	pv.Spec.ClaimRef = &kube.ClaimReference{Namespace: "shop", Name: "old-data", UID: "old-uid"}
	pv.Status.Phase = "Released"
	s.PVs = []kube.PersistentVolume{pv}
	p := pod("db", "")
	p.Spec.NodeName = ""
	p.Status.Phase = "Pending"
	p.Status.ContainerStatuses = nil
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable", Message: "0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims."}}
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD251", "PersistentVolumeClaim shop/data", "PersistentVolume data-pv fits it, but is Released", "reference to claim shop/old-data, which was deleted", "reclaim policy Retain")
	if !strings.Contains(f.Fix, `kubectl patch pv data-pv --type=json -p '[{"op":"remove","path":"/spec/claimRef"}]'`) {
		t.Errorf("fix %q", f.Fix)
	}
	if len(f.Affects) != 1 || f.Affects[0].Name != "db" {
		t.Errorf("the waiting pod should be listed under the claim: %v", f.Affects)
	}

	// Released and too small as well: it does not fit, so clearing the reference would not help.
	s.PVs[0].Spec.Capacity["storage"] = "1Gi"
	expect(t, only(t, Diagnose(s)), "KD250", "PersistentVolumeClaim shop/data", "holds 1Gi, less than the 5Gi", "is Released")
}

func TestResourceQuotaRequiresALimitThePodsDoNotSet(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 0)
	for i := range s.Workloads {
		s.Workloads[i].Status.Replicas = 0
	}
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate",
		`Error creating: pods "web-rs-x7k2p" is forbidden: failed quota: compute: must specify limits.memory for: web`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD275", "Deployment shop/web", "ResourceQuota compute puts a quota on limits.memory, which", "container web sets no resources.limits.memory", "The quota is not used up")
	if !strings.HasPrefix(f.Fix, "Set resources.limits.memory on the containers named, or add a LimitRange") {
		t.Errorf("fix %q", f.Fix)
	}

	// Two resources, one of them missing from two containers; plain cpu counts requests.
	s.Events[0].Message = `Error creating: pods "web-rs-x7k2p" is forbidden: failed quota: compute: must specify cpu for: proxy,web; limits.memory for: web`
	f = only(t, Diagnose(s))
	expect(t, f, "KD275", "Deployment shop/web", "puts a quota on cpu and limits.memory", "containers proxy, web set no resources.requests.cpu; container web sets no resources.limits.memory")

	// A quota that is used up is still KD170.
	s.Events[0].Message = `Error creating: pods "web-rs-x7k2p" is forbidden: exceeded quota: compute, requested: limits.memory=1Gi, used: limits.memory=4Gi, limited: limits.memory=4Gi`
	expect(t, only(t, Diagnose(s)), "KD170", "Deployment shop/web", "is used up")
}

func TestNetworkPolicyNamespaceSelectorMatchesNoNamespace(t *testing.T) {
	namespaces := func(names ...string) []kube.Namespace {
		var out []kube.Namespace
		for _, n := range names {
			out = append(out, kube.Namespace{Metadata: kube.ObjectMeta{Name: n, Labels: map[string]string{"kubernetes.io/metadata.name": n}}})
		}
		return out
	}
	build := func() *snapshot.Snapshot {
		s := snap()
		web := pod("web-7d4f8-abcde", "web")
		client := pod("client-5c7d9-qwert", "client")
		client.Metadata.Labels = map[string]string{"app": "client"}
		crashed(&client, 1, "Error", 3)
		s.Pods = []kube.Pod{client, web}
		svc := service("web", map[string]string{"app": "web"}, port(8080))
		svc.Spec.ClusterIP = "10.96.40.12"
		s.Services = []kube.Service{svc}
		s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
		s.Logs = []snapshot.Log{{Pod: client.Ref(), Container: "web", Previous: true, Lines: []string{"Connecting to web (10.96.40.12:80)", "wget: download timed out"}}}
		np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "web-ingress", Namespace: "shop"}}
		np.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
		np.Spec.Ingress = []kube.NetworkPolicyRule{{From: []kube.NetworkPolicyPeer{{NamespaceSelector: &kube.LabelSelector{MatchLabels: map[string]string{"name": "shop"}}}}}}
		s.NetworkPolicies = []kube.NetworkPolicy{np}
		s.NamespaceObjects = namespaces("default", "kube-system", "shop")
		return s
	}

	// The client's connection is dropped, and the selector that matches no namespace is why: one finding, on the
	// client, naming the policy; the policy's own finding is not repeated.
	s := build()
	f := only(t, Diagnose(s))
	expect(t, f, "KD274", "ReplicaSet shop/client-rs", "connection to Service web times out", "NetworkPolicy web-ingress allows ingress on port 8080 only from namespaces labelled name=shop",
		"no namespace of the cluster has those labels", "namespace shop exists, and its labels are kubernetes.io/metadata.name=shop")
	if !strings.Contains(f.Fix, "namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: shop}}") || !strings.Contains(f.Fix, "kubectl label namespace shop name=shop") {
		t.Errorf("fix %q", f.Fix)
	}

	// Nothing is failing: the policy's finding stands alone, as a warning.
	s = build()
	s.Pods[0] = pod("client-5c7d9-qwert", "client")
	s.Pods[0].Metadata.Labels = map[string]string{"app": "client"}
	s.Logs = nil
	f = only(t, Diagnose(s))
	expect(t, f, "KD274", "NetworkPolicy shop/web-ingress", "has an ingress rule that allows traffic from namespaces labelled name=shop", "so the rule allows nothing")
	if f.Severity != Warning {
		t.Errorf("severity %v", f.Severity)
	}

	// A label that names no namespace either: no namespace to point at.
	s = build()
	s.NetworkPolicies[0].Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels = map[string]string{"team": "frontend"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD274", "ReplicaSet shop/client-rs", "namespaces labelled team=frontend")
	if strings.Contains(f.Cause, "exists, and its labels") || !strings.Contains(f.Fix, "kubectl get namespaces --show-labels") {
		t.Errorf("cause %q fix %q", f.Cause, f.Fix)
	}

	// The namespace has the label: the selector matches, and the connection has another cause.
	s = build()
	s.NamespaceObjects[2].Metadata.Labels["name"] = "shop"
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD274" || f.Rule == "KD127" {
			t.Errorf("labelled namespace: %s %s", f.Rule, f.Cause)
		}
	}

	// The selector matches another namespace only: the rule is alive, and it does not admit this namespace's client.
	s = build()
	s.NamespaceObjects[0].Metadata.Labels["name"] = "shop"
	expect(t, only(t, Diagnose(s)), "KD127", "ReplicaSet shop/client-rs", "NetworkPolicy web-ingress allows no ingress traffic")

	// A snapshot without the cluster's namespaces (recorded before they were read, or not permitted): no claim.
	s = build()
	s.NamespaceObjects = nil
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD274" || f.Rule == "KD127" {
			t.Errorf("namespaces unread: %s %s", f.Rule, f.Cause)
		}
	}
}

func rbacSnapshot() (*snapshot.Snapshot, *kube.Pod) {
	s := snap()
	p := pod("worker-5c7d9-qwert", "worker")
	p.Metadata.Labels = map[string]string{"app": "worker"}
	p.Spec.ServiceAccountName = "app"
	p.Spec.Containers[0].Command = []string{"sh", "-c", "wget -O - https://kubernetes.default.svc/api/v1/namespaces/shop/configmaps"}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.ServiceAccounts = []kube.ServiceAccount{{Metadata: kube.ObjectMeta{Name: "app", Namespace: "shop"}}, {Metadata: kube.ObjectMeta{Name: "default", Namespace: "shop"}}}
	s.Roles = []kube.Role{{Metadata: kube.ObjectMeta{Name: "configmap-reader", Namespace: "shop"}}}
	var b kube.RoleBinding
	b.Metadata = kube.ObjectMeta{Name: "read-config", Namespace: "shop"}
	b.RoleRef.Kind, b.RoleRef.Name = "Role", "configmap-reader"
	b.Subjects = []kube.Subject{{Kind: "ServiceAccount", Name: "app", Namespace: "shop"}}
	s.RoleBindings = []kube.RoleBinding{b}
	s.ClusterRoles = []string{"admin", "edit", "view"}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true,
		Lines: []string{"Connecting to kubernetes.default.svc (10.96.0.1:443)", "wget: server returned error: HTTP/1.1 403 Forbidden"}}}
	return s, &s.Pods[0]
}

func TestRoleBindingGrantsARoleThatDoesNotExist(t *testing.T) {
	// The pod's ServiceAccount is refused, and its binding names a Role the namespace does not have.
	s, _ := rbacSnapshot()
	s.RoleBindings[0].RoleRef.Name = "config-reader"
	f := only(t, Diagnose(s))
	expect(t, f, "KD227", "ReplicaSet shop/worker-rs", "the API server refuses its ServiceAccount app", "RoleBinding read-config grants Role config-reader to ServiceAccount app",
		"there is no Role config-reader in namespace shop, so the binding grants nothing", "the namespace's Roles are configmap-reader", "403 Forbidden")
	if !strings.Contains(f.Fix, "a binding's roleRef cannot be changed, so delete RoleBinding read-config and create it again") {
		t.Errorf("fix %q", f.Fix)
	}

	// The API server's own sentence, as client-go prints it.
	s.Logs[0].Lines = []string{`configmaps is forbidden: User "system:serviceaccount:shop:app" cannot list resource "configmaps" in API group "" in the namespace "shop"`}
	expect(t, only(t, Diagnose(s)), "KD227", "ReplicaSet shop/worker-rs", "RoleBinding read-config grants Role config-reader")

	// Nothing fails yet: the binding is reported on its own, as a warning.
	s, p := rbacSnapshot()
	s.RoleBindings[0].RoleRef.Name = "config-reader"
	*p = pod("worker-5c7d9-qwert", "worker")
	s.Logs = nil
	f = only(t, Diagnose(s))
	expect(t, f, "KD227", "RoleBinding shop/read-config", "there is no Role config-reader in namespace shop")
	if f.Severity != Warning {
		t.Errorf("severity %v", f.Severity)
	}

	// A ClusterRole that does not exist, and one that does.
	s.RoleBindings[0].RoleRef.Kind, s.RoleBindings[0].RoleRef.Name = "ClusterRole", "viewer"
	expect(t, only(t, Diagnose(s)), "KD227", "RoleBinding shop/read-config", "there is no ClusterRole viewer in the cluster")
	s.RoleBindings[0].RoleRef.Name = "view"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	// The role exists as the other kind: the roleRef's kind is wrong.
	s.ClusterRoles = append(s.ClusterRoles, "config-reader")
	s.RoleBindings[0].RoleRef.Kind, s.RoleBindings[0].RoleRef.Name = "Role", "config-reader"
	f = only(t, Diagnose(s))
	expect(t, f, "KD227", "RoleBinding shop/read-config", "there is a ClusterRole config-reader, so the roleRef's kind is wrong")
	if !strings.Contains(f.Fix, "with roleRef kind ClusterRole") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.RoleBindings[0].RoleRef.Kind, s.RoleBindings[0].RoleRef.Name = "ClusterRole", s.Roles[0].Metadata.Name
	expect(t, only(t, Diagnose(s)), "KD227", "RoleBinding shop/read-config", "there is a Role "+s.Roles[0].Metadata.Name+", so the roleRef's kind is wrong")

	// The binding is sound: a refusal is then a missing permission, which KD126 names from the API server's sentence.
	s, _ = rbacSnapshot()
	s.Logs[0].Lines = []string{`secrets is forbidden: User "system:serviceaccount:shop:app" cannot list resource "secrets" in API group "" in the namespace "shop"`}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs", "it may not list secrets")

	// Roles could not be read: no claim that one is missing.
	s, _ = rbacSnapshot()
	s.RoleBindings[0].RoleRef.Name = "config-reader"
	s.Roles = nil
	s.Gaps = []snapshot.Gap{{Resource: "roles.rbac.authorization.k8s.io", Namespace: "shop", Error: "forbidden"}}
	if f := only(t, Diagnose(s)); f.Rule == "KD227" {
		t.Errorf("roles unread: %s", f.Cause)
	}
}

func TestRoleBindingNamesAServiceAccountThatDoesNotExist(t *testing.T) {
	// The pod runs as app, the binding says apps, and the API server refuses app.
	s, _ := rbacSnapshot()
	s.RoleBindings[0].Subjects[0].Name = "apps"
	f := only(t, Diagnose(s))
	expect(t, f, "KD228", "ReplicaSet shop/worker-rs", "refuses its ServiceAccount app, which no RoleBinding of namespace shop names",
		"RoleBinding read-config grants Role configmap-reader to ServiceAccount apps", "there is no ServiceAccount apps")
	if !strings.HasPrefix(f.Fix, "Set the subject of RoleBinding read-config to ServiceAccount app (a binding's subjects can be edited)") {
		t.Errorf("fix %q", f.Fix)
	}

	// Nothing fails yet: a warning on the binding, which says who it was most likely meant for.
	s, p := rbacSnapshot()
	s.RoleBindings[0].Subjects[0].Name = "apps"
	*p = pod("worker-5c7d9-qwert", "worker")
	p.Spec.ServiceAccountName = "app"
	s.Logs = nil
	f = only(t, Diagnose(s))
	expect(t, f, "KD228", "RoleBinding shop/read-config", "there is no ServiceAccount apps in namespace shop, so nothing receives the permission",
		"pods here run as ServiceAccount app, which no RoleBinding of the namespace names")
	if f.Severity != Warning {
		t.Errorf("severity %v", f.Severity)
	}

	// A ServiceAccount of another namespace is not ours to judge, and users and groups are not objects at all.
	s.RoleBindings[0].Subjects = []kube.Subject{{Kind: "ServiceAccount", Name: "ci", Namespace: "build"}, {Kind: "User", Name: "priya"}, {Kind: "Group", Name: "devs"}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestNetworkPolicyAllowsTheServicePortNotThePodsPort(t *testing.T) {
	s := snap()
	web := pod("web-7d4f8-abcde", "web")
	client := pod("client-5c7d9-qwert", "client")
	client.Metadata.Labels = map[string]string{"app": "client"}
	crashed(&client, 1, "Error", 3)
	s.Pods = []kube.Pod{client, web}
	svc := service("web", map[string]string{"app": "web"}, port(8080))
	svc.Spec.ClusterIP = "10.96.40.12"
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Logs = []snapshot.Log{{Pod: client.Ref(), Container: "web", Previous: true, Lines: []string{"Connecting to web (10.96.40.12:80)", "wget: download timed out"}}}
	eighty, dns := kube.IntOrString{Int: 80}, kube.IntOrString{Int: 53}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "client-egress", Namespace: "shop"}}
	np.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
	np.Spec.PolicyTypes = []string{"Egress"}
	np.Spec.Egress = []kube.NetworkPolicyRule{
		{Ports: []kube.NetworkPolicyPort{{Port: &dns}}},
		{To: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}, Ports: []kube.NetworkPolicyPort{{Port: &eighty}}},
	}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	f := only(t, Diagnose(s))
	expect(t, f, "KD127", "ReplicaSet shop/client-rs", "NetworkPolicy client-egress allows egress between them on port 80, the Service's port",
		"checked after the Service has forwarded the connection, against the pods' own port 8080 (the targetPort), which no rule allows")
	if !strings.HasPrefix(f.Fix, "In NetworkPolicy client-egress, allow port 8080, the pods' port, in place of 80") {
		t.Errorf("fix %q", f.Fix)
	}

	// The same mistake on the servers' side: ingress allowed on the Service's port.
	in := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "web-ingress", Namespace: "shop"}}
	in.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	in.Spec.Ingress = []kube.NetworkPolicyRule{{From: []kube.NetworkPolicyPeer{{PodSelector: &kube.LabelSelector{MatchLabels: map[string]string{"app": "client"}}}}, Ports: []kube.NetworkPolicyPort{{Port: &eighty}}}}
	s.NetworkPolicies = []kube.NetworkPolicy{in}
	expect(t, only(t, Diagnose(s)), "KD127", "ReplicaSet shop/client-rs", "NetworkPolicy web-ingress allows ingress between them on port 80, the Service's port")

	// The rule for port 80 is for other pods: the client is simply not allowed, as before.
	s.NetworkPolicies[0].Spec.Ingress[0].From[0].PodSelector.MatchLabels["app"] = "api"
	f = only(t, Diagnose(s))
	expect(t, f, "KD127", "ReplicaSet shop/client-rs", "NetworkPolicy web-ingress allows no ingress traffic between them on port 8080")
}

func TestProbeCommandIsOneString(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{Exec: &kube.ExecAction{Command: []string{"cat /tmp/healthy"}}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web", "Unhealthy",
		`Liveness probe errored and resulted in unknown state: rpc error: code = Unknown desc = failed to exec in container: failed to start exec "8f1c": OCI runtime exec failed: exec failed: unable to start container process: exec: "cat /tmp/healthy": stat cat /tmp/healthy: no such file or directory`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD129", "Pod shop/web", `liveness probe has the command line "cat /tmp/healthy" as one item`, "a program with that whole name, spaces included", "checks nothing")
	if !strings.HasPrefix(f.Fix, `Write each word of the probe's command as its own item: command: ["cat", "/tmp/healthy"].`) || !strings.Contains(f.Fix, `["sh", "-c", "cat /tmp/healthy"]`) {
		t.Errorf("fix %q", f.Fix)
	}

	// The same slip in a readiness probe keeps the container out of its Service.
	p.Spec.Containers[0].LivenessProbe = nil
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{Exec: &kube.ExecAction{Command: []string{"cat /tmp/healthy"}}}
	notReady(&p)
	s.Pods = []kube.Pod{p}
	s.Events[0].Message = strings.Replace(s.Events[0].Message, "Liveness probe errored and resulted in unknown state", "Readiness probe errored and resulted in unknown state", 1)
	expect(t, only(t, Diagnose(s)), "KD120", "Pod shop/web", `readiness probe has the command line "cat /tmp/healthy" as one item`, "gets no traffic")
}

func TestJobStoppedByItsActiveDeadline(t *testing.T) {
	s := snap()
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "export", Namespace: "shop"}
	limit, completions := int64(30), int32(1)
	j.Spec.ActiveDeadlineSeconds, j.Spec.Completions = &limit, &completions
	j.Status.Conditions = []kube.Condition{{Type: "Failed", Status: "True", Reason: "DeadlineExceeded", Message: "Job was active longer than specified deadline"}}
	s.Jobs = []kube.Job{j}
	f := only(t, Diagnose(s))
	expect(t, f, "KD180", "Job shop/export", "stopped by its own activeDeadlineSeconds (30)", "still running 30s after it started", "0 of 1 completions had succeeded", "Nothing crashed")
	if !strings.Contains(f.Fix, "recreate the Job with a higher activeDeadlineSeconds") || !strings.Contains(f.Fix, "kubectl logs -f job/export") {
		t.Errorf("fix %q", f.Fix)
	}
}

func TestClaimHasLostItsPersistentVolume(t *testing.T) {
	s := snap()
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop", Annotations: map[string]string{"pv.kubernetes.io/bind-completed": "yes"}}
	pvc.Spec.VolumeName = "pvc-7f3a"
	pvc.Status.Phase = "Lost"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	s.Events = []kube.Event{event("PersistentVolumeClaim", "data", "ClaimLost", "Bound claim has lost its PersistentVolume. Data on the volume is lost!", time.Minute)}
	p := pod("db", "")
	p.Spec.NodeName = ""
	p.Status.Phase = "Pending"
	p.Status.ContainerStatuses = nil
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: `0/1 nodes are available: persistentvolumeclaim "data" bound to non-existent persistentvolume "pvc-7f3a". preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.`}}
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD252", "PersistentVolumeClaim shop/data", "is Lost: it is marked as bound to PersistentVolume pvc-7f3a, and there is no such PersistentVolume",
		"The volume was deleted under the claim, or the claim was created from a copy of a bound claim")
	if !strings.HasPrefix(f.Fix, "A Lost claim never binds again.") || !strings.Contains(f.Fix, "without spec.volumeName and without the pv.kubernetes.io annotations") {
		t.Errorf("fix %q", f.Fix)
	}
	if len(f.Affects) != 1 || f.Affects[0].Name != "db" {
		t.Errorf("the pod that mounts the claim should be listed under it: %v", f.Affects)
	}

	// The volume is there, and the controller still calls the binding broken (two claims on one volume).
	var pv kube.PersistentVolume
	pv.Metadata.Name = "pvc-7f3a"
	s.PVs = []kube.PersistentVolume{pv}
	s.Events[0].Reason, s.Events[0].Message = "ClaimMisbound", "Two claims are bound to the same volume, this one is bound incorrectly"
	f = only(t, Diagnose(s))
	expect(t, f, "KD252", "PersistentVolumeClaim shop/data", "the PersistentVolume controller found that binding broken")
	if len(f.Evidence) < 2 || !strings.Contains(f.Evidence[1].Detail, "Two claims are bound to the same volume") {
		t.Errorf("evidence %+v", f.Evidence)
	}
}

func TestLimitRangeDefaultLimitIsBelowTheRequest(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 0)
	for i := range s.Workloads {
		s.Workloads[i].Status.Replicas = 0
		s.Workloads[i].Spec.Template.Spec.Containers = []kube.Container{{Name: "web", Resources: kube.Resources{Requests: map[string]string{"memory": "256Mi"}}}}
	}
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate",
		`Error creating: Pod "web-rs-x7k2p" is invalid: spec.containers[0].resources.requests: Invalid value: "256Mi": must be less than or equal to memory limit of 128Mi`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD276", "Deployment shop/web", "container web requests 256Mi of memory and sets no memory limit", "the namespace's LimitRange gave it its default limit, 128Mi")
	if !strings.HasPrefix(f.Fix, "Set the memory limit of container web in the pod template, at or above its request of 256Mi") {
		t.Errorf("fix %q", f.Fix)
	}
}

// TestClaimFindingOutlastsTheTenMinuteMarks holds a pending claim's finding steady once the cluster is more than ten
// minutes into the fault, as the fault suite recorded it: the scheduler stops saying which claim it waits for, and
// the Deployment passes its progress deadline. Neither is a second cause.
func TestClaimFindingOutlastsTheTenMinuteMarks(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	s.Workloads[0].Status.Conditions = []kube.Condition{{Type: "Progressing", Status: "False", Reason: "ProgressDeadlineExceeded", Message: `ReplicaSet "web-rs" has timed out progressing.`}}
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "shared", Namespace: "shop"}
	pvc.Spec.AccessModes = []string{"ReadWriteMany"}
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	s.StorageClasses = []kube.StorageClass{{Metadata: kube.ObjectMeta{Name: "standard", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}},
		Provisioner: "rancher.io/local-path", VolumeBindingMode: "WaitForFirstConsumer"}}
	s.Events = []kube.Event{event("PersistentVolumeClaim", "shared", "ProvisioningFailed",
		`failed to provision volume with StorageClass "standard": NodePath only supports ReadWriteOnce and ReadWriteOncePod (1.22+) access modes`, time.Minute)}
	p := pod("web-rs-a", "web")
	p.Spec.NodeName = ""
	p.Status.Phase = "Pending"
	p.Status.ContainerStatuses = nil
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "SchedulerError",
		Message: `running PreBind plugin "VolumeBinding": binding volumes: context deadline exceeded`}}
	p.Spec.Volumes = []kube.Volume{{Name: "shared", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "shared"}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD156", "PersistentVolumeClaim shop/shared", "asks for access mode ReadWriteMany")
	if len(f.Affects) != 1 || f.Affects[0].Name != "web-rs-a" {
		t.Errorf("the waiting pod should be listed under the claim: %v", f.Affects)
	}
}

func TestCommandUsesAShellOperatorWithNoShell(t *testing.T) {
	s := snap()
	p := pod("worker-5c7d9-qwert", "worker")
	c := &p.Spec.Containers[0]
	c.Command = []string{"echo", "starting", "&&", "sleep", "3600"}
	crashed(&p, 0, "Completed", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"starting && sleep 3600"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD226", "ReplicaSet shop/worker-rs", "runs echo starting && sleep 3600 with no shell", "&& is a shell operator (run the next command if the first succeeds)",
		"one more argument to echo", `its log shows the operator as text: "starting && sleep 3600"`)
	if !strings.HasPrefix(f.Fix, `Run the line through a shell: command: ["sh", "-c", "echo starting && sleep 3600"]`) {
		t.Errorf("fix %q", f.Fix)
	}

	// A pipe in args, and a log that does not show it.
	c.Command, c.Args = []string{"/app/export"}, []string{"--all", "|", "gzip"}
	s.Pods = []kube.Pod{p}
	s.Logs[0].Lines = []string{"export: unexpected argument"}
	f = only(t, Diagnose(s))
	expect(t, f, "KD226", "ReplicaSet shop/worker-rs", "| is a shell operator (pipe the output into the next command)", "one more argument to /app/export")
	if strings.Contains(f.Cause, "its log shows") {
		t.Errorf("cause %q", f.Cause)
	}

	// The program's own syntax: the ";" that ends find's -exec, and the ">" that test compares with.
	for _, cmd := range [][]string{{"find", "/data", "-name", "*.tmp", "-exec", "rm", "{}", ";"}, {"/usr/bin/test", "5", ">", "3"}} {
		c.Command, c.Args = cmd, nil
		s.Pods = []kube.Pod{p}
		if f := only(t, Diagnose(s)); f.Rule == "KD226" {
			t.Errorf("%v: %s", cmd, f.Cause)
		}
	}

	// A shell does run the line: the operator works, and the crash has another cause.
	c.Command, c.Args = []string{"sh", "-c", "echo starting && exit 3"}, nil
	s.Pods = []kube.Pod{p}
	if f := only(t, Diagnose(s)); f.Rule == "KD226" {
		t.Errorf("with a shell: %s", f.Cause)
	}
}

func TestFlagsAreInCommand(t *testing.T) {
	s := snap()
	p := pod("web-5c7d9-qwert", "web")
	p.Spec.Containers[0].Command = []string{"--port=8080", "--verbose"}
	waiting(&p, "RunContainerError", `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: exec: "--port=8080": executable file not found in $PATH`)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD229", "ReplicaSet shop/web-rs", `command is ["--port=8080", "--verbose"]`, "command replaces the image's ENTRYPOINT", `a program named "--port=8080"`)
	if !strings.HasPrefix(f.Fix, `Move the flags to args and leave command out: args: ["--port=8080", "--verbose"].`) {
		t.Errorf("fix %q", f.Fix)
	}

	// A program that is simply not in the image is still KD114.
	p.Spec.Containers[0].Command = []string{"webserver", "--port=8080"}
	waiting(&p, "RunContainerError", `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: exec: "webserver": executable file not found in $PATH`)
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD114", "ReplicaSet shop/web-rs")
}

func TestAdmissionWebhookCannotBeReached(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 0)
	for i := range s.Workloads {
		s.Workloads[i].Status.Replicas = 0
	}
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate",
		`Error creating: Internal error occurred: failed calling webhook "pods.policy.example.com": failed to call webhook: Post "https://policy.shop.svc:443/validate?timeout=5s": service "policy" not found`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD277", "Deployment shop/web", "must ask admission webhook pods.policy.example.com", "cannot: Service policy in namespace shop does not exist", "The webhook rejected nothing")
	if !strings.HasPrefix(f.Fix, "Bring the webhook back: Service policy in namespace shop and the pods behind it.") || !strings.Contains(f.Fix, "failurePolicy: Ignore") {
		t.Errorf("fix %q", f.Fix)
	}

	for msg, want := range map[string]string{
		`Post "https://policy.shop.svc:443/validate?timeout=5s": no endpoints available for service "policy"`:                                      "Service policy in namespace shop has no ready pods",
		`Post "https://policy.shop.svc:443/validate?timeout=5s": dial tcp 10.96.4.7:443: connect: connection refused`:                              "Service policy in namespace shop refuses the connection",
		`Post "https://policy.shop.svc:443/validate?timeout=5s": context deadline exceeded`:                                                        "Service policy in namespace shop does not answer in time",
		`Post "https://policy.shop.svc:443/validate?timeout=5s": tls: failed to verify certificate: x509: certificate signed by unknown authority`: "does not accept the certificate of Service policy in namespace shop",
		`Post "https://hooks.example.com/validate?timeout=5s": EOF`:                                                                                `Post "https://hooks.example.com/validate?timeout=5s": EOF`,
	} {
		s.Events[0].Message = `Error creating: Internal error occurred: failed calling webhook "pods.policy.example.com": failed to call webhook: ` + msg
		f := only(t, Diagnose(s))
		if f.Rule != "KD277" || !strings.Contains(f.Cause, want) {
			t.Errorf("%s:\n got %s %s", msg, f.Rule, f.Cause)
		}
	}

	// A webhook that answers and says no is a policy, not an outage: KD173.
	s.Events[0].Message = `Error creating: admission webhook "pods.policy.example.com" denied the request: images must come from registry.example.com`
	expect(t, only(t, Diagnose(s)), "KD173", "Deployment shop/web")
}

func TestValidatingAdmissionPolicyRejectsThePods(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 0)
	for i := range s.Workloads {
		s.Workloads[i].Status.Replicas = 0
	}
	s.Events = []kube.Event{event("ReplicaSet", "web-rs", "FailedCreate",
		`Error creating: pods "web-rs-x2k4p" is forbidden: ValidatingAdmissionPolicy 'require-team-label' with binding 'require-team-label-everywhere' denied request: every pod needs a team label`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD279", "Deployment shop/web", "ValidatingAdmissionPolicy require-team-label, through binding require-team-label-everywhere, denies them: every pod needs a team label")
	if len(f.Evidence) != 3 || !strings.Contains(f.Fix, "narrow binding require-team-label-everywhere's matchResources") {
		t.Errorf("evidence %+v fix %s", f.Evidence, f.Fix)
	}
	// A policy without a message says which expression failed.
	s.Events[0].Message = `Error creating: pods "web-rs-x2k4p" is forbidden: ValidatingAdmissionPolicy 'require-team-label' with binding 'b' denied request: failed expression: has(object.metadata.labels.team)`
	expect(t, only(t, Diagnose(s)), "KD279", "Deployment shop/web", "failed expression: has(object.metadata.labels.team)")
}

// TestContainerCaughtJustAfterFinishing is a Deployment's container whose process ends with code 0 each time, as the
// fault suite recorded it between an exit and the kubelet's back-off: state terminated, reason Completed, five
// restarts. It used to yield no finding at all.
func TestContainerCaughtJustAfterFinishing(t *testing.T) {
	s := snap()
	p := pod("worker-5c7d9-qwert", "worker")
	p.Spec.Containers[0].Command = []string{"/app/migrate"}
	notReady(&p)
	done := &kube.ContainerStateTerminated{ExitCode: 0, Reason: "Completed"}
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Terminated: done}
	p.Status.ContainerStatuses[0].LastTerminationState = kube.ContainerState{Terminated: done}
	p.Status.ContainerStatuses[0].RestartCount = 5
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD110", "ReplicaSet shop/worker-rs", "process finishes with code 0", "a long-running container is expected")

	// A Job's container that finished, and an init container, did what they were meant to.
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "migrate", Controller: yes()}}
	s.Pods = []kube.Pod{p}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("job: %+v", r.Findings)
	}
}

// kubectlDenied puts the API server's refusal, as kubectl prints it, in the worker's log.
func kubectlDenied(s *snapshot.Snapshot, verb, resource, group, scope string) {
	s.Logs[0].Lines = []string{fmt.Sprintf(`Error from server (Forbidden): %s is forbidden: User "system:serviceaccount:shop:app" cannot %s resource %q in API group %q %s`, resource, verb, resource, group, scope)}
}

func TestRoleGrantsTheResourceInAnotherGroup(t *testing.T) {
	s, _ := rbacSnapshot()
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}}}
	kubectlDenied(s, "list", "deployments", "apps", `in the namespace "shop"`)
	f := only(t, Diagnose(s))
	expect(t, f, "KD300", "ReplicaSet shop/worker-rs", "it may not list deployments.apps in namespace shop",
		`Role configmap-reader grants get, list, watch on deployments, but in apiGroups [""], and deployments are in API group "apps"`)
	if !strings.Contains(f.Fix, `Set apiGroups to ["apps"] in the rule of Role configmap-reader`) {
		t.Errorf("fix: %s", f.Fix)
	}

	// The rule grants it in full: the refusal is something else, and KD126 says what to grant.
	s.Roles[0].Rules[0].APIGroups = []string{"apps"}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")

	// Roles were not read: no claim about them.
	s.Roles[0].Rules[0].APIGroups = []string{""}
	s.Gaps = []snapshot.Gap{{Resource: "roles.rbac.authorization.k8s.io"}}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestRoleNamesAResourceThatDoesNotExist(t *testing.T) {
	s, _ := rbacSnapshot()
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmap"}, Verbs: []string{"get", "list"}}}
	kubectlDenied(s, "list", "configmaps", "", `in the namespace "shop"`)
	f := only(t, Diagnose(s))
	expect(t, f, "KD301", "ReplicaSet shop/worker-rs", "it may not list configmaps in namespace shop",
		`Role configmap-reader grants get, list on resource "configmap", and the API has no resource by that name: it is "configmaps"`)
	if !strings.Contains(f.Fix, `Write "configmaps" for "configmap" in the resources of Role configmap-reader`) {
		t.Errorf("fix: %s", f.Fix)
	}
	for _, slip := range []string{"ConfigMaps", "ConfigMap", "configmpas", "confgmaps"} {
		s.Roles[0].Rules[0].Resources = []string{slip}
		expect(t, only(t, Diagnose(s)), "KD301", "ReplicaSet shop/worker-rs", slip)
	}
	kubectlDenied(s, "list", "networkpolicies", "networking.k8s.io", `in the namespace "shop"`)
	s.Roles[0].Rules[0].APIGroups, s.Roles[0].Rules[0].Resources = []string{"networking.k8s.io"}, []string{"networkpolicy"}
	expect(t, only(t, Diagnose(s)), "KD301", "ReplicaSet shop/worker-rs", `"networkpolicy"`)

	// Another resource altogether is no slip: KD126 says what to grant.
	kubectlDenied(s, "list", "secrets", "", `in the namespace "shop"`)
	s.Roles[0].Rules[0].APIGroups, s.Roles[0].Rules[0].Resources = []string{""}, []string{"configmaps"}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestRoleGrantsTheResourceButNotTheVerb(t *testing.T) {
	s, _ := rbacSnapshot()
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}}}
	kubectlDenied(s, "watch", "configmaps", "", `in the namespace "shop"`)
	f := only(t, Diagnose(s))
	expect(t, f, "KD302", "ReplicaSet shop/worker-rs", "it may not watch configmaps in namespace shop",
		"Role configmap-reader grants get, list on configmaps, and not watch (a client that follows changes")
	if !strings.Contains(f.Fix, `Add "watch" to the verbs of the rule of Role configmap-reader that names configmaps`) {
		t.Errorf("fix: %s", f.Fix)
	}
	s.Roles[0].Rules[0].Verbs = []string{"get"}
	kubectlDenied(s, "list", "configmaps", "", `in the namespace "shop"`)
	expect(t, only(t, Diagnose(s)), "KD302", "ReplicaSet shop/worker-rs", "grants get on configmaps, and not list (get reads one object by name")
	s.Roles[0].Rules[0].Verbs = []string{"*"}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestRoleLimitsAListByResourceNames(t *testing.T) {
	s, _ := rbacSnapshot()
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"settings"}, Verbs: []string{"get", "list", "watch"}}}
	kubectlDenied(s, "list", "configmaps", "", `in the namespace "shop"`)
	f := only(t, Diagnose(s))
	expect(t, f, "KD303", "ReplicaSet shop/worker-rs", "it may not list configmaps in namespace shop",
		`Role configmap-reader grants get, list, watch on configmaps only for resourceNames ["settings"], and a list request names no object`)
	if !strings.Contains(f.Fix, "Grant list on configmaps in a rule of Role configmap-reader without resourceNames (it then covers every configmap of the namespace), or have the app get settings by name") {
		t.Errorf("fix: %s", f.Fix)
	}
	// A get names its object: a refused get is something else.
	kubectlDenied(s, "get", "configmaps", "", `in the namespace "shop"`)
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestPermissionIsGrantedInAnotherNamespace(t *testing.T) {
	s, _ := rbacSnapshot()
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "watch"}}}
	kubectlDenied(s, "list", "configmaps", "", `in the namespace "default"`)
	f := only(t, Diagnose(s))
	expect(t, f, "KD304", "ReplicaSet shop/worker-rs", "it may not list configmaps in namespace default",
		"RoleBinding read-config grants it, through Role configmap-reader, in namespace shop only", "the request is for namespace default")
	if !strings.Contains(f.Fix, "create a Role and a RoleBinding there for ServiceAccount shop/app") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The grant elsewhere is not the same request: nothing to point at.
	s.Roles[0].Rules[0].Verbs = []string{"get"}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestARoleBindingCannotGrantAClusterWideRequest(t *testing.T) {
	s, _ := rbacSnapshot()
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}}}
	kubectlDenied(s, "list", "pods", "", "at the cluster scope")
	f := only(t, Diagnose(s))
	expect(t, f, "KD305", "ReplicaSet shop/worker-rs", "it may not list pods across the cluster",
		"RoleBinding read-config grants it, through Role configmap-reader, in namespace shop only, and the request is across all namespaces")
	if !strings.Contains(f.Fix, "kubectl -n shop instead of -A") {
		t.Errorf("fix: %s", f.Fix)
	}

	// A ClusterRole bound by a RoleBinding.
	s.RoleBindings[0].RoleRef.Kind, s.RoleBindings[0].RoleRef.Name = "ClusterRole", "node-reader"
	s.ClusterRoles = append(s.ClusterRoles, "node-reader")
	kubectlDenied(s, "list", "nodes", "", "at the cluster scope")
	f = only(t, Diagnose(s))
	expect(t, f, "KD305", "ReplicaSet shop/worker-rs", "RoleBinding read-config binds ClusterRole node-reader to it, and a RoleBinding grants a ClusterRole's rules in its own namespace, shop, only")
	if !strings.Contains(f.Fix, "kubectl create clusterrolebinding app-node-reader --clusterrole=node-reader --serviceaccount=shop:app") {
		t.Errorf("fix: %s", f.Fix)
	}

	// The binding is for another ServiceAccount: nothing grants the app anything, and KD126 says what to grant.
	s.RoleBindings[0].Subjects[0].Name = "default"
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestSpreadConstraintKeyIsOnNoNode(t *testing.T) {
	s := snap()
	s.Nodes = append(s.Nodes, node("node-2", "8", "32Gi"))
	p := unschedulablePod("0/2 nodes are available: 2 node(s) didn't match pod topology spread constraints (missing required label). preemption: 0/2 nodes are available: 2 Preemption is not helpful for scheduling.")
	p.Spec.TopologySpreadConstraints = []kube.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "topology.kubernetes.io/zone", WhenUnsatisfiable: "DoNotSchedule",
		LabelSelector: &kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD245", "Pod shop/web", "spread it over topology.kubernetes.io/zone (whenUnsatisfiable: DoNotSchedule), and none of the 2 nodes has that label")
	if !strings.Contains(f.Fix, "kubernetes.io/hostname") {
		t.Errorf("fix: %s", f.Fix)
	}

	// A node has the label: the constraint is unmet for another reason, and KD144 says so.
	s.Nodes[1].Metadata.Labels["topology.kubernetes.io/zone"] = "a"
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web")

	// Nodes were not read: no claim about their labels.
	delete(s.Nodes[1].Metadata.Labels, "topology.kubernetes.io/zone")
	s.Gaps = []snapshot.Gap{{Resource: "nodes"}}
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web")
}

func TestPodAffinityRequiresPodsThatDoNotExist(t *testing.T) {
	s := snap()
	p := unschedulablePod("0/1 nodes are available: 1 node(s) didn't match pod affinity rules. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.")
	p.Spec.Affinity = []byte(`{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"app":"cache"}},"topologyKey":"kubernetes.io/hostname"}]}}`)
	cache := pod("redis-0", "")
	cache.Metadata.Labels = map[string]string{"app": "redis"}
	s.Pods = []kube.Pod{p, cache}
	f := only(t, Diagnose(s))
	expect(t, f, "KD246", "Pod shop/web", "only beside pods labelled app=cache (topologyKey kubernetes.io/hostname), and namespace shop has no such pod",
		"(the other pods there have app=redis)")

	// The pod matches its own term: the scheduler would let it start, so the rule is unmet for another reason.
	p.Metadata.Labels["app"] = "cache"
	s.Pods = []kube.Pod{p, cache}
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web")

	// A pod with the labels exists: the rule is unmet for another reason.
	p.Metadata.Labels["app"] = "web"
	cache.Metadata.Labels["app"] = "cache"
	s.Pods = []kube.Pod{p, cache}
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web")

	// A term over another namespace, not read: nothing is claimed about it.
	cache.Metadata.Labels["app"] = "redis"
	p.Spec.Affinity = []byte(`{"podAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":[{"labelSelector":{"matchLabels":{"app":"cache"}},"namespaces":["data"],"topologyKey":"kubernetes.io/hostname"}]}}`)
	s.Pods = []kube.Pod{p, cache}
	expect(t, only(t, Diagnose(s)), "KD144", "Pod shop/web")
}

func TestNodeAffinityNoNodeMeets(t *testing.T) {
	s := snap()
	s.Nodes[0].Metadata.Labels["kubernetes.io/arch"] = "amd64"
	p := unschedulablePod("0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.")
	p.Spec.Affinity = []byte(`{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/arch","operator":"In","values":["arm64"]},{"key":"kubernetes.io/os","operator":"Exists"}]}]}}}`)
	s.Pods = []kube.Pod{p}
	s.Nodes[0].Metadata.Labels["kubernetes.io/os"] = "linux"
	expect(t, only(t, Diagnose(s)), "KD141", "Pod shop/web", "the pod's required node affinity asks for kubernetes.io/arch in (arm64), and the nodes have amd64, which no node meets")

	// Two terms, either of which would do; a label no node has.
	p.Spec.Affinity = []byte(`{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"gpu","operator":"Exists"}]},{"key":"x","matchExpressions":[{"key":"kubernetes.io/arch","operator":"NotIn","values":["amd64"]}]}]}}}`)
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD141", "Pod shop/web", "asks for gpu, a label no node has; or kubernetes.io/arch notin (amd64), and the nodes have amd64")

	// Each expression is met by some node: no claim about which.
	p.Spec.Affinity = []byte(`{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/arch","operator":"In","values":["amd64"]}]}]}}}`)
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD141", "Pod shop/web", "no node matches the pod's node selector or affinity")
}

func TestDockerSocketOnAContainerdNode(t *testing.T) {
	s := snap()
	s.Nodes[0].Status.NodeInfo.ContainerRuntimeVersion = "containerd://2.1.4"
	p := pod("builder", "")
	p.Status.Phase = "Pending"
	waiting(&p, "ContainerCreating", "")
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "builder", "FailedMount", `MountVolume.SetUp failed for volume "docker" : hostPath type check failed, /var/run/docker.sock is not a socket file, unable to determine its type: path "/var/run/docker.sock" does not exist`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD135", "Pod shop/builder", "volume docker mounts the Docker socket /var/run/docker.sock, and node node-1 runs containerd://2.1.4, not Docker")
	if !strings.Contains(f.Fix, "/run/containerd/containerd.sock") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The runtime is not known: the plain account.
	s.Nodes[0].Status.NodeInfo.ContainerRuntimeVersion = ""
	expect(t, only(t, Diagnose(s)), "KD135", "Pod shop/builder", "which is not a socket file on node node-1")
}

func TestVolumeMountedAsADirectoryWhereAFileIsRead(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	crashed(&p, 1, "Error", 3)
	p.Spec.Volumes = []kube.Volume{{Name: "config", ConfigMap: &kube.ConfigMapVolumeSource{Name: "app-config"}}}
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "config", MountPath: "/etc/app/config.yaml"}}
	s.Pods = []kube.Pod{p}
	s.ConfigMaps = []kube.KeySet{{Name: "app-config", Namespace: "shop", Keys: []string{"config.yaml"}}}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"loading settings", "error: read /etc/app/config.yaml: is a directory"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD233", "Deployment shop/web", "it reads /etc/app/config.yaml as a file, and /etc/app/config.yaml is where volume config (ConfigMap app-config) is mounted whole, without subPath",
		"a directory holding the volume's files (config.yaml)")
	if !strings.Contains(f.Fix, "Mount the volume at /etc/app, so that /etc/app/config.yaml is the file of key config.yaml in it") ||
		!strings.Contains(f.Fix, "subPath: config.yaml (a subPath mount does not follow later changes to the ConfigMap)") {
		t.Errorf("fix: %s", f.Fix)
	}

	// Python's wording, and a key named otherwise.
	s.ConfigMaps[0].Keys = []string{"settings.yaml"}
	s.Logs[0].Lines = []string{`IsADirectoryError: [Errno 21] Is a directory: '/etc/app/config.yaml'`}
	f = only(t, Diagnose(s))
	expect(t, f, "KD233", "Deployment shop/web", "(settings.yaml)")
	if !strings.Contains(f.Fix, "The volume has no key config.yaml") {
		t.Errorf("fix: %s", f.Fix)
	}

	// The path is inside the mount: not this.
	s.Logs[0].Lines = []string{"error: read /etc/app/config.yaml/x: is a directory"}
	if f := only(t, Diagnose(s)); f.Rule == "KD233" {
		t.Errorf("%+v", f)
	}
}

func TestHPATargetKindNotServed(t *testing.T) {
	s := snap()
	h := hpa("web", kube.Condition{Type: "AbleToScale", Status: "False", Reason: "FailedGetScale",
		Message: `the HPA controller was unable to get the target's current scale: no matches for kind "Deployment" in group "extensions"`})
	h.Spec.ScaleTargetRef.APIVersion = "extensions/v1beta1"
	s.HPAs = []kube.HorizontalPodAutoscaler{h}
	f := only(t, Diagnose(s))
	expect(t, f, "KD293", "HorizontalPodAutoscaler shop/web", `names its target as kind Deployment in apiVersion extensions/v1beta1, and the cluster serves no Deployment in API group "extensions"`, "(Deployments are served from apps/v1)")
	if f.Fix != "Set scaleTargetRef.apiVersion to apps/v1: Deployments are served from apps/v1, and extensions/v1beta1 is an old version the API no longer serves." {
		t.Errorf("fix: %s", f.Fix)
	}
	if f.Severity != Warning || len(f.Affects) != 1 || f.Affects[0].Name != "web" {
		t.Errorf("%+v", f)
	}

	h.Spec.ScaleTargetRef.APIVersion, h.Spec.ScaleTargetRef.Kind = "apps/v1", "deployment"
	h.Status.Conditions[0].Message = `the HPA controller was unable to get the target's current scale: no matches for kind "deployment" in group "apps"`
	s.HPAs = []kube.HorizontalPodAutoscaler{h}
	f = only(t, Diagnose(s))
	expect(t, f, "KD293", "HorizontalPodAutoscaler shop/web", "kind deployment in apiVersion apps/v1")
	if !strings.Contains(f.Fix, "Write the kind as Deployment") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestLivenessProbeKillsBeforeTheAppStarts(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Containers[0].LivenessProbe = &kube.Probe{TCPSocket: &kube.TCPSocketAction{Port: port(8080)}, InitialDelaySeconds: 5, PeriodSeconds: 5, FailureThreshold: 3}
	crashed(&p, 137, "Error", 4)
	lt := p.Status.ContainerStatuses[0].LastTerminationState.Terminated
	lt.StartedAt, lt.FinishedAt = t0.Add(-3*time.Minute), t0.Add(-3*time.Minute+52*time.Second)
	s.Pods = []kube.Pod{p}
	e1 := event("Pod", "web-rs-a", "Unhealthy", "Liveness probe failed: dial tcp 10.244.0.7:8080: connect: connection refused", time.Minute)
	e1.InvolvedObject.FieldPath = "spec.containers{web}"
	e2 := event("Pod", "web-rs-a", "Killing", "Container web failed liveness probe, will be restarted", 2*time.Minute)
	e2.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e1, e2}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"loading model weights (4 GiB)", "warming the cache"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD306", "Deployment shop/web", "killed by its liveness probe before it has started: every probe finds nothing listening on port 8080",
		"gives up after about 20s (initialDelaySeconds 5, then periodSeconds 5 x failureThreshold 3), there is no startupProbe, and each run ends after 52s",
		`the last line still about starting: "warming the cache"`)
	if !strings.Contains(f.Fix, "Add a startupProbe") {
		t.Errorf("fix: %s", f.Fix)
	}

	// The probe checks a port the container does not declare: more likely the wrong port than a slow start.
	p.Spec.Containers[0].LivenessProbe.TCPSocket.Port = port(9090)
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD112", "Deployment shop/web", "9090")
	p.Spec.Containers[0].LivenessProbe.TCPSocket.Port = port(8080)
	s.Pods = []kube.Pod{p}

	// The app said it was listening: it started, and the probe fails for another reason.
	s.Logs[0].Lines = append(s.Logs[0].Lines, "listening on :8081")
	expect(t, only(t, Diagnose(s)), "KD112", "Deployment shop/web")

	// An error in the log: the app failed, it was not slow.
	s.Logs[0].Lines = []string{"error: cannot open /data/model.bin"}
	expect(t, only(t, Diagnose(s)), "KD112", "Deployment shop/web")

	// A run far longer than the probe allows: it started and stopped answering later.
	s.Logs[0].Lines = []string{"warming the cache"}
	lt.FinishedAt = lt.StartedAt.Add(20 * time.Minute)
	expect(t, only(t, Diagnose(s)), "KD112", "Deployment shop/web")

	// A startupProbe covers the start: not this.
	lt.FinishedAt = lt.StartedAt.Add(52 * time.Second)
	p.Spec.Containers[0].StartupProbe = &kube.Probe{TCPSocket: &kube.TCPSocketAction{Port: port(8080)}}
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD112", "Deployment shop/web")
}

func TestNetworkPolicyIPBlockIsJudgedByThePodIP(t *testing.T) {
	s := snap()
	web := pod("web-7d4f8-abcde", "web")
	web.Status.PodIP = "10.244.0.17"
	client := pod("client-5c7d9-qwert", "client")
	client.Metadata.Labels = map[string]string{"app": "client"}
	crashed(&client, 1, "Error", 3)
	s.Pods = []kube.Pod{client, web}
	svc := service("web", map[string]string{"app": "web"}, port(8080))
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Logs = []snapshot.Log{{Pod: client.Ref(), Container: "web", Previous: true, Lines: []string{"Connecting to web (10.96.40.12:80)", "wget: download timed out"}}}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "client-egress", Namespace: "shop"}}
	np.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
	np.Spec.PolicyTypes = []string{"Egress"}
	np.Spec.Egress = []kube.NetworkPolicyRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "192.168.0.0/16"}}}}}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	// The block does not hold the pod's IP: the policy allows nothing the connection needs.
	expect(t, only(t, Diagnose(s)), "KD127", "ReplicaSet shop/client-rs", "NetworkPolicy client-egress allows no egress traffic between them on port 8080")

	// It holds it: allowed, so the timeout is something else.
	s.NetworkPolicies[0].Spec.Egress[0].To[0].IPBlock.CIDR = "10.244.0.0/16"
	if f := only(t, Diagnose(s)); f.Rule == "KD127" {
		t.Errorf("blocked though the ipBlock holds the pod: %s", f.Cause)
	}
	// Excepted from it: blocked.
	s.NetworkPolicies[0].Spec.Egress[0].To[0].IPBlock.Except = []string{"10.244.0.0/24"}
	expect(t, only(t, Diagnose(s)), "KD127", "ReplicaSet shop/client-rs")
	// The pod's IP is not known: assume the block may hold it.
	s.Pods[1].Status.PodIP = ""
	if f := only(t, Diagnose(s)); f.Rule == "KD127" {
		t.Errorf("blocked though the pod's IP is unknown: %s", f.Cause)
	}
}

func TestNetworkPolicyAllowsTheServiceClusterIP(t *testing.T) {
	s := snap()
	web := pod("web-7d4f8-abcde", "web")
	web.Status.PodIP = "10.244.0.17"
	client := pod("client-5c7d9-qwert", "client")
	client.Metadata.Labels = map[string]string{"app": "client"}
	crashed(&client, 1, "Error", 3)
	s.Pods = []kube.Pod{client, web}
	svc := service("web", map[string]string{"app": "web"}, port(8080))
	svc.Spec.ClusterIP = "10.96.0.200"
	s.Services = []kube.Service{svc}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.Logs = []snapshot.Log{{Pod: client.Ref(), Container: "web", Previous: true, Lines: []string{"Connecting to web (10.96.0.200:80)", "wget: download timed out"}}}
	eighty := kube.IntOrString{Int: 80}
	np := kube.NetworkPolicy{Metadata: kube.ObjectMeta{Name: "client-egress", Namespace: "shop"}}
	np.Spec.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "client"}}
	np.Spec.PolicyTypes = []string{"Egress"}
	np.Spec.Egress = []kube.NetworkPolicyRule{{To: []kube.NetworkPolicyPeer{{IPBlock: &kube.IPBlock{CIDR: "10.96.0.200/32"}}}, Ports: []kube.NetworkPolicyPort{{Port: &eighty}}}}
	s.NetworkPolicies = []kube.NetworkPolicy{np}
	f := only(t, Diagnose(s))
	expect(t, f, "KD360", "ReplicaSet shop/client-rs", "NetworkPolicy client-egress allows egress to ipBlock 10.96.0.200/32, which holds the Service's cluster IP 10.96.0.200",
		"against the pods' IPs, such as 10.244.0.17, which no rule allows")
	if !strings.Contains(f.Fix, "replace the ipBlock with a podSelector for the Service's pods (app=web) on port 8080") {
		t.Errorf("fix: %s", f.Fix)
	}
	// A block that holds neither: the plain KD127.
	s.NetworkPolicies[0].Spec.Egress[0].To[0].IPBlock.CIDR = "192.168.0.0/16"
	expect(t, only(t, Diagnose(s)), "KD127", "ReplicaSet shop/client-rs")
}

func TestContainerConnectsToAFixedIPNotTheService(t *testing.T) {
	s := snap()
	deployment(s, "api", 1, 0)
	p := pod("api-rs-a", "api")
	p.Spec.Containers[0].Env = []kube.EnvVar{{Name: "DB_HOST", Value: "10.96.0.201"}, {Name: "DB_PORT", Value: "5432"}}
	crashed(&p, 1, "Error", 3)
	db := service("db", map[string]string{"app": "db"}, port(8080))
	db.Spec.ClusterIP = "10.96.37.4"
	dbPod := pod("db-0", "")
	dbPod.Metadata.Labels = map[string]string{"app": "db"}
	s.Pods = []kube.Pod{p, dbPod}
	s.Services = []kube.Service{db}
	s.EndpointSlices = []kube.EndpointSlice{slice("db", 1)}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"connecting to the database at 10.96.0.201:5432",
		"Connecting to 10.96.0.201:5432 (10.96.0.201:5432)", "wget: can't connect to remote host (10.96.0.201): Connection refused"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD361", "Deployment shop/api", "its connection to 10.96.0.201 fails: the address is written into DB_HOST=10.96.0.201, and Service db, which DB_HOST names, has cluster IP 10.96.37.4")
	if !strings.HasPrefix(f.Fix, "Set DB_HOST to the Service's name, db (or db.shop.svc)") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The variable names no Service: no guess at which was meant.
	s.Pods[0].Spec.Containers[0].Env[0].Name = "DATABASE"
	if f := only(t, Diagnose(s)); f.Rule == "KD361" {
		t.Errorf("%+v", f)
	}
	// The address is the Service's own: the failure is something else.
	s.Pods[0].Spec.Containers[0].Env[0].Name = "DB_HOST"
	s.Services[0].Spec.ClusterIP = "10.96.0.201"
	if f := only(t, Diagnose(s)); f.Rule == "KD361" {
		t.Errorf("%+v", f)
	}
}

func TestOOMKilledByTheAppsOwnMemorySetting(t *testing.T) {
	s := snap()
	deployment(s, "api", 1, 0)
	p := pod("api-rs-a", "api")
	p.Spec.Containers[0].Resources.Limits = map[string]string{"memory": "1Gi"}
	p.Spec.Containers[0].Env = []kube.EnvVar{{Name: "JAVA_OPTS", Value: "-XX:+UseG1GC -Xmx2g"}}
	crashed(&p, 137, "OOMKilled", 4)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD111", "Deployment shop/api", "uses more than its 1Gi memory limit", "the app is told to use more than that: -Xmx2g, 2Gi, in variable JAVA_OPTS")
	if !strings.HasPrefix(f.Fix, "Set -Xmx2g below the 1Gi limit") {
		t.Errorf("fix: %s", f.Fix)
	}
	for _, c := range []struct {
		env  kube.EnvVar
		args []string
		want string
	}{
		{kube.EnvVar{Name: "CACHE_SIZE_MB", Value: "2048"}, nil, "CACHE_SIZE_MB=2048, 2Gi, in the environment"},
		{kube.EnvVar{Name: "GOMEMLIMIT", Value: "1536MiB"}, nil, "GOMEMLIMIT=1536MiB"},
		{kube.EnvVar{Name: "X", Value: "y"}, []string{"node", "--max-old-space-size=4096", "server.js"}, "--max-old-space-size=4096, 4Gi, in the command line"},
	} {
		s.Pods[0].Spec.Containers[0].Env = []kube.EnvVar{c.env}
		s.Pods[0].Spec.Containers[0].Args = c.args
		expect(t, only(t, Diagnose(s)), "KD111", "Deployment shop/api", c.want)
	}
	// Below the limit: the setting is not the cause, and is not named.
	s.Pods[0].Spec.Containers[0].Env = []kube.EnvVar{{Name: "JAVA_OPTS", Value: "-Xmx512m"}}
	s.Pods[0].Spec.Containers[0].Args = nil
	if f := only(t, Diagnose(s)); strings.Contains(f.Cause, "told to use") {
		t.Errorf("named a setting below the limit: %s", f.Cause)
	}
}

func TestReadinessProbeTimesOut(t *testing.T) {
	s := snap()
	p := pod("web", "")
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/healthz", Port: port(8080)}, PeriodSeconds: 5}
	p.Status.ContainerStatuses[0].Ready = false
	s.Pods = []kube.Pod{p}
	e := event("Pod", "web", "Unhealthy", `Readiness probe failed: Get "http://10.244.0.7:8080/healthz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`, time.Minute)
	e.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e}
	f := only(t, Diagnose(s))
	expect(t, f, "KD120", "Pod shop/web", "its readiness probe times out: the app does not answer within the probe's 1s timeoutSeconds")
	if !strings.HasPrefix(f.Fix, "Raise the readiness probe's timeoutSeconds") {
		t.Errorf("fix: %s", f.Fix)
	}
	// An exec probe's timeout, as the kubelet reports it.
	s.Pods[0].Spec.Containers[0].ReadinessProbe = &kube.Probe{Exec: &kube.ExecAction{Command: []string{"sh", "-c", "check-db"}}, TimeoutSeconds: 2}
	s.Events[0].Message = `Readiness probe failed: command "sh -c check-db" timed out`
	expect(t, only(t, Diagnose(s)), "KD120", "Pod shop/web", "within the probe's 2s timeoutSeconds")
}

func TestOptionalKeyMissingLeavesAVariableUnset(t *testing.T) {
	s := snap()
	deployment(s, "api", 1, 0)
	p := pod("api-rs-a", "api")
	yes := true
	p.Spec.Containers[0].Env = []kube.EnvVar{{Name: "DATABASE_URL", ValueFrom: &kube.EnvVarSource{SecretKeyRef: &kube.KeyRef{Name: "db", Key: "url", Optional: &yes}}}}
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.Secrets = []kube.KeySet{{Name: "db", Namespace: "shop", Type: "Opaque", Keys: []string{"uri"}}}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"starting api", "fatal: DATABASE_URL is not set"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD235", "Deployment shop/api", "DATABASE_URL is unset: it comes from key url of Secret db, marked optional, and Secret db has no key url (it has uri)")
	if !strings.HasPrefix(f.Fix, "Add key url to Secret db, or point DATABASE_URL at the key it has") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The Secret does not exist at all.
	s.Secrets = nil
	expect(t, only(t, Diagnose(s)), "KD235", "Deployment shop/api", "there is no Secret db in namespace shop")

	// Not optional: the kubelet refuses to start the container, which is KD131's to report, not this.
	s.Pods[0].Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Optional = nil
	if f := only(t, Diagnose(s)); f.Rule == "KD235" {
		t.Errorf("%+v", f)
	}
	// The log names another variable: no claim.
	s.Pods[0].Spec.Containers[0].Env[0].ValueFrom.SecretKeyRef.Optional = &yes
	s.Logs[0].Lines = []string{"fatal: DATABASE_URL_RO is not set"}
	if f := only(t, Diagnose(s)); f.Rule == "KD235" {
		t.Errorf("%+v", f)
	}
}

func TestOptionalEnvFromMissingLeavesVariablesUnset(t *testing.T) {
	s := snap()
	deployment(s, "api", 1, 0)
	p := pod("api-rs-a", "api")
	yes := true
	p.Spec.Containers[0].EnvFrom = []kube.EnvFromSource{{ConfigMapRef: &kube.NameRef{Name: "api-env", Optional: &yes}}}
	p.Spec.Containers[0].Env = []kube.EnvVar{{Name: "LOG_LEVEL", Value: "info"}}
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.ConfigMaps = []kube.KeySet{{Name: "app-env", Namespace: "shop", Keys: []string{"API_URL"}}}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"fatal: API_URL is not set"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD235", "Deployment shop/api", "API_URL is unset: no env entry sets it, and the container takes its variables from ConfigMap api-env with envFrom, marked optional, and there is no ConfigMap api-env")
	// The variable named is one env sets itself: not this.
	s.Logs[0].Lines = []string{"fatal: LOG_LEVEL is not set"}
	if f := only(t, Diagnose(s)); f.Rule == "KD235" {
		t.Errorf("%+v", f)
	}
	// The ConfigMap exists: not this.
	s.Logs[0].Lines = []string{"fatal: API_URL is not set"}
	s.ConfigMaps[0].Name = "api-env"
	if f := only(t, Diagnose(s)); f.Rule == "KD235" {
		t.Errorf("%+v", f)
	}
}

func TestNodeSelectorPinsAPodToANodeThatIsGone(t *testing.T) {
	s := snap()
	p := unschedulablePod("0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.")
	p.Spec.NodeSelector = map[string]string{"kubernetes.io/hostname": "worker-7"}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD141", "Pod shop/web", "pins it to node worker-7 by kubernetes.io/hostname, and there is no node worker-7 (the nodes are node-1)")
	// A node of that name exists but is excluded for another label: the plain account.
	p.Spec.NodeSelector["disktype"] = "ssd"
	p.Spec.NodeSelector["kubernetes.io/hostname"] = "node-1"
	s.Pods = []kube.Pod{p}
	expect(t, only(t, Diagnose(s)), "KD141", "Pod shop/web", "no node has the labels")
}

func TestServiceOfPodsWaitingForAClaimIsTheClaims(t *testing.T) {
	s := snap()
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Spec.StorageClassName = strp("manual")
	pvc.Spec.Resources.Requests = map[string]string{"storage": "5Gi"}
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	var pv kube.PersistentVolume
	pv.Metadata.Name = "data-pv"
	pv.Spec.StorageClassName = "manual"
	pv.Spec.Capacity = map[string]string{"storage": "1Gi"}
	pv.Status.Phase = "Available"
	s.PVs = []kube.PersistentVolume{pv}
	p := unschedulablePod("0/1 nodes are available: pod has unbound immediate PersistentVolumeClaims. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.")
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	s.Pods = []kube.Pod{p}
	s.Services = []kube.Service{service("db", map[string]string{"app": "web"}, port(8080))}
	s.EndpointSlices = []kube.EndpointSlice{slice("db", 0)}
	// One finding, the claim's; the Service it leaves without endpoints is listed under it, not reported first.
	f := only(t, Diagnose(s))
	expect(t, f, "KD250", "PersistentVolumeClaim shop/data")
	if !containsRef(f.Affects, kube.Ref{Kind: "Service", Namespace: "shop", Name: "db"}) {
		t.Errorf("affects %v", f.Affects)
	}
}

func TestPostStartHookCaughtBeforeTheBackOff(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	waiting(&p, "PostStartHookError", `Exec lifecycle hook ([sh -c /opt/warm-cache.sh]) for Container "web" in Pod "web-rs-a_shop(uid)" failed - error: command 'sh -c /opt/warm-cache.sh' exited with 127: sh: /opt/warm-cache.sh: not found`)
	p.Status.ContainerStatuses[0].RestartCount = 5
	p.Spec.Containers[0].Lifecycle = &kube.Lifecycle{PostStart: &kube.LifecycleHandler{Exec: &kube.ExecAction{Command: []string{"sh", "-c", "/opt/warm-cache.sh"}}}}
	s.Pods = []kube.Pod{p}
	e := event("Pod", "web-rs-a", "FailedPostStartHook", `Exec lifecycle hook ([sh -c /opt/warm-cache.sh]) for Container "web" in Pod "web-rs-a_shop(uid)" failed - error: command 'sh -c /opt/warm-cache.sh' exited with 127: sh: /opt/warm-cache.sh: not found`, time.Minute)
	e.InvolvedObject.FieldPath = "spec.containers{web}"
	s.Events = []kube.Event{e}
	expect(t, only(t, Diagnose(s)), "KD116", "Deployment shop/web", "postStart hook (sh -c /opt/warm-cache.sh) fails")
}

func TestRoleGrantsTheResourceButNotItsSubresource(t *testing.T) {
	s, _ := rbacSnapshot()
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}
	kubectlDenied(s, "get", "pods/log", "", `in the namespace "shop"`)
	f := only(t, Diagnose(s))
	expect(t, f, "KD307", "ReplicaSet shop/worker-rs", "it may not get pods/log in namespace shop",
		"Role configmap-reader grants get, list on pods, and the request is for its log subresource, pods/log", "a rule that names pods covers the objects, not their subresources")
	if !strings.Contains(f.Fix, `Add "pods/log" to the resources of the rule of Role configmap-reader that names pods (with verb get)`) {
		t.Errorf("fix: %s", f.Fix)
	}
	// "pods/*" and "*/log" grant it: the refusal is something else.
	for _, r := range []string{"pods/*", "*/log", "pods/log"} {
		s.Roles[0].Rules[0].Resources = []string{"pods", r}
		expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
	}
	// A rule without the verb is KD307's business only when it has the verb.
	s.Roles[0].Rules[0].Resources, s.Roles[0].Rules[0].Verbs = []string{"pods"}, []string{"list"}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestPermissionIsBoundToAnotherServiceAccount(t *testing.T) {
	s, p := rbacSnapshot()
	p.Spec.ServiceAccountName = ""
	s.Roles[0].Rules = []kube.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "watch"}}}
	s.RoleBindings[0].Subjects[0] = kube.Subject{Kind: "ServiceAccount", Name: "app"}
	s.Logs[0].Lines = []string{`configmaps is forbidden: User "system:serviceaccount:shop:default" cannot list resource "configmaps" in API group "" in the namespace "shop"`}
	f := only(t, Diagnose(s))
	expect(t, f, "KD308", "ReplicaSet shop/worker-rs", "refuses its ServiceAccount default: it may not list configmaps in namespace shop",
		"RoleBinding read-config grants it, through Role configmap-reader, to ServiceAccount app", "a pod whose template sets no serviceAccountName runs as default")
	if !strings.Contains(f.Fix, "Set serviceAccountName: app in the pod template, or, if the app should keep ServiceAccount default, add it to the subjects of RoleBinding read-config") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The Role does not grant the request: nothing to point at.
	s.Roles[0].Rules[0].Verbs = []string{"get"}
	expect(t, only(t, Diagnose(s)), "KD126", "ReplicaSet shop/worker-rs")
}

func TestScriptHasWindowsLineEndings(t *testing.T) {
	s := snap()
	deployment(s, "worker", 1, 0)
	p := pod("worker-rs-a", "worker")
	p.Spec.Containers[0].Command = []string{"sh", "/scripts/start.sh"}
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "scripts", MountPath: "/scripts"}}
	p.Spec.Volumes = []kube.Volume{{Name: "scripts", ConfigMap: &kube.ConfigMapVolumeSource{Name: "worker-scripts"}}}
	crashed(&p, 2, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.ConfigMaps = []kube.KeySet{{Namespace: "shop", Name: "worker-scripts", Keys: []string{"start.sh"}}}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true,
		Lines: []string{"starting the worker", "/scripts/start.sh: line 3: cd: can't cd to /app\r: No such file or directory"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD309", "Deployment shop/worker", "script /scripts/start.sh has Windows line endings (CRLF)", "the script comes from ConfigMap worker-scripts", `/app\r`)
	if !strings.Contains(f.Fix, "create ConfigMap worker-scripts again from the file") {
		t.Errorf("fix: %s", f.Fix)
	}
	// Bash says it another way.
	s.Logs[0].Lines = []string{"/scripts/start.sh: line 2: $'\\r': command not found"}
	expect(t, only(t, Diagnose(s)), "KD309", "Deployment shop/worker", "Windows line endings")

	// An app that writes CRLF logs, or a progress bar, is no sign.
	s.Logs[0].Lines = []string{"fatal: config not found\r", "downloading\r 45%\r 90%"}
	if f := only(t, Diagnose(s)); f.Rule == "KD309" {
		t.Errorf("CRLF logs: %s", f.Cause)
	}
}

func TestContainerReadsAPathWhereOnlyTheInitContainerMounts(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Volumes = []kube.Volume{{Name: "rendered", EmptyDir: &kube.EmptyDirVolumeSource{}}}
	p.Spec.InitContainers = []kube.Container{{Name: "render", VolumeMounts: []kube.VolumeMount{{Name: "rendered", MountPath: "/work"}}}}
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "rendered", MountPath: "/etc/app"}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"cat: can't open '/work/app.conf': No such file or directory"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD310", "Deployment shop/web", "/work/app.conf does not exist: init container render mounts volume rendered (emptyDir) at /work",
		"container web mounts it at /etc/app, so the file is /etc/app/app.conf there")
	if !strings.Contains(f.Fix, "Mount volume rendered at /work in container web as in init container render, or have the app read /etc/app/app.conf") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The container does not mount the volume.
	s.Pods[0].Spec.Containers[0].VolumeMounts = nil
	expect(t, only(t, Diagnose(s)), "KD310", "Deployment shop/web", "container web does not mount volume rendered at all")
	// A path the init container does not mount: not this.
	s.Logs[0].Lines = []string{"cat: can't open '/srv/app.conf': No such file or directory"}
	if f := only(t, Diagnose(s)); f.Rule == "KD310" {
		t.Errorf("other path: %s", f.Cause)
	}
}

func TestKeyFileModeIsTooOpen(t *testing.T) {
	s := snap()
	deployment(s, "git-sync", 1, 0)
	p := pod("git-sync-rs-a", "git-sync")
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "deploy-key", MountPath: "/etc/git-secret"}}
	p.Spec.Volumes = []kube.Volume{{Name: "deploy-key", Secret: &kube.SecretVolumeSource{SecretName: "deploy-key"}}}
	crashed(&p, 255, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{
		"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@",
		"Permissions 0644 for '/etc/git-secret/ssh' are too open.",
		"It is required that your private key files are NOT accessible by others.",
	}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD311", "Deployment shop/git-sync", "the app refuses key file /etc/git-secret/ssh", "its mode is 0644 (the default mode, as no defaultMode is set) on volume deploy-key (Secret deploy-key)")
	if !strings.Contains(f.Fix, "Set defaultMode: 0400 on volume deploy-key") {
		t.Errorf("fix: %s", f.Fix)
	}
	// PostgreSQL's words; the user is not root.
	uid := int64(999)
	s.Pods[0].Spec.SecurityContext = &kube.PodSecurityContext{RunAsUser: &uid}
	s.Logs[0].Lines = []string{`FATAL:  private key file "/etc/git-secret/ssh" has group or world access`}
	f = only(t, Diagnose(s))
	expect(t, f, "KD311", "Deployment shop/git-sync", "its mode is 0644")
	if !strings.Contains(f.Fix, "runs as user 999") {
		t.Errorf("fix: %s", f.Fix)
	}
	// A private mode: the refusal is something else.
	m := int32(0o400)
	s.Pods[0].Spec.Volumes[0].Secret.DefaultMode = &m
	if f := only(t, Diagnose(s)); f.Rule == "KD311" {
		t.Errorf("0400: %s", f.Cause)
	}
}

func TestContainerRunsAsAUserTheImageDoesNotDefine(t *testing.T) {
	s := snap()
	deployment(s, "worker", 1, 0)
	p := pod("worker-rs-a", "worker")
	uid := int64(10001)
	p.Spec.SecurityContext = &kube.PodSecurityContext{RunAsUser: &uid}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"whoami: unknown uid 10001"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD312", "Deployment shop/worker", "it runs as user ID 10001 (runAsUser, in the pod's securityContext), which has no entry in the image's /etc/passwd")
	if !strings.Contains(f.Fix, "add user 10001 to the image's /etc/passwd") {
		t.Errorf("fix: %s", f.Fix)
	}
	for _, l := range []string{"KeyError: 'getpwuid(): uid not found: 10001'", "user: unknown userid 10001", "No user exists for uid 10001", "I have no name!"} {
		s.Logs[0].Lines = []string{l}
		expect(t, only(t, Diagnose(s)), "KD312", "Deployment shop/worker", "10001")
	}
	// Another user ID in the message, or no runAsUser: not this.
	s.Logs[0].Lines = []string{"whoami: unknown uid 20002"}
	if f := only(t, Diagnose(s)); f.Rule == "KD312" {
		t.Errorf("other uid: %s", f.Cause)
	}
	s.Pods[0].Spec.SecurityContext = nil
	s.Logs[0].Lines = []string{"I have no name!"}
	if f := only(t, Diagnose(s)); f.Rule == "KD312" {
		t.Errorf("no runAsUser: %s", f.Cause)
	}
}

// gatewaySnapshot holds a working Gateway API setup: GatewayClass envoy, Gateway public with an HTTP listener on
// port 80, and HTTPRoute shop sending shop.example.com to Service web, port 80, which has a ready pod.
func gatewaySnapshot() *snapshot.Snapshot {
	s := snap()
	s.Pods = []kube.Pod{pod("web", "")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	s.NamespaceObjects = []kube.Namespace{{Metadata: kube.ObjectMeta{Name: "shop", Labels: map[string]string{"kubernetes.io/metadata.name": "shop"}}}}
	var class kube.GatewayClass
	class.Metadata.Name = "envoy"
	s.GatewayClasses = []kube.GatewayClass{class}
	var gw kube.Gateway
	gw.Metadata = kube.ObjectMeta{Name: "public", Namespace: "shop"}
	gw.Spec.GatewayClassName = "envoy"
	gw.Spec.Listeners = []kube.Listener{{Name: "http", Port: 80, Protocol: "HTTP"}}
	s.Gateways = []kube.Gateway{gw}
	var rt kube.Route
	rt.Kind, rt.Metadata = "HTTPRoute", kube.ObjectMeta{Name: "shop", Namespace: "shop"}
	rt.Spec.ParentRefs = []kube.ParentRef{{Name: "public"}}
	rt.Spec.Hostnames = []string{"shop.example.com"}
	p := int32(80)
	rt.Spec.Rules = append(rt.Spec.Rules, kube.RouteRule{BackendRefs: []kube.BackendRef{{Name: "web", Port: &p}}})
	s.Routes = []kube.Route{rt}
	return s
}

func TestAWorkingGatewaySetupIsQuiet(t *testing.T) {
	if r := Diagnose(gatewaySnapshot()); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestRouteSendsTrafficToAServiceThatDoesNotExist(t *testing.T) {
	s := gatewaySnapshot()
	s.Routes[0].Spec.Rules[0].BackendRefs[0].Name = "web-v2"
	f := only(t, Diagnose(s))
	expect(t, f, "KD362", "HTTPRoute shop/shop", "HTTPRoute shop sends traffic to Service web-v2 (from rule 1), which does not exist", "HTTP 500")
	if !strings.Contains(f.Fix, "Correct the backendRef's name in HTTPRoute shop, or create the Service") {
		t.Errorf("fix: %s", f.Fix)
	}
	// A backend in a namespace that was not read: nothing is known about it.
	s.Routes[0].Spec.Rules[0].BackendRefs[0].Namespace = "payments"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	// Services were not read.
	s.Routes[0].Spec.Rules[0].BackendRefs[0].Namespace = ""
	s.Gaps = []snapshot.Gap{{Resource: "services"}}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD362" {
			t.Errorf("services unread: %s", f.Cause)
		}
	}
}

func TestRouteSendsTrafficToAPortTheServiceDoesNotExpose(t *testing.T) {
	s := gatewaySnapshot()
	p := int32(8080)
	s.Routes[0].Spec.Rules[0].BackendRefs[0].Port = &p
	f := only(t, Diagnose(s))
	expect(t, f, "KD363", "HTTPRoute shop/shop", "port 8080 of Service web (from rule 1), which exposes port 80 (to the pods' http)")
	if !strings.Contains(f.Fix, "not the container's targetPort") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestRouteIsAttachedToAGatewayThatDoesNotExist(t *testing.T) {
	s := gatewaySnapshot()
	s.Routes[0].Spec.ParentRefs[0].Name = "public-gateway"
	f := only(t, Diagnose(s))
	expect(t, f, "KD364", "HTTPRoute shop/shop", "HTTPRoute shop attaches to Gateway public-gateway, which does not exist in namespace shop", "the Gateways of namespace shop are public")
	// A Gateway in a namespace that was not read: nothing is known about it.
	s.Routes[0].Spec.ParentRefs[0].Namespace = "gateways"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	// Gateways were not read.
	s.Routes[0].Spec.ParentRefs[0].Namespace = ""
	s.Gaps = []snapshot.Gap{{Resource: "gateways.gateway.networking.k8s.io"}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestGatewayNamesAGatewayClassThatDoesNotExist(t *testing.T) {
	s := gatewaySnapshot()
	s.Gateways[0].Spec.GatewayClassName = "nginx"
	f := only(t, Diagnose(s))
	expect(t, f, "KD365", "Gateway shop/public", "Gateway public names GatewayClass nginx, which does not exist", "the cluster's GatewayClasses are envoy")
	s.GatewayClasses = nil
	expect(t, only(t, Diagnose(s)), "KD365", "Gateway shop/public", "the cluster has no GatewayClass")
	s.Gaps = []snapshot.Gap{{Resource: "gatewayclasses.gateway.networking.k8s.io"}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestRouteNamesAListenerTheGatewayDoesNotHave(t *testing.T) {
	s := gatewaySnapshot()
	s.Routes[0].Spec.ParentRefs[0].SectionName = "https"
	f := only(t, Diagnose(s))
	expect(t, f, "KD366", "HTTPRoute shop/shop", "HTTPRoute shop attaches to listener https of Gateway public, and the Gateway has no such listener", "its listeners are http (port 80, HTTP)")
	s.Routes[0].Spec.ParentRefs[0].SectionName = ""
	p := int32(443)
	s.Routes[0].Spec.ParentRefs[0].Port = &p
	expect(t, only(t, Diagnose(s)), "KD366", "HTTPRoute shop/shop", "attaches to port 443 of Gateway public")
	s.Routes[0].Spec.ParentRefs[0].SectionName, p = "http", 80
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestGatewaysListenersDoNotAdmitTheRoute(t *testing.T) {
	s := gatewaySnapshot()
	l := &s.Gateways[0].Spec.Listeners[0]
	l.AllowedRoutes = &struct {
		Namespaces *struct {
			From     string              `json:"from,omitempty"`
			Selector *kube.LabelSelector `json:"selector,omitempty"`
		} `json:"namespaces,omitempty"`
		Kinds []struct {
			Group string `json:"group,omitempty"`
			Kind  string `json:"kind"`
		} `json:"kinds,omitempty"`
	}{}
	l.AllowedRoutes.Namespaces = &struct {
		From     string              `json:"from,omitempty"`
		Selector *kube.LabelSelector `json:"selector,omitempty"`
	}{From: "Selector", Selector: &kube.LabelSelector{MatchLabels: map[string]string{"gateway-access": "public"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD368", "HTTPRoute shop/shop", "no listener it attaches to admits it", "listener http admits routes from namespaces labelled gateway-access=public only", "namespace shop has labels kubernetes.io/metadata.name=shop")
	if !strings.Contains(f.Fix, "Label namespace shop so listener http's selector matches it") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.NamespaceObjects[0].Metadata.Labels["gateway-access"] = "public"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}

	// A Gateway in another namespace admits routes from its own only, by default.
	s = gatewaySnapshot()
	s.Namespaces = nil
	s.Gateways[0].Metadata.Namespace = "edge"
	s.Routes[0].Spec.ParentRefs[0].Namespace = "edge"
	expect(t, only(t, Diagnose(s)), "KD368", "HTTPRoute shop/shop", "listener http admits routes from its own namespace, edge, only (allowedRoutes.namespaces.from: Same, the default), and the route is in namespace shop")

	// A TCP listener takes TCPRoutes.
	s = gatewaySnapshot()
	s.Gateways[0].Spec.Listeners[0].Protocol = "TCP"
	expect(t, only(t, Diagnose(s)), "KD368", "HTTPRoute shop/shop", "listener http (TCP) takes TCPRoute, not HTTPRoutes")
}

func TestRoutesHostnamesAreServedByNoListener(t *testing.T) {
	s := gatewaySnapshot()
	s.Gateways[0].Spec.Listeners[0].Hostname = "*.store.example.com"
	f := only(t, Diagnose(s))
	expect(t, f, "KD367", "HTTPRoute shop/shop", "HTTPRoute shop serves shop.example.com, and the listeners of Gateway public it attaches to serve *.store.example.com (listener http)")
	for _, h := range []string{"shop.example.com", "*.example.com", ""} {
		s.Gateways[0].Spec.Listeners[0].Hostname = h
		if r := Diagnose(s); len(r.Findings) != 0 {
			t.Errorf("listener %q: %+v", h, r.Findings)
		}
	}
	for _, c := range []struct {
		l, r string
		ok   bool
	}{{"*.example.com", "a.b.example.com", true}, {"*.example.com", "example.com", false}, {"a.example.com", "*.example.com", true}, {"*.example.com", "*.shop.example.com", true}, {"*.store.example.com", "*.example.com", true}, {"*.a.com", "*.b.com", false}} {
		if hostMatch(c.l, c.r) != c.ok {
			t.Errorf("hostMatch(%q, %q) = %v", c.l, c.r, !c.ok)
		}
	}
}

func TestGatewayListenersCertificateSecretIsMissing(t *testing.T) {
	s := gatewaySnapshot()
	l := kube.Listener{Name: "https", Port: 443, Protocol: "HTTPS"}
	l.TLS = &struct {
		Mode            string `json:"mode,omitempty"`
		CertificateRefs []struct {
			Group     string `json:"group,omitempty"`
			Kind      string `json:"kind,omitempty"`
			Name      string `json:"name"`
			Namespace string `json:"namespace,omitempty"`
		} `json:"certificateRefs,omitempty"`
	}{}
	l.TLS.CertificateRefs = append(l.TLS.CertificateRefs, struct {
		Group     string `json:"group,omitempty"`
		Kind      string `json:"kind,omitempty"`
		Name      string `json:"name"`
		Namespace string `json:"namespace,omitempty"`
	}{Name: "shop-tls"})
	s.Gateways[0].Spec.Listeners = append(s.Gateways[0].Spec.Listeners, l)
	f := only(t, Diagnose(s))
	expect(t, f, "KD370", "Gateway shop/public", "listener https of Gateway public (port 443, HTTPS) terminates TLS with Secret shop-tls, and there is no Secret shop-tls in namespace shop")
	s.Secrets = []kube.KeySet{{Namespace: "shop", Name: "shop-tls", Type: "Opaque", Keys: []string{"cert.pem", "key.pem"}}}
	expect(t, only(t, Diagnose(s)), "KD370", "Gateway shop/public", "Secret shop-tls has keys cert.pem, key.pem, and a certificate Secret needs tls.crt and tls.key")
	s.Secrets[0].Keys = []string{"tls.crt", "tls.key"}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestRouteSendsTrafficToANamespaceThatDoesNotGrantIt(t *testing.T) {
	s := gatewaySnapshot()
	s.Namespaces = nil // every namespace read
	s.Services[0].Metadata.Namespace = "payments"
	s.EndpointSlices[0].Metadata.Namespace = "payments"
	s.Pods[0].Metadata.Namespace = "payments"
	s.Routes[0].Spec.Rules[0].BackendRefs[0].Namespace = "payments"
	f := only(t, Diagnose(s))
	expect(t, f, "KD369", "HTTPRoute shop/shop", "HTTPRoute shop sends traffic to Service web in namespace payments (from rule 1), and no ReferenceGrant in namespace payments lets HTTPRoutes of namespace shop refer to its Services")
	var g kube.ReferenceGrant
	g.Metadata = kube.ObjectMeta{Name: "from-shop", Namespace: "payments"}
	g.Spec.From = append(g.Spec.From, struct {
		Group     string `json:"group"`
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
	}{"gateway.networking.k8s.io", "HTTPRoute", "shop"})
	g.Spec.To = append(g.Spec.To, struct {
		Group string `json:"group"`
		Kind  string `json:"kind"`
		Name  string `json:"name,omitempty"`
	}{"", "Service", ""})
	s.ReferenceGrants = []kube.ReferenceGrant{g}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	// A grant for another Service only.
	s.ReferenceGrants[0].Spec.To[0].Name = "ledger"
	expect(t, only(t, Diagnose(s)), "KD369", "HTTPRoute shop/shop")
}

func TestRouteIsAttachedToNoGateway(t *testing.T) {
	s := gatewaySnapshot()
	s.Routes[0].Spec.ParentRefs = nil
	f := only(t, Diagnose(s))
	expect(t, f, "KD372", "HTTPRoute shop/shop", "HTTPRoute shop has no parentRefs, so it is attached to no Gateway")
	// Gateways unread: a route with no parentRefs is attached to nothing all the same.
	s.Gaps = []snapshot.Gap{{Resource: "gateways.gateway.networking.k8s.io"}}
	expect(t, only(t, Diagnose(s)), "KD372", "HTTPRoute shop/shop")
}

func TestHTTPRoutesSendTheSameHostAndPathToDifferentServices(t *testing.T) {
	s := gatewaySnapshot()
	canary := s.Routes[0]
	canary.Metadata.Name = "shop-canary"
	canary.Spec.Rules = []kube.RouteRule{{BackendRefs: []kube.BackendRef{{Name: "web", Port: canary.Spec.Rules[0].BackendRefs[0].Port}}}}
	canary.Spec.Rules[0].BackendRefs[0].Name = "web"
	s.Routes = append(s.Routes, canary)
	// The same Service: no conflict.
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	s.Services = append(s.Services, service("web-v2", map[string]string{"app": "web"}, named("http")))
	s.EndpointSlices = append(s.EndpointSlices, slice("web-v2", 1))
	s.Routes[1].Spec.Rules[0].BackendRefs[0].Name = "web-v2"
	f := only(t, Diagnose(s))
	expect(t, f, "KD371", "HTTPRoute shop/shop-canary", "HTTPRoute shop-canary claims shop.example.com with path prefix / (to Service web-v2; HTTPRoute shop sends it to Service web), on Gateway public", "so shop-canary gets none of those requests")
	// Created first, the canary wins instead.
	s.Routes[0].Metadata.CreationTimestamp, s.Routes[1].Metadata.CreationTimestamp = t0, t0.Add(-time.Hour)
	expect(t, only(t, Diagnose(s)), "KD371", "HTTPRoute shop/shop", "HTTPRoute shop claims shop.example.com")
	// A header match is narrower: no tie.
	s.Routes[1].Spec.Rules[0].Matches = []kube.RouteMatch{{Headers: []any{map[string]string{"name": "x-canary", "value": "true"}}}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestVariableComesFromALabelThePodDoesNotHave(t *testing.T) {
	s := snap()
	deployment(s, "api", 1, 0)
	p := pod("api-rs-a", "api")
	p.Spec.Containers[0].Env = []kube.EnvVar{{Name: "APP_VERSION", ValueFrom: &kube.EnvVarSource{FieldRef: &struct {
		FieldPath string `json:"fieldPath"`
	}{FieldPath: "metadata.labels['app.kubernetes.io/version']"}}}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"APP_VERSION is empty: cannot tag the build"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD236", "Deployment shop/api", "APP_VERSION is empty: it comes from the pod's label app.kubernetes.io/version (fieldRef metadata.labels['app.kubernetes.io/version']), and the pod has no such label", "the pod's labels are app")
	if !strings.Contains(f.Fix, "Add label app.kubernetes.io/version to the pod template's metadata") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The pod has the label: the complaint is something else.
	s.Pods[0].Metadata.Labels["app.kubernetes.io/version"] = "1.4.2"
	if f := only(t, Diagnose(s)); f.Rule == "KD236" {
		t.Errorf("label present: %s", f.Cause)
	}
}

func TestClaimsSelectorStopsProvisioning(t *testing.T) {
	s := snap()
	var sc kube.StorageClass
	sc.Metadata = kube.ObjectMeta{Name: "standard", Annotations: map[string]string{"storageclass.kubernetes.io/is-default-class": "true"}}
	sc.Provisioner, sc.VolumeBindingMode = "rancher.io/local-path", "WaitForFirstConsumer"
	s.StorageClasses = []kube.StorageClass{sc}
	var pvc kube.PersistentVolumeClaim
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop"}
	pvc.Spec.AccessModes = []string{"ReadWriteOnce"}
	pvc.Spec.Selector = &kube.LabelSelector{MatchLabels: map[string]string{"tier": "fast"}}
	pvc.Status.Phase = "Pending"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	p := pod("web", "")
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("PersistentVolumeClaim", "data", "ProvisioningFailed",
		`failed to provision volume with StorageClass "standard": claim.Spec.Selector is not supported`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD253", "PersistentVolumeClaim shop/data", "has a selector, tier=fast, and the provisioner of the default StorageClass standard does not provision a volume for a claim with one")
	// The same words, and no selector: KD152 reports the event as it is.
	s.PVCs[0].Spec.Selector = nil
	expect(t, only(t, Diagnose(s)), "KD152", "PersistentVolumeClaim shop/data")
}

func TestSpreadConstraintWithMoreMinDomainsThanTheNodesForm(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 1)
	running := pod("web-rs-a", "web")
	pending := pod("web-rs-b", "web")
	md := int32(3)
	for _, p := range []*kube.Pod{&running, &pending} {
		p.Spec.TopologySpreadConstraints = []kube.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "kubernetes.io/hostname", WhenUnsatisfiable: "DoNotSchedule",
			LabelSelector: &kube.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, MinDomains: &md}}
	}
	pending.Spec.NodeName = ""
	pending.Status.Phase = "Pending"
	pending.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 node(s) didn't match pod topology spread constraints. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."}}
	pending.Status.ContainerStatuses = nil
	s.Pods = []kube.Pod{running, pending}
	f := only(t, Diagnose(s))
	expect(t, f, "KD144", "Deployment shop/web", "its constraint over kubernetes.io/hostname has minDomains 3, and the nodes form 1 domain (node-1)",
		"no domain may hold more than maxSkew (1) of the pods the constraint counts, and 1 such pod already run")
	if !strings.Contains(f.Fix, "Lower minDomains to the number of kubernetes.io/hostname domains the nodes form (1)") {
		t.Errorf("fix: %s", f.Fix)
	}
	// Without minDomains, the account says where the pods are.
	for i := range s.Pods {
		s.Pods[i].Spec.TopologySpreadConstraints[0].MinDomains = nil
	}
	expect(t, only(t, Diagnose(s)), "KD144", "Deployment shop/web", "its constraint over kubernetes.io/hostname (maxSkew 1) spreads the pods it counts over 1 domain (node-1), where 1 such pod already run")
}

func TestPortInUseOnTheHostNetwork(t *testing.T) {
	s := snap()
	deployment(s, "node-agent", 1, 0)
	p := pod("node-agent-rs-a", "node-agent")
	p.Spec.HostNetwork = true
	p.Spec.Containers[0].Ports = []kube.ContainerPort{{ContainerPort: 10250}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"httpd: bind: Address in use"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD122", "Deployment shop/node-agent", "the pod runs in the node's network (hostNetwork: true), so it shares ports with every process of the node, and 10250 is the kubelet's")
	if !strings.Contains(f.Fix, "drop hostNetwork") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.Logs[0].Lines = []string{"listen tcp 0.0.0.0:9100: bind: address already in use"}
	expect(t, only(t, Diagnose(s)), "KD122", "Deployment shop/node-agent", "something on the node has 9100")
}

func TestSharedMemoryIsTooSmall(t *testing.T) {
	s := snap()
	deployment(s, "trainer", 1, 0)
	p := pod("trainer-rs-a", "trainer")
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true,
		Lines: []string{"loading batch 1", "dd: error writing '/dev/shm/batch': No space left on device"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD313", "Deployment shop/trainer", "shared memory (/dev/shm) is full", "the container runtime's 64 MiB", "/dev/shm/batch")
	if !strings.Contains(f.Fix, "emptyDir with medium: Memory at /dev/shm") {
		t.Errorf("fix: %s", f.Fix)
	}
	// PyTorch says it as a bus error in a DataLoader worker.
	s.Logs[0].Lines = []string{"ERROR: Unexpected bus error encountered in worker. This might be caused by insufficient shared memory (shm)."}
	expect(t, only(t, Diagnose(s)), "KD313", "Deployment shop/trainer", "insufficient shared memory")
	// A memory volume at /dev/shm that is still too small: its sizeLimit.
	s.Pods[0].Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "dshm", MountPath: "/dev/shm"}}
	s.Pods[0].Spec.Volumes = []kube.Volume{{Name: "dshm", EmptyDir: &kube.EmptyDirVolumeSource{Medium: "Memory", SizeLimit: "256Mi"}}}
	f = only(t, Diagnose(s))
	expect(t, f, "KD313", "Deployment shop/trainer", "volume dshm is mounted there with sizeLimit 256Mi")
	if !strings.Contains(f.Fix, "Raise volume dshm's sizeLimit") {
		t.Errorf("fix: %s", f.Fix)
	}
	// Running out of disk elsewhere is not shared memory.
	s.Logs[0].Lines = []string{"write /data/out.bin: no space left on device"}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD313" {
			t.Errorf("disk: %s", f.Cause)
		}
	}
}

func TestStatefulSetsPeersHaveNoDNSRecordsUntilReady(t *testing.T) {
	s := snap()
	sts := kube.Workload{Kind: "StatefulSet", Metadata: kube.ObjectMeta{Name: "quorum", Namespace: "shop"}}
	two := int32(2)
	sts.Spec.Replicas, sts.Spec.ServiceName, sts.Spec.PodManagementPolicy = &two, "quorum", "Parallel"
	s.Workloads = []kube.Workload{sts}
	p := pod("quorum-0", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "StatefulSet", Name: "quorum", Controller: yes()}}
	crashed(&p, 1, "Error", 3)
	s.Pods = []kube.Pod{p}
	svc := service("quorum", map[string]string{"app": "web"}, port(8080))
	svc.Spec.ClusterIP, svc.Spec.Ports[0].Port = "None", 8080
	s.Services = []kube.Service{svc}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"Server:\t\t10.96.0.10",
		"** server can't find quorum-1.quorum.shop.svc.cluster.local: NXDOMAIN", "cannot reach peer quorum-1.quorum"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD373", "StatefulSet shop/quorum", "cannot resolve its peer quorum-1.quorum", "publishes a pod's DNS record only once the pod is ready")
	if !strings.Contains(f.Fix, "publishNotReadyAddresses: true on Service quorum") || strings.Contains(f.Fix, "Parallel") {
		t.Errorf("fix: %s", f.Fix)
	}
	// OrderedReady: the peer is not even created.
	s.Workloads[0].Spec.PodManagementPolicy = ""
	f = only(t, Diagnose(s))
	expect(t, f, "KD373", "StatefulSet shop/quorum", "quorum-1 is not even created")
	// The Service already publishes not-ready pods: the lookup fails for another reason.
	s.Services[0].Spec.PublishNotReadyAddresses = true
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD373" {
			t.Errorf("published: %s", f.Cause)
		}
	}
}

func TestRouteRuleGivesEveryBackendWeightZero(t *testing.T) {
	s := gatewaySnapshot()
	zero, one := int32(0), int32(1)
	p := int32(80)
	s.Services = append(s.Services, service("web-v2", map[string]string{"app": "web"}, named("http")))
	s.EndpointSlices = append(s.EndpointSlices, slice("web-v2", 1))
	r := &s.Routes[0].Spec.Rules[0]
	r.BackendRefs[0].Weight = &zero
	r.BackendRefs = append(r.BackendRefs, kube.BackendRef{Name: "web-v2", Port: &p, Weight: &zero})
	f := only(t, Diagnose(s))
	expect(t, f, "KD374", "HTTPRoute shop/shop", "rule 1 of HTTPRoute shop sends traffic to web, web-v2, all with weight 0", "HTTP 500")
	// One backend at 1, or with no weight (which means 1): traffic flows.
	r.BackendRefs[1].Weight = &one
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	r.BackendRefs[1].Weight = nil
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestRoutePathIsAPatternItsMatchTypeComparesAsText(t *testing.T) {
	s := gatewaySnapshot()
	var m kube.RouteMatch
	m.Path = &struct {
		Type  string `json:"type,omitempty"`
		Value string `json:"value,omitempty"`
	}{"PathPrefix", "/api/*"}
	s.Routes[0].Spec.Rules[0].Matches = []kube.RouteMatch{m}
	f := only(t, Diagnose(s))
	expect(t, f, "KD375", "HTTPRoute shop/shop", "matches path /api/* with type PathPrefix, which compares it as text", "404")
	if !strings.HasPrefix(f.Fix, "Use path /api with type PathPrefix") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.Routes[0].Spec.Rules[0].Matches[0].Path.Type, s.Routes[0].Spec.Rules[0].Matches[0].Path.Value = "Exact", "/v[0-9]+/orders"
	expect(t, only(t, Diagnose(s)), "KD375", "HTTPRoute shop/shop", "path /v[0-9]+/orders with type Exact")
	// A regular expression is meant as one, and a plain prefix is fine.
	s.Routes[0].Spec.Rules[0].Matches[0].Path.Type = "RegularExpression"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	s.Routes[0].Spec.Rules[0].Matches[0].Path.Type, s.Routes[0].Spec.Rules[0].Matches[0].Path.Value = "PathPrefix", "/api"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestIngressPathIsAPatternItsPathTypeComparesAsText(t *testing.T) {
	s := snap()
	defaultIngressClass(s)
	s.Pods = []kube.Pod{pod("web", "")}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web"}, named("http"))}
	s.EndpointSlices = []kube.EndpointSlice{slice("web", 1)}
	ing := ingress("shop", "web", 80, "")
	ing.Spec.Rules[0].HTTP.Paths[0].Path, ing.Spec.Rules[0].HTTP.Paths[0].PathType = "/api/.*", "Prefix"
	s.Ingresses = []kube.Ingress{ing}
	f := only(t, Diagnose(s))
	expect(t, f, "KD278", "Ingress shop/shop", "routes path /api/.* on shop.example.com with pathType Prefix, which compares paths as text")
	if !strings.HasPrefix(f.Fix, "Use path /api with pathType Prefix") {
		t.Errorf("fix: %s", f.Fix)
	}
	// ImplementationSpecific may be a regular expression to the controller.
	s.Ingresses[0].Spec.Rules[0].HTTP.Paths[0].PathType = "ImplementationSpecific"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestAppArmorProfileIsNotLoadedOnTheNode(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Containers[0].SecurityContext = &kube.SecurityContext{AppArmorProfile: &kube.AppArmorProfile{Type: "Localhost", LocalhostProfile: "k8s-web"}}
	waiting(&p, "CreateContainerError", `failed to create containerd container: failed to generate apparmor spec opts: apparmor profile not found k8s-web`)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD314", "Deployment shop/web", "Localhost AppArmor profile k8s-web, which is not loaded on node node-1")
	if !strings.Contains(f.Fix, "apparmor_parser") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The profile set for the whole pod.
	s.Pods[0].Spec.Containers[0].SecurityContext = nil
	s.Pods[0].Spec.SecurityContext = &kube.PodSecurityContext{AppArmorProfile: &kube.AppArmorProfile{Type: "Localhost", LocalhostProfile: "k8s-web"}}
	expect(t, only(t, Diagnose(s)), "KD314", "Deployment shop/web", "profile k8s-web")
	// A node without AppArmor: the kubelet rejects the pod.
	q := pod("web-rs-b", "web")
	q.Spec.SecurityContext = s.Pods[0].Spec.SecurityContext
	q.Status = kube.PodStatus{Phase: "Failed", Reason: "AppArmor", Message: "Cannot enforce AppArmor: AppArmor is not enabled on the host"}
	s.Pods = []kube.Pod{q}
	expect(t, only(t, Diagnose(s)), "KD314", "Deployment shop/web", "asks for AppArmor profile Localhost k8s-web", "AppArmor is not enabled on the host")
}

func TestClaimIsBeingDeletedWhilePodsStillUseIt(t *testing.T) {
	s := snap()
	deployment(s, "db", 1, 1)
	old := pod("db-rs-old", "db")
	old.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "data"}}}
	fresh := old
	fresh.Metadata.Name, fresh.Spec.NodeName = "db-rs-new", ""
	fresh.Status = kube.PodStatus{Phase: "Pending", Conditions: []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: `0/1 nodes are available: persistentvolumeclaim "data" is being deleted. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.`}}}
	s.Pods = []kube.Pod{old, fresh}
	var pvc kube.PersistentVolumeClaim
	gone := t0.Add(-10 * time.Minute)
	pvc.Metadata = kube.ObjectMeta{Name: "data", Namespace: "shop", DeletionTimestamp: &gone, Finalizers: []string{"kubernetes.io/pvc-protection"}}
	pvc.Status.Phase = "Bound"
	s.PVCs = []kube.PersistentVolumeClaim{pvc}
	f := only(t, Diagnose(s))
	expect(t, f, "KD254", "Deployment shop/db", "PersistentVolumeClaim data, which was deleted 10m0s ago", "while pod db-rs-old still uses it", "when it stops, the claim goes")
	if !strings.Contains(f.Fix, "persistentVolumeReclaimPolicy: Retain") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestProbeConnectsOverTCPToAUDPPort(t *testing.T) {
	s := snap()
	deployment(s, "dns", 1, 0)
	p := pod("dns-rs-a", "dns")
	notReady(&p)
	p.Spec.Containers[0].Ports = []kube.ContainerPort{{Name: "dns", ContainerPort: 53, Protocol: "UDP"}}
	p.Spec.Containers[0].ReadinessProbe = &kube.Probe{TCPSocket: &kube.TCPSocketAction{Port: named("dns")}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "dns-rs-a", "Unhealthy", "Readiness probe failed: dial tcp 10.244.0.7:53: connect: connection refused", 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD212", "Deployment shop/dns", "readiness probe (tcpSocket) checks port 53 (named dns), which the container declares for UDP only", "never becomes ready")
	// The same port declared for TCP too: the probe may well reach something.
	s.Pods[0].Spec.Containers[0].Ports = append(s.Pods[0].Spec.Containers[0].Ports, kube.ContainerPort{Name: "dns-tcp", ContainerPort: 53, Protocol: "TCP"})
	s.Pods[0].Spec.Containers[0].ReadinessProbe.TCPSocket.Port = port(53)
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD212" {
			t.Errorf("TCP too: %s", f.Cause)
		}
	}
}

func TestTemplateChangeWaitsForPodsToBeDeleted(t *testing.T) {
	s := snap()
	sts := kube.Workload{Kind: "StatefulSet", Metadata: kube.ObjectMeta{Name: "cache", Namespace: "shop"}}
	three := int32(3)
	sts.Spec.Replicas = &three
	sts.Spec.UpdateStrategy.Type = "OnDelete"
	sts.Status.Replicas, sts.Status.ReadyReplicas, sts.Status.UpdatedReplicas = 3, 3, 1
	sts.Status.CurrentRevision, sts.Status.UpdateRevision = "cache-6d5f", "cache-7b9c"
	s.Workloads = []kube.Workload{sts}
	f := only(t, Diagnose(s))
	expect(t, f, "KD294", "StatefulSet shop/cache", "2 of its 3 pods still run the old one", "updateStrategy is OnDelete")
	if !strings.Contains(f.Fix, "kubectl rollout status statefulset/cache") {
		t.Errorf("fix: %s", f.Fix)
	}
	// Rolled out, or RollingUpdate: nothing waits on anyone.
	s.Workloads[0].Status.CurrentRevision = "cache-7b9c"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
	// A DaemonSet on four nodes, one of them updated.
	ds := kube.Workload{Kind: "DaemonSet", Metadata: kube.ObjectMeta{Name: "agent", Namespace: "shop"}}
	ds.Spec.UpdateStrategy.Type = "OnDelete"
	ds.Status.DesiredNumberScheduled, ds.Status.NumberReady, ds.Status.UpdatedNumberScheduled = 4, 4, 1
	s.Workloads = []kube.Workload{ds}
	expect(t, only(t, Diagnose(s)), "KD294", "DaemonSet shop/agent", "3 of its 4 pods still run the old one")
}

func TestContainerRunsAShellWithNothingToDo(t *testing.T) {
	s := snap()
	deployment(s, "toolbox", 1, 0)
	p := pod("toolbox-rs-a", "toolbox")
	p.Spec.Containers[0].Image = "docker.io/library/ubuntu:26.04"
	crashed(&p, 0, "Completed", 5)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD315", "Deployment shop/toolbox", "exits with code 0 as soon as it starts: it sets no command, and image ubuntu's default command is a shell")
	if !strings.Contains(f.Fix, "sleep infinity") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.Pods[0].Spec.Containers[0].Image, s.Pods[0].Spec.Containers[0].Command = "registry.example.com/tools:1", []string{"/bin/sh"}
	expect(t, only(t, Diagnose(s)), "KD315", "Deployment shop/toolbox", "its command is a shell with no script")
	// A shell with a script, or a terminal, is something else.
	s.Pods[0].Spec.Containers[0].Args = []string{"-c", "echo done"}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD315" {
			t.Errorf("script: %s", f.Cause)
		}
	}
}

func TestInPlaceResizeCannotFitTheNode(t *testing.T) {
	s := snap()
	deployment(s, "batch", 1, 1)
	p := pod("batch-rs-a", "batch")
	p.Status.Conditions = append(p.Status.Conditions, kube.Condition{Type: "PodResizePending", Status: "True", Reason: "Infeasible",
		Message: "Node didn't have enough capacity: cpu, requested: 64000, capacity: 8000"})
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD247", "Deployment shop/batch", "node node-1 cannot hold the new size at all", "requested: 64000, capacity: 8000")
	if f.Severity != Warning || !strings.Contains(f.Fix, "a resize never moves a pod") {
		t.Errorf("severity %v fix %s", f.Severity, f.Fix)
	}
	// The API server refuses such a resize at once (1.35 and later): the client that asked exits with its message.
	q := pod("resize-x7k2p", "")
	q.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "resize", Controller: yes()}}
	crashed(&q, 1, "Error", 0)
	q.Status.Phase = "Failed"
	s.Jobs = []kube.Job{{Metadata: kube.ObjectMeta{Name: "resize", Namespace: "shop"}}}
	s.Pods = append(s.Pods, q)
	s.Logs = []snapshot.Log{{Pod: q.Ref(), Container: "web", Previous: true,
		Lines: []string{`Error from server (Forbidden): pods "batch-rs-a" is forbidden: node didn't have enough allocatable resources: cpu, requested: 64000, allocatable: 4000`}}}
	var refused *Finding
	for i, f := range Diagnose(s).Findings {
		if f.Object.Kind == "Job" {
			refused = &Diagnose(s).Findings[i]
		}
	}
	if refused == nil {
		t.Fatal("no finding for the Job that asked for the resize")
	}
	expect(t, *refused, "KD247", "Job shop/resize", "refused the in-place resize it asked for", "has 4000m cpu allocatable, and the resize asks for 64000m")
	s.Pods, s.Logs, s.Jobs = s.Pods[:1], nil, nil

	// Deferred: the node may have room later, and the kubelet retries.
	s.Pods[0].Status.Conditions[2].Reason = "Deferred"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestStatefulSetUpdateStopsAtItsPartition(t *testing.T) {
	s := snap()
	sts := kube.Workload{Kind: "StatefulSet", Metadata: kube.ObjectMeta{Name: "kafka", Namespace: "shop"}}
	three, part := int32(3), int32(2)
	sts.Spec.Replicas = &three
	sts.Spec.UpdateStrategy.RollingUpdate = &struct {
		Partition *int32 `json:"partition,omitempty"`
	}{&part}
	sts.Status.Replicas, sts.Status.ReadyReplicas, sts.Status.UpdatedReplicas = 3, 3, 1
	sts.Status.CurrentRevision, sts.Status.UpdateRevision = "kafka-6d5f", "kafka-7b9c"
	s.Workloads = []kube.Workload{sts}
	f := only(t, Diagnose(s))
	expect(t, f, "KD296", "StatefulSet shop/kafka", "2 of its 3 pods still run the old one", "partition 2", "pods kafka-0 to kafka-1 keep the old one")
	// A partition at the replica count lets the change reach no pod.
	part = 3
	s.Workloads[0].Status.UpdatedReplicas = 0
	expect(t, only(t, Diagnose(s)), "KD296", "StatefulSet shop/kafka", "none of its 3 pods runs it", "reaches no pod")
	// Rolled out as far as the partition allows and no further change: nothing to say.
	s.Workloads[0].Status.CurrentRevision = "kafka-7b9c"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestRolloutDeadlineIsShorterThanAPodTakesToBecomeAvailable(t *testing.T) {
	s := snap()
	deployment(s, "api", 2, 2)
	d := &s.Workloads[0]
	ten := int32(10)
	d.Spec.ProgressDeadlineSeconds = &ten
	d.Spec.Template.Spec.Containers = []kube.Container{{Name: "api", ReadinessProbe: &kube.Probe{InitialDelaySeconds: 30}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD295", "Deployment shop/api", "progressDeadlineSeconds is 10", "cannot count as available in under 30s", "container api's readiness probe waits initialDelaySeconds 30")
	// minReadySeconds adds to the wait.
	d.Spec.MinReadySeconds = 15
	ninety := int32(40)
	d.Spec.ProgressDeadlineSeconds = &ninety
	expect(t, only(t, Diagnose(s)), "KD295", "Deployment shop/api", "under 45s", "then minReadySeconds 15")
	// The default deadline, or one long enough, says nothing.
	d.Spec.ProgressDeadlineSeconds = nil
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestNodeSelectorFromARuntimeClass(t *testing.T) {
	s := snap()
	deployment(s, "sandboxed", 1, 0)
	p := pod("sandboxed-rs-a", "sandboxed")
	p.Spec.NodeName = ""
	p.Spec.RuntimeClassName = "gvisor"
	p.Spec.NodeSelector = map[string]string{"sandbox.example.com/runtime": "gvisor"}
	p.Status = kube.PodStatus{Phase: "Pending", Conditions: []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."}}}
	s.Pods = []kube.Pod{p}
	var rc kube.RuntimeClass
	rc.Metadata.Name, rc.Handler = "gvisor", "runsc"
	rc.Scheduling = &struct {
		NodeSelector map[string]string `json:"nodeSelector,omitempty"`
		Tolerations  []kube.Toleration `json:"tolerations,omitempty"`
	}{NodeSelector: map[string]string{"sandbox.example.com/runtime": "gvisor"}}
	s.RuntimeClasses = []kube.RuntimeClass{rc}
	f := only(t, Diagnose(s))
	expect(t, f, "KD141", "Deployment shop/sandboxed", "sandbox.example.com/runtime=gvisor comes from RuntimeClass gvisor (handler runsc)", "not from the pod's own template")
	if !strings.Contains(f.Fix, "Label the nodes that have the runsc runtime handler") {
		t.Errorf("fix: %s", f.Fix)
	}
	// Without the RuntimeClass on record, the selector is the pod's own.
	s.RuntimeClasses = nil
	f = only(t, Diagnose(s))
	if strings.Contains(f.Cause, "RuntimeClass") {
		t.Errorf("cause: %s", f.Cause)
	}
}

func TestNoNodeCanTakeAnotherPod(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.NodeName = ""
	p.Status = kube.PodStatus{Phase: "Pending", Conditions: []kube.Condition{{Type: "PodScheduled", Status: "False", Reason: "Unschedulable",
		Message: "0/1 nodes are available: 1 Too many pods. preemption: 0/1 nodes are available: 1 No preemption victims found for incoming pod."}}}
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD140", "Deployment shop/web", "no node can take another pod: 1 node already runs as many pods as its kubelet allows", "pod limits: node-1 110")
	if strings.Contains(f.Fix, "request") || !strings.Contains(f.Fix, "maxPods") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestSidecarsStartupProbeHoldsTheAppBack(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.InitContainers = []kube.Container{{Name: "proxy", RestartPolicy: "Always", StartupProbe: &kube.Probe{HTTPGet: &kube.HTTPGetAction{Path: "/ready", Port: port(15021)}}}}
	p.Status.Phase = "Pending"
	started := false
	p.Status.InitContainerStatuses = []kube.ContainerStatus{{Name: "proxy", Started: &started, RestartCount: 3, State: kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: t0}},
		LastTerminationState: kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: 137, Reason: "Error"}}}}
	p.Status.ContainerStatuses = []kube.ContainerStatus{{Name: "web", State: kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: "PodInitializing"}}}}
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "True"}, {Type: "Initialized", Status: "False"}}
	s.Pods = []kube.Pod{p}
	s.Events = []kube.Event{event("Pod", "web-rs-a", "Unhealthy", `Startup probe failed: Get "http://10.244.0.9:15021/ready": dial tcp 10.244.0.9:15021: connect: connection refused`, 0),
		event("Pod", "web-rs-a", "Killing", "Container proxy failed startup probe, will be restarted", 0)}
	expect(t, only(t, Diagnose(s)), "KD112", "Deployment shop/web", "container proxy fails its startup probe", "it is a sidecar", "so container web never starts")
}

func TestContainerCallsTheAPIServerWithATokenForAnotherAudience(t *testing.T) {
	s := snap()
	deployment(s, "sync", 1, 0)
	p := pod("sync-rs-a", "sync")
	crashed(&p, 1, "Error", 3)
	src := kube.ProjectedSource{ServiceAccountToken: &struct {
		Audience string `json:"audience,omitempty"`
		Path     string `json:"path"`
	}{"vault", "vault-token"}}
	p.Spec.Volumes = []kube.Volume{{Name: "vault-token", Projected: &kube.ProjectedVolumeSource{Sources: []kube.ProjectedSource{src}}}}
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "vault-token", MountPath: "/var/run/secrets/tokens"}}
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"listing pods", "wget: server returned error: HTTP/1.1 401 Unauthorized"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD316", "Deployment shop/sync", "refuses its token (401 Unauthorized, not a missing permission)", "the token at /var/run/secrets/tokens/vault-token", "minted for audience vault")
	// A 403 is a missing permission, not this.
	s.Logs[0].Lines = []string{`pods is forbidden: User "system:serviceaccount:shop:sync" cannot list resource "pods" in API group "" in the namespace "shop"`}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD316" {
			t.Errorf("403: %s", f.Cause)
		}
	}
}

func TestServiceSelectsTheDeploymentsLabelsNotItsPods(t *testing.T) {
	s := snap()
	deployment(s, "api", 1, 1)
	s.Workloads[0].Metadata.Labels = map[string]string{"app": "api"}
	s.Workloads[0].Spec.Template.Metadata.Labels = map[string]string{"app": "api-server"}
	p := pod("api-rs-a", "api")
	p.Metadata.Labels = map[string]string{"app": "api-server"}
	s.Pods = []kube.Pod{p}
	s.Services = []kube.Service{service("api", map[string]string{"app": "api"}, port(8080))}
	f := only(t, Diagnose(s))
	expect(t, f, "KD160", "Service shop/api", "app=api matches Deployment api's own labels (under its metadata), which its pods do not get; its pods carry app=api-server")
	if !strings.Contains(f.Fix, "spec.template.metadata.labels: only those labels reach the pods") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestSystemCriticalPriorityIsNotAllowedInTheNamespace(t *testing.T) {
	s := snap()
	deployment(s, "agent", 1, 0)
	for i := range s.Workloads {
		s.Workloads[i].Status.Replicas = 0
		s.Workloads[i].Spec.Template.Spec.PriorityClassName = "system-node-critical"
	}
	s.Events = []kube.Event{event("ReplicaSet", "agent-rs", "FailedCreate",
		`Error creating: pods "agent-rs-x2k4p" is forbidden: insufficient quota to match these scopes: [{PriorityClass In [system-node-critical system-cluster-critical]}]`, time.Minute)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD380", "Deployment shop/agent", "they use PriorityClass system-node-critical", "only in a namespace with a ResourceQuota that names that class, as kube-system has; shop has none")
	if !strings.Contains(f.Fix, "copied from a kube-system manifest") || !strings.Contains(f.Fix, "scopeSelector names PriorityClass system-node-critical") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestServiceSelectsAnOldPodTemplateHash(t *testing.T) {
	s := snap()
	deployment(s, "web", 2, 2)
	a, b := pod("web-rs-a", "web"), pod("web-rs-b", "web")
	for _, p := range []*kube.Pod{&a, &b} {
		p.Metadata.Labels = map[string]string{"app": "web", "pod-template-hash": "7c4b9d5f6"}
	}
	s.Pods = []kube.Pod{a, b}
	s.Services = []kube.Service{service("web", map[string]string{"app": "web", "pod-template-hash": "5d9f7c6b8d"}, port(8080))}
	f := only(t, Diagnose(s))
	expect(t, f, "KD160", "Service shop/web", "pod-template-hash=5d9f7c6b8d is a label the Deployment controller", "changes with each rollout", "the pods now carry pod-template-hash=7c4b9d5f6")
	if !strings.Contains(f.Fix, "Remove pod-template-hash") {
		t.Errorf("fix: %s", f.Fix)
	}
	// A selector of generated labels alone is not this: nothing else to select the pods by.
	s.Services[0].Spec.Selector = map[string]string{"pod-template-hash": "5d9f7c6b8d"}
	for _, f := range Diagnose(s).Findings {
		if strings.Contains(f.Cause, "changes with each rollout") {
			t.Errorf("generated label only: %s", f.Cause)
		}
	}
}

func TestJobManagedByAnotherController(t *testing.T) {
	s := snap()
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "train", Namespace: "shop", CreationTimestamp: t0.Add(-10 * time.Minute)}
	j.Spec.ManagedBy = "batch.example.com/scheduler"
	s.Jobs = []kube.Job{j}
	f := only(t, Diagnose(s))
	expect(t, f, "KD298", "Job shop/train", "spec.managedBy batch.example.com/scheduler", "creates no pods", "in 10m0s that controller has not started it")
	s.Jobs[0].Spec.ManagedBy = "kueue.x-k8s.io/multikueue"
	expect(t, only(t, Diagnose(s)), "KD298", "Job shop/train", "MultiKueue, which runs it on a worker cluster")
	// Started by the controller it names, the Job controller's own name, or just created: nothing to say.
	started := t0.Add(-9 * time.Minute)
	s.Jobs[0].Status.StartTime = &started
	s.Jobs[0].Status.Active = 1
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("started: %+v", r.Findings)
	}
	s.Jobs[0].Status.StartTime, s.Jobs[0].Status.Active = nil, 0
	s.Jobs[0].Spec.ManagedBy = "kubernetes.io/job-controller"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("the Job controller: %+v", r.Findings)
	}
	s.Jobs[0].Spec.ManagedBy = "batch.example.com/scheduler"
	s.Jobs[0].Metadata.CreationTimestamp = t0.Add(-30 * time.Second)
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("just created: %+v", r.Findings)
	}
}

func TestContainerCannotEnterItsWorkingDirectory(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	uid := int64(10001)
	p.Spec.SecurityContext = &kube.PodSecurityContext{RunAsUser: &uid}
	p.Spec.Containers[0].WorkingDir = "/root/app"
	waiting(&p, "RunContainerError", `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: chdir to cwd ("/root/app") set in config.json failed: permission denied`)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD237", "Deployment shop/web", "working directory /root/app (its workingDir) is under /root, which user 10001 may not enter (permission denied)", "creates a missing working directory as root")
	// A file where a directory should be; the kubelet's escaped form of the message reads the same.
	s.Pods[0].Spec.SecurityContext, s.Pods[0].Spec.Containers[0].WorkingDir = nil, ""
	s.Pods[0].Status.ContainerStatuses[0].State.Waiting.Message = `error during container init: chdir to cwd (\"/app/server\") set in config.json failed: not a directory`
	f = only(t, Diagnose(s))
	expect(t, f, "KD237", "Deployment shop/web", "working directory /app/server (the image's WORKDIR) is a file in the image")
	if !strings.Contains(f.Fix, "/app.") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestOOMKilledUnderThePodLevelLimit(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Containers = append(p.Spec.Containers, kube.Container{Name: "proxy", Image: "registry.example.com/proxy:2"})
	p.Spec.Resources = &kube.Resources{Limits: map[string]string{"memory": "64Mi", "cpu": "1"}}
	crashed(&p, 137, "OOMKilled", 4)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD111", "Deployment shop/web", "under the pod's own 64Mi memory limit (spec.resources.limits.memory)", "shared by all 2 of the pod's containers")
	if !strings.Contains(f.Fix, "pod-level memory limit") {
		t.Errorf("fix: %s", f.Fix)
	}
	// The container's own limit is the one it hit.
	s.Pods[0].Spec.Containers[0].Resources.Limits = map[string]string{"memory": "32Mi"}
	expect(t, only(t, Diagnose(s)), "KD111", "Deployment shop/web", "uses more than its 32Mi memory limit")
}

func backendTLS(name, target, ca string) kube.BackendTLSPolicy {
	var b kube.BackendTLSPolicy
	b.Metadata = kube.ObjectMeta{Name: name, Namespace: "shop"}
	b.Spec.TargetRefs = append(b.Spec.TargetRefs, struct {
		Group       string `json:"group"`
		Kind        string `json:"kind"`
		Name        string `json:"name"`
		SectionName string `json:"sectionName,omitempty"`
	}{"", "Service", target, ""})
	b.Spec.Validation.CACertificateRefs = append(b.Spec.Validation.CACertificateRefs, struct {
		Group string `json:"group"`
		Kind  string `json:"kind"`
		Name  string `json:"name"`
	}{"", "ConfigMap", ca})
	b.Spec.Validation.Hostname = target + ".shop.svc"
	return b
}

func TestBackendTLSPolicyCACertificate(t *testing.T) {
	s := snap()
	s.Services = []kube.Service{service("auth", nil, port(8443))}
	s.EndpointSlices = []kube.EndpointSlice{slice("auth", 1)}
	s.BackendTLSPolicies = []kube.BackendTLSPolicy{backendTLS("auth-tls", "auth", "auth-ca")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD376", "BackendTLSPolicy shop/auth-tls", "Service auth against the CA bundle in ConfigMap auth-ca, and there is no ConfigMap auth-ca in namespace shop", "fail with a 5xx error")
	s.ConfigMaps = []kube.KeySet{keys("shop", "auth-ca", "ca.pem")}
	expect(t, only(t, Diagnose(s)), "KD376", "BackendTLSPolicy shop/auth-tls", "ConfigMap auth-ca has keys ca.pem, and the CA bundle must be under key ca.crt")
	s.ConfigMaps = []kube.KeySet{keys("shop", "auth-ca", "ca.crt")}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a good CA ConfigMap: %+v", r.Findings)
	}
	// ConfigMaps not read: nothing to say.
	s.ConfigMaps = nil
	s.Gaps = []snapshot.Gap{{Resource: "configmaps"}}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("configmaps not read: %+v", r.Findings)
	}
}

func TestBackendTLSPolicyTarget(t *testing.T) {
	s := snap()
	s.Services = []kube.Service{service("auth", nil, port(8443))}
	s.EndpointSlices = []kube.EndpointSlice{slice("auth", 1)}
	s.ConfigMaps = []kube.KeySet{keys("shop", "auth-ca", "ca.crt")}
	s.BackendTLSPolicies = []kube.BackendTLSPolicy{backendTLS("auth-tls", "auth-svc", "auth-ca")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD377", "BackendTLSPolicy shop/auth-tls", "targets Service auth-svc, and there is no Service auth-svc in namespace shop (there is a Service auth)", "connects without TLS")
	if !strings.Contains(f.Fix, "Service auth,") {
		t.Errorf("fix: %s", f.Fix)
	}
	s.BackendTLSPolicies[0].Spec.TargetRefs[0].Name, s.BackendTLSPolicies[0].Spec.TargetRefs[0].SectionName = "auth", "https"
	s.Services[0].Spec.Ports[0].Name = "web"
	expect(t, only(t, Diagnose(s)), "KD377", "BackendTLSPolicy shop/auth-tls", "targets Service auth (port https), and Service auth has no port named https (its ports are named web)")
	s.Services[0].Spec.Ports[0].Name = "https"
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a good target: %+v", r.Findings)
	}
}

func TestRouteSendsTrafficToADeployment(t *testing.T) {
	s := gatewaySnapshot()
	deployment(s, "storefront", 1, 1)
	s.Routes[0].Spec.Rules[0].BackendRefs[0] = kube.BackendRef{Group: "apps", Kind: "Deployment", Name: "storefront"}
	f := only(t, Diagnose(s))
	expect(t, f, "KD378", "HTTPRoute shop/shop", "sends the requests of rule 1 to Deployment storefront", "InvalidKind", "Service web selects Deployment storefront's pods")
	if !strings.Contains(f.Fix, "Send the rule to Service web,") {
		t.Errorf("fix: %s", f.Fix)
	}
	// Another group's kind is an implementation's or an extension's backend: nothing to say.
	s.Routes[0].Spec.Rules[0].BackendRefs[0] = kube.BackendRef{Group: "inference.networking.k8s.io", Kind: "InferencePool", Name: "llama"}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("InferencePool: %+v", r.Findings)
	}
}

func TestImageFromALocalhostRegistry(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Containers[0].Image = "localhost/shop/web:dev"
	waiting(&p, "ErrImagePull", `failed to pull and unpack image "localhost/shop/web:dev": failed to resolve reference "localhost/shop/web:dev": failed to do request: Head "https://localhost/v2/shop/web/manifests/dev": dial tcp [::1]:443: connect: connection refused`)
	s.Pods = []kube.Pod{p}
	f := only(t, Diagnose(s))
	expect(t, f, "KD103", "Deployment shop/web", "names registry localhost, and on node node-1 that is the node itself", "podman and buildah name local builds localhost/")
	if !strings.Contains(f.Fix, "kind load docker-image") {
		t.Errorf("fix: %s", f.Fix)
	}
	// A registry on a port of localhost, as kind's local-registry recipe names it.
	s.Pods[0].Spec.Containers[0].Image = "localhost:5001/web:dev"
	expect(t, only(t, Diagnose(s)), "KD103", "Deployment shop/web", "names registry localhost:5001")
	// Any other unreachable registry keeps the general cause.
	s.Pods[0].Spec.Containers[0].Image = "registry.corp.internal/web:dev"
	expect(t, only(t, Diagnose(s)), "KD103", "Deployment shop/web", "the node cannot reach the registry for image registry.corp.internal/web:dev")
	if registry("localhost/web") != "localhost" || registry("library/busybox") != "docker.io" {
		t.Errorf("registry: %s %s", registry("localhost/web"), registry("library/busybox"))
	}
}

func TestValueEndsWithANewlineFromAYAMLBlock(t *testing.T) {
	s := snap()
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	p.Spec.Containers[0].Command = []string{"sh", "-c", "cat \"$0\" > /dev/null && exec httpd -f -p 8080\n"}
	p.Spec.Containers[0].Args = []string{"/etc/app/app.conf\n"}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: []string{"cat: can't open '/etc/app/app.conf", "': No such file or directory"}}}
	f := only(t, Diagnose(s))
	expect(t, f, "KD238", "Deployment shop/web", `its args item "/etc/app/app.conf\n" ends with a newline, which a YAML literal block (|) keeps`, "cat: can't open '/etc/app/app.conf")
	// An environment variable, quoted by the program that read it.
	s.Pods[0].Spec.Containers[0].Args = nil
	s.Pods[0].Spec.Containers[0].Env = []kube.EnvVar{{Name: "API_URL", Value: "http://api.shop.svc:8080\n"}}
	s.Logs[0].Lines = []string{`parse "http://api.shop.svc:8080`, `": net/url: invalid control character in URL`}
	expect(t, only(t, Diagnose(s)), "KD238", "Deployment shop/web", `its env API_URL value "http://api.shop.svc:8080\n"`)
	// A script that ends with a newline, and a log that does not quote the value: not this.
	s.Pods[0].Spec.Containers[0].Env = nil
	s.Logs[0].Lines = []string{"httpd: bind: Address in use"}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD238" {
			t.Errorf("script: %s", f.Cause)
		}
	}
}
