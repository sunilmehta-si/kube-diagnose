package diagnose

// Rule documents one rule: what it detects and from which evidence. docs/rules.md is generated from this list.
type Rule struct {
	ID       string
	Title    string
	Severity Severity
	Detects  string
	Evidence string
}

// Rules is every rule kube-diagnose can report, in ID order. IDs are stable: a rule is retired, never renumbered.
var Rules = []Rule{
	{"KD100", "Image cannot be pulled", Critical, "A container waits in ErrImagePull or ImagePullBackOff for a reason none of KD101-KD103 recognises.", "The container's waiting state and the newest pull-failure event."},
	{"KD101", "Image does not exist", Critical, "The registry answered that the image's tag or digest does not exist.", "The waiting state, and the pull-failure event whose message says not found or manifest unknown."},
	{"KD102", "Registry refused the image pull", Critical, "The registry refused the pull: no credentials, wrong credentials, or a repository that does not exist and is reported as access denied.", "The pull-failure event saying unauthorized, denied, 401/403 or insufficient_scope, and whether the pod has imagePullSecrets."},
	{"KD103", "Registry cannot be reached", Critical, "The node could not reach the registry: DNS, connection or TLS failure.", "The pull-failure event saying no such host, i/o timeout, connection refused or TLS handshake timeout."},
	{"KD104", "Image reference is invalid", Critical, "The image field is not a valid reference.", "The container waiting in InvalidImageName."},
	{"KD105", "Registry rate-limits the image pull", Critical, "The registry refused the pull because a pull quota is used up (429 Too Many Requests), as Docker Hub does for anonymous pulls.", "The pull-failure event with toomanyrequests or 429."},
	{"KD106", "Image pull secret does not exist", Critical, "The registry refused the pull, and a Secret the pod lists in imagePullSecrets does not exist, so the pull went without credentials.", "The pull-failure event, the FailedToRetrieveImagePullSecret event when present, and the Secret list (names only)."},
	{"KD107", "Image pull secret has the wrong type", Critical, "The registry refused the pull, and a Secret the pod lists in imagePullSecrets is not of type kubernetes.io/dockerconfigjson or dockercfg, so the kubelet ignored it.", "The pull-failure event and the Secret's type and key names (never values)."},
	{"KD110", "Container keeps crashing", Critical, "A container exits and is restarted (CrashLoopBackOff), or a Job's container exits non-zero. The exit code is explained and the log line that reads like the error is quoted. Exit code 0 in a long-running workload is called out.", "The last terminated state (exit code, reason) and the tail of the previous run's log."},
	{"KD111", "Container runs out of memory", Critical, "A container is killed for using more memory than its limit (OOMKilled). Critical while it crash-loops, a warning while it runs between kills.", "The terminated state with reason OOMKilled, and the container's memory limit."},
	{"KD112", "Liveness probe kills the container", Critical, "The kubelet restarts a container because its liveness or startup probe fails. When the probe's port is not one the container declares, it says so.", "Unhealthy and Killing events naming the probe, the exit code 137 or 143, and the probe spec."},
	{"KD113", "Image built for another CPU architecture", Critical, "The container's binary fails with exec format error: the image is for another architecture than the node.", "The start error or the log line with exec format error."},
	{"KD114", "Command not found in the image", Critical, "The container's command does not exist in the image.", "The StartError or RunContainerError saying executable file not found, and the container's command."},
	{"KD115", "Init container fails", Critical, "An init container exits non-zero, so the app containers never start.", "The init container's terminated state and the tail of its log."},
	{"KD116", "Lifecycle hook fails", Critical, "A container's postStart hook fails, so the kubelet kills the container each time it starts and it crash-loops.", "FailedPostStartHook events naming the container, with the hook's error."},
	{"KD117", "Image runs as root but the pod requires non-root", Critical, "The pod sets runAsNonRoot and the image runs as root, or names a non-numeric user the kubelet cannot check, so the container is never created.", "The container's CreateContainerConfigError message."},
	{"KD120", "Readiness probe failing", Critical, "A running container never becomes ready because its readiness probe fails, so its Services send it no traffic.", "Unhealthy events for the readiness probe, the container's ready state, and the probe spec."},
	{"KD130", "ConfigMap does not exist", Critical, "A container's env, envFrom or a volume refers to a ConfigMap that does not exist.", "CreateContainerConfigError or a FailedMount event, and the ConfigMap list showing it is absent."},
	{"KD131", "Secret does not exist", Critical, "A container's env, envFrom or a volume refers to a Secret that does not exist.", "CreateContainerConfigError or a FailedMount event, and the Secret list (names only) showing it is absent."},
	{"KD132", "Key missing from ConfigMap or Secret", Critical, "A container reads a key that the ConfigMap or Secret does not have.", "The kubelet's couldn't-find-key message, and the object's key names (never values)."},
	{"KD133", "Volume cannot be mounted", Critical, "A pod is stuck creating its containers because a volume fails to mount, for a reason KD130-KD132 do not cover.", "The FailedMount event."},
	{"KD139", "Container configuration is invalid", Critical, "CreateContainerConfigError for a reason KD130-KD132 do not cover.", "The container's waiting message."},
	{"KD140", "No node has enough of a resource", Critical, "The scheduler finds no node with enough free cpu, memory, pods or an extended resource such as GPUs. When the request exceeds every node's allocatable, it says the pod can never fit.", "The pod's PodScheduled condition, its requests, and the largest node's allocatable."},
	{"KD141", "No node matches the pod's node selector", Critical, "No node has the labels the pod's nodeSelector or node affinity requires.", "The scheduler's message, the pod's nodeSelector, and the node list."},
	{"KD142", "Nodes have taints the pod does not tolerate, or are cordoned", Critical, "Nodes reject the pod because of taints it does not tolerate, or because they are cordoned.", "The scheduler's message naming the taint, and the nodes' taints."},
	{"KD143", "Pod waits for a PersistentVolumeClaim", Critical, "A pod cannot be scheduled until its claim is bound; the pod is listed under the claim's own finding when there is one.", "The scheduler's unbound-claim message and the claim's phase."},
	{"KD149", "Pod cannot be scheduled", Critical, "The scheduler rejects every node for a reason KD140-KD143 do not cover; its message is quoted.", "The pod's PodScheduled condition or FailedScheduling event."},
	{"KD150", "StorageClass does not exist", Critical, "A claim asks for a StorageClass that does not exist.", "The claim's storageClassName and the StorageClass list."},
	{"KD151", "No default StorageClass", Critical, "A claim names no StorageClass and the cluster has no default, so nothing provisions it.", "The claim, the StorageClass list, and the absence of an Available static volume."},
	{"KD152", "Volume is not provisioned", Critical, "A claim stays Pending: provisioning failed or its provisioner never answered.", "ProvisioningFailed, ExternalProvisioning or FailedBinding events on the claim."},
	{"KD153", "PersistentVolumeClaim does not exist", Critical, "A pod mounts a claim that does not exist.", "The scheduler's message and the claim list."},
	{"KD160", "Service selects no pods", Critical, "A Service's selector matches no pod and no workload's pod template, and the pod labels closest to it are named.", "The Service's selector and the labels of the pods in the namespace."},
	{"KD161", "Service targets a port the pods do not have", Critical, "A Service's targetPort names a port no selected container declares, so the Service has no endpoints although its pods are ready.", "The Service's ports, the pods' named ports, and the empty EndpointSlice."},
	{"KD162", "Service has no ready pods", Critical, "A Service selects pods but none is ready, for a reason no other finding explains. When a pod finding explains it, the Service is listed under that finding instead.", "The selected pods and their readiness."},
	{"KD163", "NetworkPolicy blocks all traffic to a Service", Warning, "Every ready pod behind a Service is selected by ingress NetworkPolicies with no rules, so nothing can connect. A warning, because a closed Service can be intended.", "The policy's pod selector and empty ingress, and the Service's pods."},
	{"KD164", "Service targets a port the pods do not declare", Warning, "A numeric targetPort that none of the selected containers declares, while they declare others: the usual shape of a wrong targetPort. A warning, because declaring ports is optional.", "The Service's ports and the pods' declared ports."},
	{"KD170", "ResourceQuota is exhausted", Critical, "A controller cannot create pods because a ResourceQuota is used up or requires requests and limits the pods do not set.", "The controller's FailedCreate event and the quota's usage."},
	{"KD171", "ServiceAccount does not exist", Critical, "A controller cannot create pods because their ServiceAccount does not exist.", "The FailedCreate event and the ServiceAccount list."},
	{"KD172", "Pod Security admission rejects the pods", Critical, "Pods violate the namespace's Pod Security level and are rejected; each violation is quoted.", "The FailedCreate event and the namespace's pod-security labels."},
	{"KD173", "Admission webhook rejects the pods", Critical, "An admission webhook denies the controller's pods.", "The FailedCreate event naming the webhook."},
	{"KD179", "Controller cannot create pods", Critical, "A controller's FailedCreate event for a reason KD170-KD173 do not cover.", "The FailedCreate event."},
	{"KD180", "Job failed", Critical, "A Job failed (backoff limit or deadline) and no pod is left to show why.", "The Job's Failed condition."},
	{"KD181", "Deployment rollout stalled", Warning, "A Deployment passed its progress deadline and no pod finding explains it.", "The Progressing condition with ProgressDeadlineExceeded."},
	{"KD190", "Node is not ready", Critical, "A node's Ready condition is False or Unknown; the pods on it are listed.", "The node's Ready condition."},
	{"KD191", "Node is under pressure", Warning, "A node reports MemoryPressure, DiskPressure, PIDPressure or NetworkUnavailable.", "The node's condition."},
	{"KD192", "Pod was evicted", Warning, "The kubelet evicted a pod, usually for node pressure.", "The pod's Evicted status and message."},
}

// RuleByID finds a rule.
func RuleByID(id string) (Rule, bool) {
	for _, r := range Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
