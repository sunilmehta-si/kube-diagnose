package diagnose

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// problem is what is wrong with one pod. Problems of pods with the same owner and the same cause become one finding.
type problem struct {
	rule, title string
	severity    Severity
	pod         kube.Pod
	container   string
	cause       string
	key         string // groups pods with the same cause: no pod names in it
	evidence    []Evidence
	fix         string
	// linkTo is set when the root cause is another object (a pending PVC): the pod joins that object's finding.
	linkTo *kube.Ref
}

// podProblem returns the first thing wrong with a pod, checking in the order a pod starts: scheduling, volumes and
// configuration, image, process, probes. A later stage's symptoms are caused by an earlier one, so the first
// failure is the root cause.
func podProblem(ix *index, p kube.Pod) *problem {
	if p.Metadata.DeletionTimestamp != nil || p.Status.Phase == "Succeeded" {
		return nil
	}
	if p.Status.Reason == "Evicted" {
		return evicted(p)
	}
	if c, ok := kube.FindCondition(p.Status.Conditions, "PodScheduled"); ok && c.Status == "False" {
		if c.Reason == "SchedulingGated" {
			return gated(ix, p)
		}
		return unschedulable(ix, p, c)
	}
	if pr := unclaimed(ix, p); pr != nil {
		return pr
	}
	if pr := mountProblem(ix, p); pr != nil {
		return pr
	}
	if pr := sandboxProblem(ix, p); pr != nil {
		return pr
	}
	statuses := append(append([]kube.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
	for _, cs := range statuses {
		if pr := containerProblem(ix, p, cs); pr != nil {
			return pr
		}
	}
	for _, cs := range p.Status.InitContainerStatuses {
		if pr := initStuck(ix, p, cs); pr != nil {
			return pr
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if pr := probeProblem(ix, p, cs); pr != nil {
			return pr
		}
	}
	return nil
}

// unclaimedAfter is how long a pod may wait before a scheduler that never looked at it is reported.
const unclaimedAfter = 2 * time.Minute

// unclaimed finds a pod that no scheduler has looked at: Pending, on no node, with no PodScheduled condition, and
// asking for a scheduler other than the default. That scheduler is not running or does not watch the namespace.
func unclaimed(ix *index, p kube.Pod) *problem {
	name := p.Spec.SchedulerName
	if p.Status.Phase != "Pending" || p.Spec.NodeName != "" || name == "" || name == "default-scheduler" {
		return nil
	}
	if _, ok := kube.FindCondition(p.Status.Conditions, "PodScheduled"); ok {
		return nil
	}
	age := ix.s.CollectedAt.Sub(p.Metadata.CreationTimestamp)
	if p.Metadata.CreationTimestamp.IsZero() || age < unclaimedAfter {
		return nil
	}
	return newProblem(p, "", "KD148", "Pod waits for a scheduler that is not running", Critical,
		fmt.Sprintf("the pod asks for scheduler %s and no scheduler has looked at it in %s; %s is not running, or does not handle this namespace", name, age.Round(time.Minute), name),
		"scheduler|"+name, fmt.Sprintf("Install or start %s (and check its logs and the namespaces it watches), or remove schedulerName to use the default scheduler.", name),
		Evidence{Object: p.Ref(), What: "pod asks for scheduler " + name + " and has no PodScheduled condition",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.schedulerName}{\"\\n\"}{.status.conditions}")},
		Evidence{Object: kube.Ref{Kind: "Pod", Name: "*"}, What: "scheduler pods in the cluster",
			Command: "kubectl get pods -A -o wide | grep -i sched"})
}

// initStuckAfter is how long an init container may run before it is reported as never finishing.
const initStuckAfter = 2 * time.Minute

// initStuck finds an init container that is still running long after it started, holding the pod in Init. Init
// containers that wait for a dependency loop until it appears, so the log usually names what is missing.
func initStuck(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	if p.Status.Phase != "Pending" || cs.State.Running == nil || cs.State.Running.StartedAt.IsZero() {
		return nil
	}
	if isSidecar(p, cs.Name) {
		return nil // a sidecar is meant to keep running; the init container after it is the one that holds the pod
	}
	ran := ix.s.CollectedAt.Sub(cs.State.Running.StartedAt)
	if ran < initStuckAfter {
		return nil
	}
	ev := []Evidence{{Object: p.Ref(), What: fmt.Sprintf("init container %s has been running since %s", cs.Name, cs.State.Running.StartedAt.UTC().Format(time.RFC3339)),
		Command: cmdContainerState(p, cs.Name, "state")}}
	cause := fmt.Sprintf("init container %s has run for %s without finishing, so the pod's app containers have not started", cs.Name, ran.Round(time.Minute))
	if log, ok := ix.logs[logKey{p.Metadata.Namespace, p.Metadata.Name, cs.Name}]; ok && len(log.Lines) > 0 {
		ev = append(ev, logEvidence(p, cs.Name, log))
		cause += fmt.Sprintf("; its log says: %q", errorLine(log.Lines))
	}
	fix := "Make what the init container waits for available (its log names it), or fix the check it loops on; the app containers start only after every init container exits 0."
	if svcNS, svc, _, ok := ix.missingService(p.Metadata.Namespace, ix.logs[logKey{p.Metadata.Namespace, p.Metadata.Name, cs.Name}].Lines); ok {
		cause += fmt.Sprintf("; it waits for %s, and there is no Service %s in namespace %s", svc, svc, svcNS)
		fix = fmt.Sprintf("Create Service %s in namespace %s (or deploy what it fronts), or correct the host name the init container waits for.", svc, svcNS)
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Service", Namespace: svcNS, Name: svc},
			What: fmt.Sprintf("there is no Service %s in namespace %s", svc, svcNS), Command: cmdGet("service", svcNS, svc, "")})
	}
	return newProblem(p, cs.Name, "KD119", "Init container never finishes", Critical, cause, "initstuck", fix, ev...)
}

func containerProblem(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	if w := cs.State.Waiting; w != nil {
		switch w.Reason {
		case "ErrImagePull", "ImagePullBackOff":
			return imagePull(ix, p, cs)
		case "ErrImageNeverPull":
			image := imageOf(p, cs)
			node := p.Spec.NodeName
			if node == "" {
				node = "its node"
			}
			return newProblem(p, cs.Name, "KD108", "Image is not on the node and may not be pulled", Critical,
				fmt.Sprintf("container %s's image %s is not on %s, and its imagePullPolicy is Never, so the kubelet will not pull it", cs.Name, image, node),
				"neverpull|"+image, "Load the image onto every node that may run the pod (kind load docker-image, or pre-pull it), or set imagePullPolicy to IfNotPresent so the kubelet pulls it.",
				waitingEvidence(p, cs), Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s has imagePullPolicy Never", cs.Name),
					Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].imagePullPolicy}`, cs.Name))})
		case "InvalidImageName":
			return newProblem(p, cs.Name, "KD104", "Image reference is invalid", Critical,
				fmt.Sprintf("container %s has image %q, which is not a valid image reference", cs.Name, imageOf(p, cs)),
				"invalid|"+imageOf(p, cs), "Fix the image field: registry/repository:tag or @sha256:digest.",
				waitingEvidence(p, cs))
		case "CreateContainerConfigError":
			return configError(ix, p, cs)
		case "CreateContainerError", "RunContainerError":
			if pr := startError(ix, p, cs, w.Message); pr != nil {
				return pr
			}
		case "CrashLoopBackOff":
			return crash(ix, p, cs)
		}
	}
	if t := cs.State.Terminated; t != nil && t.Reason == "StartError" {
		if pr := startError(ix, p, cs, t.Message); pr != nil {
			return pr
		}
	}
	// Exited just now: a Job's pod that failed, or a container caught between its exit and the kubelet's back-off,
	// before the state reads CrashLoopBackOff.
	if t := cs.State.Terminated; t != nil && (t.ExitCode != 0 || t.Reason == "OOMKilled") && (p.Status.Phase == "Failed" || cs.RestartCount > 0) {
		return crash(ix, p, cs)
	}
	// Running now, but killed before: out of memory or by its liveness probe, again and again.
	if lt := cs.LastTerminationState.Terminated; lt != nil && cs.RestartCount > 0 && cs.State.Running != nil {
		if lt.Reason == "OOMKilled" {
			pr := oomKilled(ix, p, cs)
			pr.severity = Warning
			return pr
		}
		if probeKilled(ix, p, cs.Name) != nil {
			pr := livenessKilled(ix, p, cs)
			pr.severity = Warning
			return pr
		}
		// Caught in the moment between two crashes: the container runs, but it has exited non-zero and been
		// restarted again and again.
		if cs.RestartCount >= 2 && (lt.ExitCode != 0 || lt.Reason == "Completed") {
			return crash(ix, p, cs)
		}
	}
	return nil
}

func newProblem(p kube.Pod, container, rule, title string, sev Severity, cause, key, fix string, ev ...Evidence) *problem {
	return &problem{rule: rule, title: title, severity: sev, pod: p, container: container, cause: cause,
		key: rule + "|" + container + "|" + key, evidence: ev, fix: fix}
}

func imageOf(p kube.Pod, cs kube.ContainerStatus) string {
	if c, ok := containerSpec(p, cs.Name); ok {
		return c.Image
	}
	return cs.Image
}

func waitingEvidence(p kube.Pod, cs kube.ContainerStatus) Evidence {
	what := fmt.Sprintf("container %s is waiting: %s", cs.Name, cs.State.Waiting.Reason)
	return Evidence{Object: p.Ref(), What: what, Detail: cs.State.Waiting.Message, Command: cmdContainerState(p, cs.Name, "state.waiting")}
}

func eventEvidence(r kube.Ref, e kube.Event) Evidence {
	what := fmt.Sprintf("event %s", e.Reason)
	if n := e.Times(); n > 1 {
		what += fmt.Sprintf(" (%d times)", n)
	}
	return Evidence{Object: r, What: what, Detail: e.Message, Command: cmdEvents(r)}
}

// ---- image pulls ----

var (
	reNotFound  = regexp.MustCompile(`(?i)\bnot found\b|manifest unknown|NotFound|no such manifest|name unknown`)
	reDenied    = regexp.MustCompile(`(?i)unauthorized|authentication required|access denied|denied:|insufficient_scope|\b40[13]\b|forbidden`)
	reRateLimit = regexp.MustCompile(`(?i)toomanyrequests|429 too many requests|pull rate limit`)
	rePlatform  = regexp.MustCompile(`(?i)no match for platform in manifest|no matching manifest for|does not provide the specified platform`)
	reNetwork   = regexp.MustCompile(`(?i)no such host|i/o timeout|connection refused|tls handshake timeout|context deadline exceeded|network is unreachable|dial tcp`)
)

func imagePull(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	image := imageOf(p, cs)
	ev := []Evidence{waitingEvidence(p, cs)}
	msg := cs.State.Waiting.Message
	for _, e := range ix.eventsFor(p.Ref(), "Failed") {
		if strings.Contains(e.Message, image) || strings.Contains(e.Message, "pull") {
			ev = append(ev, eventEvidence(p.Ref(), e))
			msg = e.Message + " " + msg
			break
		}
	}
	switch {
	case reRateLimit.MatchString(msg):
		return newProblem(p, cs.Name, "KD105", "Registry rate-limits the image pull", Critical,
			fmt.Sprintf("the registry is rate-limiting pulls of image %s (it answered 429 Too Many Requests)", image), "ratelimit|"+registry(image),
			"Pull with credentials (an account raises the limit; list a docker-registry Secret in imagePullSecrets), or mirror the image to a registry you control.", ev...)
	case rePlatform.MatchString(msg):
		arch := "the node's architecture"
		for _, n := range ix.s.Nodes {
			if n.Metadata.Name == p.Spec.NodeName && n.Metadata.Labels["kubernetes.io/arch"] != "" {
				arch = n.Metadata.Labels["kubernetes.io/os"] + "/" + n.Metadata.Labels["kubernetes.io/arch"]
			}
		}
		return newProblem(p, cs.Name, "KD109", "Image has no build for the node's platform", Critical,
			fmt.Sprintf("image %s exists, but has no build for %s, so the node cannot pull it", image, arch), "platform|"+image,
			"Use a multi-architecture image that includes the node's platform, or schedule the pod onto nodes it was built for (a nodeSelector on kubernetes.io/arch).", ev...)
	case reNetwork.MatchString(msg) && !reNotFound.MatchString(msg):
		return newProblem(p, cs.Name, "KD103", "Registry cannot be reached", Critical,
			fmt.Sprintf("the node cannot reach the registry for image %s", image), "net|"+registry(image),
			"Check the registry host name in the image, and that nodes can resolve and reach it (DNS, egress, proxy).", ev...)
	case reDenied.MatchString(msg):
		if pr := pullSecretProblem(ix, p, cs, image, ev); pr != nil {
			return pr
		}
		cause := fmt.Sprintf("the registry refused to serve image %s (%s)", image, deniedReason(msg))
		if strings.Contains(strings.ToLower(msg), "does not exist") {
			cause = fmt.Sprintf("image %s does not exist, or it is private and the pod has no credentials for it (%s)", image, deniedReason(msg))
		}
		fix := "Check the repository name; if it is private, create a docker-registry Secret and list it in imagePullSecrets."
		if len(p.Spec.ImagePullSecrets) > 0 {
			fix = "Check the repository name and that the imagePullSecrets hold valid credentials for this registry."
		}
		return newProblem(p, cs.Name, "KD102", "Registry refused the image pull", Critical, cause, "denied|"+image, fix, ev...)
	case reNotFound.MatchString(msg):
		return newProblem(p, cs.Name, "KD101", "Image does not exist", Critical,
			fmt.Sprintf("image %s does not exist in its registry (the tag or digest is not there)", image), "notfound|"+image,
			"Correct the image tag or digest, or push that tag to the registry.", ev...)
	}
	return newProblem(p, cs.Name, "KD100", "Image cannot be pulled", Critical,
		fmt.Sprintf("image %s cannot be pulled", image), "pull|"+image,
		"Read the pull error in the evidence; the node's container runtime reported it.", ev...)
}

// pullSecretProblem finds an imagePullSecrets entry that names a Secret that does not exist, the usual reason a
// registry refuses a pod that was meant to have credentials.
func pullSecretProblem(ix *index, p kube.Pod, cs kube.ContainerStatus, image string, ev []Evidence) *problem {
	if !ix.read("secrets") {
		return nil
	}
	ns := p.Metadata.Namespace
	for _, ref := range p.Spec.ImagePullSecrets {
		if sec, ok := ix.secrets[nsName{ns, ref.Name}]; ok {
			if sec.Type == "kubernetes.io/dockerconfigjson" || sec.Type == "kubernetes.io/dockercfg" {
				continue
			}
			// The kubelet reads registry credentials only from these two Secret types and skips any other.
			ev = append(ev, Evidence{Object: kube.Ref{Kind: "Secret", Namespace: ns, Name: ref.Name},
				What:    fmt.Sprintf("Secret %s has type %s and keys %s", ref.Name, sec.Type, strings.Join(sec.Keys, ", ")),
				Command: cmdGet("secret", ns, ref.Name, "{.type}")})
			return newProblem(p, cs.Name, "KD107", "Image pull secret has the wrong type", Critical,
				fmt.Sprintf("imagePullSecret %s has type %s; the kubelet reads registry credentials only from kubernetes.io/dockerconfigjson Secrets, so image %s was pulled without them", ref.Name, sec.Type, image),
				"pullsecrettype|"+ref.Name, fmt.Sprintf("Recreate %s with kubectl create secret docker-registry, which sets the type and the .dockerconfigjson key.", ref.Name), ev...)
		}
		for _, e := range ix.eventsFor(p.Ref(), "FailedToRetrieveImagePullSecret") {
			ev = append(ev, eventEvidence(p.Ref(), e))
			break
		}
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Secret", Namespace: ns, Name: ref.Name},
			What: fmt.Sprintf("there is no Secret %s in namespace %s", ref.Name, ns), Command: cmdGet("secret", ns, ref.Name, "")})
		return newProblem(p, cs.Name, "KD106", "Image pull secret does not exist", Critical,
			fmt.Sprintf("the pod pulls image %s with imagePullSecret %s, which does not exist in namespace %s, so the registry sees no credentials", image, ref.Name, ns),
			"pullsecret|"+ref.Name, fmt.Sprintf("Create the docker-registry Secret %s in namespace %s (kubectl create secret docker-registry), or correct imagePullSecrets.", ref.Name, ns), ev...)
	}
	return nil
}

// deniedReason quotes how the registry refused, most specific first.
func deniedReason(msg string) string {
	low := strings.ToLower(msg)
	for _, s := range []string{"pull access denied", "403 forbidden", "401 unauthorized", "insufficient_scope", "unauthorized", "access denied", "denied", "403", "401", "forbidden"} {
		if strings.Contains(low, s) {
			return "it answered " + s
		}
	}
	return "it refused access"
}

func registry(image string) string {
	if i := strings.Index(image, "/"); i > 0 && strings.ContainsAny(image[:i], ".:") {
		return image[:i]
	}
	return "docker.io"
}

// ---- configuration ----

var (
	reMissingObject  = regexp.MustCompile(`(configmap|secret) "([^"]+)" not found`)
	reNonNumericUser = regexp.MustCompile(`image has non-numeric user \(([^)]+)\)`)
	reMissingKey     = regexp.MustCompile(`couldn't find key (\S+) in (ConfigMap|Secret) ([^/\s]+)/(\S+)`)
)

func configError(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	msg := cs.State.Waiting.Message
	ev := []Evidence{waitingEvidence(p, cs)}
	if m := reMissingKey.FindStringSubmatch(msg); m != nil {
		return missingKey(ix, p, cs.Name, m[2], m[4], m[1], ev)
	}
	if strings.Contains(msg, "container has runAsNonRoot and image") {
		image := imageOf(p, cs)
		cause := fmt.Sprintf("container %s must run as a non-root user (runAsNonRoot), but image %s runs as root", cs.Name, image)
		fix := "Set securityContext.runAsUser to a non-zero UID the image supports, or use an image built to run as a non-root user."
		if m := reNonNumericUser.FindStringSubmatch(msg); m != nil {
			cause = fmt.Sprintf("container %s must run as a non-root user (runAsNonRoot), and image %s names its user %q, which the kubelet cannot check is not root", cs.Name, image, m[1])
			fix = fmt.Sprintf("Set securityContext.runAsUser to the numeric UID of %s, or build the image with USER set to a number.", m[1])
		}
		return newProblem(p, cs.Name, "KD117", "Image runs as root but the pod requires non-root", Critical, cause, "nonroot|"+image, fix, ev...)
	}
	if m := reMissingObject.FindStringSubmatch(msg); m != nil {
		return missingObject(ix, p, cs.Name, m[1], m[2], ev)
	}
	// The message names only the first missing reference; check the spec for one we can prove is missing.
	if c, ok := containerSpec(p, cs.Name); ok {
		for _, ref := range envRefs(c) {
			if pr := checkRef(ix, p, cs.Name, ref, ev); pr != nil {
				return pr
			}
		}
	}
	return newProblem(p, cs.Name, "KD139", "Container configuration is invalid", Critical,
		fmt.Sprintf("container %s cannot be created: %s", cs.Name, msg), "config|"+msg,
		"Read the error in the evidence and fix the container's env, envFrom or volume references.", ev...)
}

type envRef struct {
	kind, name, key string // kind is "configmap" or "secret"; key empty for envFrom
	optional        bool
}

func envRefs(c kube.Container) []envRef {
	var out []envRef
	opt := func(b *bool) bool { return b != nil && *b }
	for _, e := range c.EnvFrom {
		if e.ConfigMapRef != nil {
			out = append(out, envRef{"configmap", e.ConfigMapRef.Name, "", opt(e.ConfigMapRef.Optional)})
		}
		if e.SecretRef != nil {
			out = append(out, envRef{"secret", e.SecretRef.Name, "", opt(e.SecretRef.Optional)})
		}
	}
	for _, e := range c.Env {
		if e.ValueFrom == nil {
			continue
		}
		if r := e.ValueFrom.ConfigMapKeyRef; r != nil {
			out = append(out, envRef{"configmap", r.Name, r.Key, opt(r.Optional)})
		}
		if r := e.ValueFrom.SecretKeyRef; r != nil {
			out = append(out, envRef{"secret", r.Name, r.Key, opt(r.Optional)})
		}
	}
	return out
}

func (ix *index) keySet(kind, ns, name string) (kube.KeySet, bool, bool) {
	resource := kind + "s"
	if !ix.read(resource) {
		return kube.KeySet{}, false, false
	}
	m := ix.configMaps
	if kind == "secret" {
		m = ix.secrets
	}
	k, ok := m[nsName{ns, name}]
	return k, ok, true
}

func checkRef(ix *index, p kube.Pod, container string, r envRef, ev []Evidence) *problem {
	if r.optional {
		return nil
	}
	ks, exists, known := ix.keySet(r.kind, p.Metadata.Namespace, r.name)
	if !known {
		return nil
	}
	if !exists {
		return missingObject(ix, p, container, r.kind, r.name, ev)
	}
	if r.key != "" && !ks.Has(r.key) {
		return missingKey(ix, p, container, kindName(r.kind), r.name, r.key, ev)
	}
	return nil
}

func kindName(k string) string {
	if strings.EqualFold(k, "secret") {
		return "Secret"
	}
	return "ConfigMap"
}

func missingObject(ix *index, p kube.Pod, container, kind, name string, ev []Evidence) *problem {
	k := kindName(kind)
	rule, title := "KD130", "ConfigMap does not exist"
	if k == "Secret" {
		rule, title = "KD131", "Secret does not exist"
	}
	ns := p.Metadata.Namespace
	if _, exists, known := ix.keySet(strings.ToLower(k), ns, name); known && !exists {
		ev = append(ev, Evidence{Object: kube.Ref{Kind: k, Namespace: ns, Name: name},
			What: fmt.Sprintf("there is no %s %s in namespace %s", k, name, ns), Command: cmdGet(k, ns, name, "")})
	}
	return newProblem(p, container, rule, title, Critical,
		fmt.Sprintf("container %s needs %s %s, which does not exist in namespace %s", container, k, name, ns),
		k+"|"+name, fmt.Sprintf("Create %s %s in namespace %s, or correct the name the pod refers to.", k, name, ns), ev...)
}

func missingKey(ix *index, p kube.Pod, container, kind, name, key string, ev []Evidence) *problem {
	k := kindName(kind)
	ns := p.Metadata.Namespace
	if ks, exists, _ := ix.keySet(strings.ToLower(k), ns, name); exists {
		have := "no keys"
		if len(ks.Keys) > 0 {
			have = "keys " + strings.Join(ks.Keys, ", ")
		}
		ev = append(ev, Evidence{Object: kube.Ref{Kind: k, Namespace: ns, Name: name},
			What: fmt.Sprintf("%s %s has %s, not %s", k, name, have, key),
			Command: fmt.Sprintf("kubectl get %s %s -n %s -o go-template=%s", strings.ToLower(k), name, ns,
				shq(`{{range $k, $v := .data}}{{$k}}{{"\n"}}{{end}}`))})
	}
	return newProblem(p, container, "KD132", "Key missing from "+k, Critical,
		fmt.Sprintf("container %s reads key %s from %s %s, which has no such key", container, key, k, name),
		k+"|"+name+"|"+key, fmt.Sprintf("Add key %s to %s %s, or correct the key name in the pod spec.", key, k, name), ev...)
}

var (
	reMultiAttach = regexp.MustCompile(`Multi-Attach error for volume "([^"]+)"(?: Volume is already used by pod\(s\) ([^\s,]+))?`)
	reMountCM     = regexp.MustCompile(`configmap "([^"]+)" not found`)
	reMountSecret = regexp.MustCompile(`secret "([^"]+)" not found`)
	reMountKey    = regexp.MustCompile(`references non-existent (config|secret) key: (\S+)`)
)

// mountProblem finds a pod stuck creating its containers because a volume cannot be mounted.
func mountProblem(ix *index, p kube.Pod) *problem {
	if p.Status.Phase != "Pending" {
		return nil
	}
	for _, e := range ix.eventsFor(p.Ref(), "FailedAttachVolume") {
		m := reMultiAttach.FindStringSubmatch(e.Message)
		if m == nil {
			continue
		}
		cause := fmt.Sprintf("volume %s can be attached to one node at a time and is still attached elsewhere", m[1])
		if m[2] != "" {
			cause = fmt.Sprintf("volume %s can be attached to one node at a time and is still in use by pod %s on another node", m[1], m[2])
		}
		return newProblem(p, "", "KD155", "Volume is attached to another node", Critical, cause, "multiattach|"+m[1],
			"Let the other pod stop first (use the Recreate strategy for single-replica Deployments with ReadWriteOnce volumes, or a StatefulSet), or use a ReadWriteMany volume. If the other node is gone, check its VolumeAttachment.",
			eventEvidence(p.Ref(), e), Evidence{Object: kube.Ref{Kind: "VolumeAttachment", Name: "*"}, What: "volume attachments",
				Command: "kubectl get volumeattachments"})
	}
	for _, e := range ix.eventsFor(p.Ref(), "FailedMount") {
		ev := []Evidence{eventEvidence(p.Ref(), e)}
		if m := reMountCM.FindStringSubmatch(e.Message); m != nil {
			pr := missingObject(ix, p, "", "configmap", m[1], ev)
			pr.cause = fmt.Sprintf("a volume of the pod needs ConfigMap %s, which does not exist in namespace %s", m[1], p.Metadata.Namespace)
			return pr
		}
		if m := reMountSecret.FindStringSubmatch(e.Message); m != nil {
			pr := missingObject(ix, p, "", "secret", m[1], ev)
			pr.cause = fmt.Sprintf("a volume of the pod needs Secret %s, which does not exist in namespace %s", m[1], p.Metadata.Namespace)
			return pr
		}
		if m := reMountKey.FindStringSubmatch(e.Message); m != nil {
			kind, name := volumeSourceFor(p, m[1], m[2])
			if name != "" {
				return missingKey(ix, p, "", kind, name, m[2], ev)
			}
		}
		return newProblem(p, "", "KD133", "Volume cannot be mounted", Critical,
			"a volume of the pod cannot be mounted: "+e.Message, "mount|"+e.Message,
			"Read the mount error in the evidence; it names the volume and why it failed.", ev...)
	}
	return nil
}

// volumeSourceFor finds which ConfigMap or Secret volume lists the missing key.
func volumeSourceFor(p kube.Pod, kind, key string) (string, string) {
	for _, v := range p.Spec.Volumes {
		if kind == "config" && v.ConfigMap != nil {
			for _, it := range v.ConfigMap.Items {
				if it.Key == key {
					return "ConfigMap", v.ConfigMap.Name
				}
			}
		}
		if kind == "secret" && v.Secret != nil {
			for _, it := range v.Secret.Items {
				if it.Key == key {
					return "Secret", v.Secret.SecretName
				}
			}
		}
	}
	return "", ""
}

// ---- processes that do not start or keep exiting ----

var (
	reNoExec     = regexp.MustCompile(`(?i)executable file not found|no such file or directory`)
	reExecFormat = regexp.MustCompile(`(?i)exec format error`)
	reErrorLine  = regexp.MustCompile(`(?i)\b(error|fatal|panic|exception|failed|cannot|can't|unable|denied|refused|not set|missing|invalid)\b`)
)

func startError(ix *index, p kube.Pod, cs kube.ContainerStatus, msg string) *problem {
	ev := []Evidence{{Object: p.Ref(), What: fmt.Sprintf("container %s did not start", cs.Name), Detail: msg,
		Command: cmdContainerState(p, cs.Name, "state")}}
	c, _ := containerSpec(p, cs.Name)
	switch {
	case reExecFormat.MatchString(msg):
		return execFormat(p, cs, ev)
	case reNoExec.MatchString(msg):
		cmd := strings.Join(append(append([]string{}, c.Command...), c.Args...), " ")
		cause := fmt.Sprintf("container %s's command is not in image %s", cs.Name, imageOf(p, cs))
		if cmd != "" {
			cause = fmt.Sprintf("container %s runs %q, which is not in image %s", cs.Name, cmd, imageOf(p, cs))
		}
		return newProblem(p, cs.Name, "KD114", "Command not found in the image", Critical, cause, "noexec|"+cmd,
			"Correct the command (or the image's entrypoint): use a path that exists in the image.", ev...)
	}
	return nil
}

func execFormat(p kube.Pod, cs kube.ContainerStatus, ev []Evidence) *problem {
	return newProblem(p, cs.Name, "KD113", "Image built for another CPU architecture", Critical,
		fmt.Sprintf("image %s's binary cannot run on this node: exec format error, which means it was built for another CPU architecture", imageOf(p, cs)),
		"execformat|"+imageOf(p, cs), "Use a multi-architecture image, or one built for the node's architecture (kubernetes.io/arch).", ev...)
}

func crash(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	t := lastExit(cs)
	if t == nil {
		return newProblem(p, cs.Name, "KD110", "Container keeps crashing", Critical,
			fmt.Sprintf("container %s keeps crashing", cs.Name), "crash|?", "Read the container's logs.", waitingEvidence(p, cs))
	}
	if t.Reason == "OOMKilled" {
		return oomKilled(ix, p, cs)
	}
	log := ix.logs[logKey{p.Metadata.Namespace, p.Metadata.Name, cs.Name}]
	if t.Reason == "StartError" || t.ExitCode == 128 {
		if pr := startError(ix, p, cs, t.Message); pr != nil {
			return pr
		}
	}
	for _, l := range log.Lines {
		if reExecFormat.MatchString(l) {
			return execFormat(p, cs, append([]Evidence{terminatedEvidence(p, cs, t)}, logEvidence(p, cs.Name, log)))
		}
	}
	if pr := hookFailed(ix, p, cs); pr != nil {
		return pr
	}
	if (t.ExitCode == 137 || t.ExitCode == 143) && probeKilled(ix, p, cs.Name) != nil {
		return livenessKilled(ix, p, cs)
	}
	ev := []Evidence{terminatedEvidence(p, cs, t)}
	if len(log.Lines) > 0 {
		ev = append(ev, logEvidence(p, cs.Name, log))
	}
	if pr := readOnlyRoot(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := portInUse(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := dnsBlocked(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := refusedByEmptyService(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := tokenNotMounted(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if svcNS, svc, line, ok := ix.missingService(p.Metadata.Namespace, log.Lines); ok {
		return newProblem(p, cs.Name, "KD121", "Container looks up a Service that does not exist", Critical,
			fmt.Sprintf("container %s exits because it cannot resolve %s: there is no Service %s in namespace %s; its log says: %q", cs.Name, svc, svc, svcNS, clip(line, 200)),
			"nosvc|"+svcNS+"/"+svc, fmt.Sprintf("Create Service %s in namespace %s (or deploy what it fronts), or correct the host name the app connects to in its configuration.", svc, svcNS),
			append(ev, Evidence{Object: kube.Ref{Kind: "Service", Namespace: svcNS, Name: svc},
				What: fmt.Sprintf("there is no Service %s in namespace %s", svc, svcNS), Command: cmdGet("service", svcNS, svc, "")})...)
	}
	title, rule := "Container keeps crashing", "KD110"
	what, kind := "exits", "container"
	sidecar := isSidecar(p, cs.Name)
	if isInit(p, cs.Name) && !sidecar {
		title, rule = "Init container fails", "KD115"
	}
	if sidecar {
		kind = "sidecar container"
	}
	if p.Status.Phase == "Failed" {
		title = "Container fails"
		what = "exited"
	}
	cause := fmt.Sprintf("%s %s %s with code %d (%s)", kind, cs.Name, what, t.ExitCode, exitMeaning(t.ExitCode))
	if line := errorLine(log.Lines); line != "" {
		cause += fmt.Sprintf("; its log says: %q", line)
	}
	fix := "Fix what the log reports; the process exits on its own, so the cause is in the app or its configuration."
	switch t.ExitCode {
	case 0:
		cause = fmt.Sprintf("container %s's process finishes with code 0, and the pod restarts it because a long-running container is expected", cs.Name)
		fix = "Run a process that keeps running (a server or loop), or run this work as a Job instead of a Deployment."
	case 127:
		fix = "The command or something it calls is not in the image: check the command, args and PATH."
	case 126:
		fix = "The command is not executable: check its file mode and that it is a binary or script for this image."
	case 137:
		fix = "Something sent SIGKILL: check memory limits and the node's events, and whether the process ignores SIGTERM."
	}
	if isInit(p, cs.Name) {
		fix = "Fix what the init container's log reports; the app containers start only after every init container succeeds."
	}
	if sidecar {
		fix = "Fix what the sidecar's log reports; it is an init container with restartPolicy: Always, so the kubelet restarts it for as long as the pod runs."
	}
	return newProblem(p, cs.Name, rule, title, Critical, cause, "exit|"+strconv.Itoa(int(t.ExitCode)), fix, ev...)
}

// lastExit is the container's most recent termination: the current state when it has just exited, else the last
// one recorded.
func lastExit(cs kube.ContainerStatus) *kube.ContainerStateTerminated {
	if cs.State.Terminated != nil {
		return cs.State.Terminated
	}
	return cs.LastTerminationState.Terminated
}

func terminatedEvidence(p kube.Pod, cs kube.ContainerStatus, t *kube.ContainerStateTerminated) Evidence {
	what := fmt.Sprintf("container %s exited with code %d", cs.Name, t.ExitCode)
	if t.Reason != "" {
		what += " (" + t.Reason + ")"
	}
	if cs.RestartCount > 0 {
		what += fmt.Sprintf(", restarted %d times", cs.RestartCount)
	}
	field := "lastState.terminated"
	if cs.State.Terminated != nil {
		field = "state.terminated"
	}
	return Evidence{Object: p.Ref(), What: what, Detail: t.Message, Command: cmdContainerState(p, cs.Name, field)}
}

// logEvidence quotes the end of a container's log: the line that reads like the error, and the lines before it.
func logEvidence(p kube.Pod, container string, l snapshot.Log) Evidence {
	lines := l.Lines
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	run := "current run"
	if l.Previous {
		run = "run that exited"
	}
	return Evidence{Object: p.Ref(), What: fmt.Sprintf("last lines of container %s's log (%s)", container, run),
		Detail: strings.Join(lines, "\n"), Command: cmdLogs(p, container, l.Previous)}
}

var reReadOnlyPath = regexp.MustCompile(`(?i)['"]?(/[^'":\s]*)['"]?:?(?: [^:]*)?: read-only file system`)

// readOnlyRoot finds a container with a read-only root filesystem that exits because it writes to it.
func readOnlyRoot(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, _ := containerSpec(p, cs.Name)
	if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		return nil
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.Contains(strings.ToLower(lines[i]), "read-only file system") {
			continue
		}
		path := ""
		if m := reReadOnlyPath.FindStringSubmatch(lines[i]); m != nil {
			path = m[1]
		}
		cause := fmt.Sprintf("container %s has a read-only root filesystem and exits because it writes to it: %q", cs.Name, clip(lines[i], 160))
		fix := "Mount a writable volume (an emptyDir) at the directory the container writes to, or point the app at one."
		if path != "" {
			fix = fmt.Sprintf("Mount an emptyDir at %s (or its parent directory), or point the app at a writable volume.", path)
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s sets readOnlyRootFilesystem: true", cs.Name),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].securityContext}`, cs.Name))})
		return newProblem(p, cs.Name, "KD118", "Container writes to its read-only root filesystem", Critical, cause, "readonly|"+path, fix, ev...)
	}
	return nil
}

var reAddrInUse = regexp.MustCompile(`(?i)address already in use|address in use|EADDRINUSE`)

// portInUse finds a container that exits because the port it binds is taken. Containers in a pod share one network
// namespace, so the usual cause is another container of the same pod on the same port.
func portInUse(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	line := ""
	for i := len(lines) - 1; i >= 0 && line == ""; i-- {
		if reAddrInUse.MatchString(lines[i]) {
			line = lines[i]
		}
	}
	if line == "" {
		return nil
	}
	c, _ := containerSpec(p, cs.Name)
	cause := fmt.Sprintf("container %s exits because the port it listens on is already in use: %q", cs.Name, clip(line, 160))
	fix := "Make the container listen on a free port; containers in one pod share its network, so each needs its own port."
	key := "addrinuse"
	for _, other := range append(append([]kube.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
		if other.Name == cs.Name {
			continue
		}
		for _, op := range other.Ports {
			for _, cp := range c.Ports {
				if op.ContainerPort == cp.ContainerPort {
					cause = fmt.Sprintf("container %s exits because port %d is already in use: container %s of the same pod also listens on %d, and containers in a pod share one network", cs.Name, cp.ContainerPort, other.Name, cp.ContainerPort)
					fix = fmt.Sprintf("Give %s or %s another port (and update the Service's targetPort to match).", cs.Name, other.Name)
					key = fmt.Sprintf("addrinuse|%d", cp.ContainerPort)
					ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("containers %s and %s both declare port %d", cs.Name, other.Name, cp.ContainerPort),
						Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{range .spec.containers[*]}{.name}{" "}{.ports}{"\n"}{end}`)})
					return newProblem(p, cs.Name, "KD122", "Port is already in use", Critical, cause, key, fix, ev...)
				}
			}
		}
	}
	return newProblem(p, cs.Name, "KD122", "Port is already in use", Critical, cause, key, fix, ev...)
}

// hookFailed finds a container that the kubelet killed because its postStart hook failed. Such a container exits
// with 137 and crash-loops like any other, and the hook's failure is only in the pod's events.
func hookFailed(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	var ev []Evidence
	var detail string
	for _, e := range ix.eventsFor(p.Ref(), "FailedPostStartHook") {
		if !mentionsContainer(e, cs.Name) && !strings.Contains(e.Message, `Container "`+cs.Name+`"`) {
			continue
		}
		ev = append(ev, eventEvidence(p.Ref(), e))
		if detail == "" && strings.Contains(e.Message, "failed - error:") {
			detail = e.Message[strings.Index(e.Message, "failed - error:")+len("failed - error: "):]
		}
		if len(ev) == 2 {
			break
		}
	}
	if len(ev) == 0 {
		return nil
	}
	cause := fmt.Sprintf("container %s's postStart hook fails, so the kubelet kills the container each time it starts", cs.Name)
	if c, ok := containerSpec(p, cs.Name); ok && c.Lifecycle != nil && c.Lifecycle.PostStart != nil {
		if h := c.Lifecycle.PostStart; h.Exec != nil {
			cause = fmt.Sprintf("container %s's postStart hook (%s) fails, so the kubelet kills the container each time it starts", cs.Name, strings.Join(h.Exec.Command, " "))
		} else if h.HTTPGet != nil {
			cause = fmt.Sprintf("container %s's postStart hook (GET %s on port %s) fails, so the kubelet kills the container each time it starts", cs.Name, orSlash(h.HTTPGet.Path), h.HTTPGet.Port)
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's postStart hook", cs.Name),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].lifecycle.postStart}`, cs.Name))})
	}
	if detail != "" {
		cause += ": " + clip(detail, 200)
	}
	return newProblem(p, cs.Name, "KD116", "Lifecycle hook fails", Critical, cause, "poststart|"+cs.Name,
		"Fix the postStart hook's command or HTTP target so it succeeds, or remove the hook; the container cannot run while it fails.", ev...)
}

func exitMeaning(code int32) string {
	switch {
	case code == 0:
		return "success"
	case code == 1:
		return "the app reported an error"
	case code == 2:
		return "misused shell builtin or bad arguments"
	case code == 126:
		return "command not executable"
	case code == 127:
		return "command not found"
	case code == 128:
		return "invalid exit argument"
	case code > 128 && code < 160:
		sig := code - 128
		name := map[int32]string{1: "SIGHUP", 2: "SIGINT", 6: "SIGABRT", 9: "SIGKILL", 11: "SIGSEGV", 15: "SIGTERM"}[sig]
		if name == "" {
			name = fmt.Sprintf("signal %d", sig)
		}
		return "killed by " + name
	}
	return "the app reported an error"
}

// errorLine picks the log line that most likely says why the process exited: the last line that reads like an
// error, else the last line.
func errorLine(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		if reErrorLine.MatchString(lines[i]) {
			return clip(lines[i], 200)
		}
	}
	if len(lines) > 0 {
		return clip(lines[len(lines)-1], 200)
	}
	return ""
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func oomKilled(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	t := lastExit(cs)
	c, _ := containerSpec(p, cs.Name)
	limit := c.Resources.Limits["memory"]
	cause := fmt.Sprintf("container %s uses more memory than its limit and is killed (OOMKilled)", cs.Name)
	ev := []Evidence{terminatedEvidence(p, cs, t)}
	if limit != "" {
		cause = fmt.Sprintf("container %s uses more than its %s memory limit and is killed (OOMKilled)", cs.Name, limit)
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s has memory limit %s", cs.Name, limit),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name,
				fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].resources.limits.memory}`, cs.Name))})
	}
	return newProblem(p, cs.Name, "KD111", "Container runs out of memory", Critical, cause, "oom|"+limit,
		"Raise the container's memory limit to what it needs at peak, or reduce the app's memory use.", ev...)
}

// probeKilled returns the newest event saying the kubelet restarted the container because a probe failed.
func probeKilled(ix *index, p kube.Pod, container string) *kube.Event {
	for _, e := range ix.eventsFor(p.Ref(), "Killing", "Unhealthy") {
		m := strings.ToLower(e.Message)
		if (strings.Contains(m, "liveness probe") || strings.Contains(m, "startup probe")) &&
			(e.Reason == "Killing" || strings.Contains(m, "failed")) && mentionsContainer(e, container) {
			e := e
			return &e
		}
	}
	return nil
}

func mentionsContainer(e kube.Event, container string) bool {
	return e.InvolvedObject.FieldPath == "" || strings.Contains(e.InvolvedObject.FieldPath, "{"+container+"}") ||
		strings.Contains(e.Message, "Container "+container+" ")
}

func livenessKilled(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	c, _ := containerSpec(p, cs.Name)
	probe, kind := c.LivenessProbe, "liveness"
	if probe == nil && c.StartupProbe != nil {
		probe, kind = c.StartupProbe, "startup"
	}
	var ev []Evidence
	for _, e := range ix.eventsFor(p.Ref(), "Unhealthy", "Killing") {
		if mentionsContainer(e, cs.Name) && strings.Contains(strings.ToLower(e.Message), "probe") {
			ev = append(ev, eventEvidence(p.Ref(), e))
			if len(ev) == 2 {
				break
			}
		}
	}
	cause := fmt.Sprintf("container %s fails its %s probe, so the kubelet restarts it (%d restarts)", cs.Name, kind, cs.RestartCount)
	if d := describeProbe(c, probe); d != "" {
		cause = fmt.Sprintf("container %s fails its %s probe (%s), so the kubelet restarts it (%d restarts)", cs.Name, kind, d, cs.RestartCount)
	}
	fix := "Point the probe at a port and path the app serves, or give it a startupProbe or longer initialDelaySeconds if it starts slowly."
	if exe := probeExecMissing(ix, p, cs.Name, kind); exe != "" {
		cause = fmt.Sprintf("container %s's %s probe runs %s, which is not in image %s, so the probe can never pass and the kubelet restarts the container (%d restarts)", cs.Name, kind, exe, imageOf(p, cs), cs.RestartCount)
		fix = probeExecFix(exe)
	}
	return newProblem(p, cs.Name, "KD112", "Liveness probe kills the container", Critical, cause, "probe|"+describeProbe(c, probe), fix, ev...)
}

// reProbeNoExec matches the kubelet's report that an exec probe's command does not exist in the container.
var reProbeNoExec = regexp.MustCompile(`exec: "([^"]+)": executable file not found|exec: "([^"]+)": stat [^:]+: no such file or directory`)

// probeExecMissing returns the command an exec probe of the given kind ("liveness", "readiness", "startup") tried to
// run and the container does not have, from the probe's events; "" when the probe failed for another reason.
func probeExecMissing(ix *index, p kube.Pod, container, kind string) string {
	for _, e := range ix.eventsFor(p.Ref(), "Unhealthy") {
		if !mentionsContainer(e, container) || !strings.HasPrefix(strings.ToLower(e.Message), kind+" probe") {
			continue
		}
		if m := reProbeNoExec.FindStringSubmatch(e.Message); m != nil {
			return m[1] + m[2]
		}
	}
	return ""
}

func probeExecFix(exe string) string {
	return fmt.Sprintf("Use a command the image has (distroless images have no shell or curl, busybox has wget but no curl), or replace the exec probe with an httpGet or tcpSocket probe, which the kubelet runs itself and needs nothing in the image; %s is the command to replace.", exe)
}

// describeProbe says what a probe checks and, when the probe's port is not one the container declares, says so.
func describeProbe(c kube.Container, p *kube.Probe) string {
	if p == nil {
		return ""
	}
	var port kube.IntOrString
	var what string
	switch {
	case p.HTTPGet != nil:
		port, what = p.HTTPGet.Port, fmt.Sprintf("GET %s on port %s", orSlash(p.HTTPGet.Path), p.HTTPGet.Port)
	case p.TCPSocket != nil:
		port, what = p.TCPSocket.Port, fmt.Sprintf("TCP port %s", p.TCPSocket.Port)
	case p.Exec != nil:
		return "command " + strings.Join(p.Exec.Command, " ")
	default:
		return ""
	}
	if len(c.Ports) > 0 && !declaresPort(c, port) {
		var ports []string
		for _, cp := range c.Ports {
			ports = append(ports, strconv.Itoa(int(cp.ContainerPort)))
		}
		what += fmt.Sprintf(", but the container declares port %s", strings.Join(ports, ", "))
	}
	return what
}

func orSlash(s string) string {
	if s == "" {
		return "/"
	}
	return s
}

func declaresPort(c kube.Container, port kube.IntOrString) bool {
	for _, cp := range c.Ports {
		if (port.IsName && cp.Name == port.Str) || (!port.IsName && cp.ContainerPort == port.Int) {
			return true
		}
	}
	return false
}

// probeProblem finds a running container that never becomes ready because its readiness probe fails.
func probeProblem(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	if cs.Ready || cs.State.Running == nil {
		return nil
	}
	for _, e := range ix.eventsFor(p.Ref(), "Unhealthy") {
		if !mentionsContainer(e, cs.Name) || !strings.Contains(strings.ToLower(e.Message), "readiness probe") {
			continue
		}
		c, _ := containerSpec(p, cs.Name)
		cause := fmt.Sprintf("container %s runs but fails its readiness probe, so it gets no traffic", cs.Name)
		if d := describeProbe(c, c.ReadinessProbe); d != "" {
			cause = fmt.Sprintf("container %s runs but fails its readiness probe (%s), so it gets no traffic", cs.Name, d)
		}
		fix := "Point the readiness probe at a port and path the app serves, or fix what makes the app report not ready."
		if exe := probeExecMissing(ix, p, cs.Name, "readiness"); exe != "" {
			cause = fmt.Sprintf("container %s's readiness probe runs %s, which is not in image %s, so the probe can never pass and the container gets no traffic", cs.Name, exe, imageOf(p, cs))
			fix = probeExecFix(exe)
		}
		return newProblem(p, cs.Name, "KD120", "Readiness probe failing", Critical, cause, "ready|"+describeProbe(c, c.ReadinessProbe), fix,
			eventEvidence(p.Ref(), e), Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s is running but not ready", cs.Name),
				Command: cmdContainerState(p, cs.Name, "ready")})
	}
	return nil
}

var (
	reEphemeralLimit = regexp.MustCompile(`(?i)(?:Container (\S+) exceeded its local ephemeral storage limit "([^"]+)"|Pod ephemeral local storage usage exceeds the total limit of containers (\S+?)\.?\s*$)`)
	reNodeLow        = regexp.MustCompile(`The node was low on resource: ([a-z.-]+)`)
)

func evicted(p kube.Pod) *problem {
	msg := p.Status.Message
	ev := []Evidence{{Object: p.Ref(), What: "pod status is Failed, reason Evicted", Detail: msg,
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.status.message}")}}
	if m := reEphemeralLimit.FindStringSubmatch(msg); m != nil {
		cause := fmt.Sprintf("the pod was evicted for writing more to its local disk than its ephemeral-storage limit (%s)", m[3])
		if m[1] != "" {
			cause = fmt.Sprintf("container %s was evicted for writing more to its local disk than its %s ephemeral-storage limit", m[1], m[2])
		}
		return &problem{rule: "KD193", title: "Container exceeded its ephemeral storage limit", severity: Warning, pod: p,
			cause: cause, key: "KD193|" + m[1], evidence: ev,
			fix: "Raise the container's ephemeral-storage limit, or move what it writes (logs, caches, scratch files) to a volume."}
	}
	cause := "the node evicted the pod: " + msg
	if m := reNodeLow.FindStringSubmatch(msg); m != nil {
		cause = fmt.Sprintf("the node ran low on %s and evicted the pod: %s", m[1], clip(msg, 200))
	}
	return &problem{rule: "KD192", title: "Pod was evicted", severity: Warning, pod: p,
		cause: cause, key: "KD192|" + msg, evidence: ev,
		fix: "Set requests close to real use (pods over their requests are evicted first) and check the node's disk and memory pressure; delete evicted pods once handled."}
}

// sortedKeys returns a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
