package diagnose

import (
	"fmt"
	"path"
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
	if p.Metadata.DeletionTimestamp != nil {
		return terminating(ix, p)
	}
	if p.Status.Phase == "Succeeded" {
		return nil
	}
	if p.Status.Reason == "Evicted" {
		return evicted(p)
	}
	if p.Status.Phase == "Failed" && p.Status.Reason == "DeadlineExceeded" {
		return deadlineExceeded(ix, p)
	}
	if p.Status.Phase == "Failed" {
		if pr := nodeRejected(ix, p); pr != nil {
			return pr
		}
	}
	if pr := draProblem(ix, p); pr != nil {
		return pr
	}
	if pr := claimBeingDeleted(ix, p); pr != nil {
		return pr
	}
	if c, ok := kube.FindCondition(p.Status.Conditions, "PodScheduled"); ok && c.Status == "False" {
		if c.Reason == "SchedulingGated" {
			return gated(ix, p)
		}
		return unschedulable(ix, p, c)
	}
	if pr := nodeMissing(ix, p); pr != nil {
		return pr
	}
	if pr := claimWaitsForBypass(ix, p); pr != nil {
		return pr
	}
	if pr := unclaimed(ix, p); pr != nil {
		return pr
	}
	if pr := memoryInBytesMount(ix, p); pr != nil {
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
	if pr := jobHeldBySidecar(ix, p); pr != nil {
		return pr
	}
	for _, cs := range p.Status.ContainerStatuses {
		if pr := probePortMissing(ix, p, cs, "startup", "readiness"); pr != nil {
			return pr
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		if pr := probeProblem(ix, p, cs); pr != nil {
			return pr
		}
	}
	if pr := readinessGate(ix, p); pr != nil {
		return pr
	}
	for _, cs := range p.Status.ContainerStatuses {
		if pr := probeCannotRun(ix, p, cs); pr != nil {
			return pr
		}
		if pr := probePortMissing(ix, p, cs, "liveness"); pr != nil {
			return pr
		}
	}
	if p.Status.Phase == "Running" {
		if pr := resizeInfeasible(p); pr != nil {
			return pr
		}
		if pr := subdomainProblem(ix, p, nil, nil, nil); pr != nil {
			return pr
		}
		if pr := hostAliasService(ix, p, nil, nil); pr != nil {
			return pr
		}
		if pr := dnsLimits(ix, p); pr != nil {
			return pr
		}
		return preStopOutlastsGrace(p)
	}
	return nil
}

var reSleepSeconds = regexp.MustCompile(`^(?:exec\s+)?sleep\s+(\d+)(?:s)?\b`)

// preStopSeconds returns how long a preStop hook waits, when that can be read from the spec: a sleep handler, or an
// exec command that is a sleep, directly or as the first thing a shell runs.
func preStopSeconds(h *kube.LifecycleHandler) (int64, bool) {
	switch {
	case h == nil:
		return 0, false
	case h.Sleep != nil:
		return h.Sleep.Seconds, true
	case h.Exec != nil:
		cmd := h.Exec.Command
		if len(cmd) >= 3 && (path.Base(cmd[0]) == "sh" || path.Base(cmd[0]) == "bash") && cmd[1] == "-c" {
			cmd = []string{cmd[2]}
		}
		line := strings.TrimSpace(strings.Join(cmd, " "))
		line = strings.TrimPrefix(line, "/bin/")
		if m := reSleepSeconds.FindStringSubmatch(line); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			return n, true
		}
	}
	return 0, false
}

// preStopOutlastsGrace finds a container whose preStop hook waits as long as the pod's termination grace period or
// longer. The grace period counts from the moment the pod is deleted and includes the hook, so the kubelet kills the
// container (SIGKILL) as the hook ends or before: the app never gets its SIGTERM to finish in-flight work, on every
// rollout, scale-down and drain.
func preStopOutlastsGrace(p kube.Pod) *problem {
	grace := int64(30)
	if g := p.Spec.TerminationGracePeriodSeconds; g != nil {
		grace = *g
	}
	for _, c := range p.Spec.Containers {
		if c.Lifecycle == nil {
			continue
		}
		wait, ok := preStopSeconds(c.Lifecycle.PreStop)
		if !ok || wait < grace {
			continue
		}
		return newProblem(p, c.Name, "KD208", "preStop hook outlasts the termination grace period", Warning,
			fmt.Sprintf("container %s's preStop hook waits %d s, and the pod's terminationGracePeriodSeconds is %d: the grace period includes the hook, so when the pod is deleted the kubelet kills the container before the app gets SIGTERM and time to finish, on every rollout, scale-down and drain", c.Name, wait, grace),
			"prestop|"+c.Name,
			fmt.Sprintf("Set terminationGracePeriodSeconds above the preStop wait plus the app's own shutdown time (for example %d), or shorten the preStop sleep.", wait+30),
			Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's preStop hook and the pod's terminationGracePeriodSeconds", c.Name),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.terminationGracePeriodSeconds}{"\n"}{.spec.containers[?(@.name=="%s")].lifecycle.preStop}`, c.Name))})
	}
	return nil
}

// probeCannotRun finds a liveness or startup probe whose command is not in the image. The kubelet reports such a
// probe as errored, not failed, and ignores the result: the container is never restarted, so the probe silently
// checks nothing.
func probeCannotRun(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	if cs.State.Running == nil {
		return nil
	}
	c, _ := containerSpec(p, cs.Name)
	for _, kind := range []string{"liveness", "startup"} {
		probe := c.LivenessProbe
		if kind == "startup" {
			probe = c.StartupProbe
		}
		if probe == nil || probe.Exec == nil {
			continue
		}
		exe := probeExecMissing(ix, p, cs.Name, kind)
		if exe == "" {
			continue
		}
		var ev []Evidence
		for _, e := range ix.eventsFor(p.Ref(), "Unhealthy") {
			if mentionsContainer(e, cs.Name) && strings.HasPrefix(strings.ToLower(e.Message), kind+" probe") {
				ev = append(ev, eventEvidence(p.Ref(), e))
				break
			}
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's %s probe runs %s", cs.Name, kind, strings.Join(probe.Exec.Command, " ")),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].%sProbe}`, cs.Name, kind))})
		return newProblem(p, cs.Name, "KD129", "Probe command is not in the image", Warning,
			fmt.Sprintf("container %s's %s probe %s; the kubelet counts that as an error, not a failure, so the probe never passes or fails and checks nothing", cs.Name, kind, probeExecWhy(exe, imageOf(p, cs))),
			"probecmd|"+kind+"|"+exe, probeExecFix(exe), ev...)
	}
	return nil
}

// readinessGateAfter is how long a running pod may wait for its readiness gates before it is reported.
const readinessGateAfter = 2 * time.Minute

// readinessGate finds a running pod whose containers are all ready but which is not Ready, because a readiness gate
// condition that some controller should set is missing or False.
func readinessGate(ix *index, p kube.Pod) *problem {
	if p.Status.Phase != "Running" || len(p.Spec.ReadinessGates) == 0 || p.Ready() {
		return nil
	}
	if c, ok := kube.FindCondition(p.Status.Conditions, "ContainersReady"); !ok || c.Status != "True" {
		return nil
	}
	if p.Status.StartTime == nil || ix.s.CollectedAt.Sub(*p.Status.StartTime) < readinessGateAfter {
		return nil
	}
	var unmet []string
	missing := true
	for _, g := range p.Spec.ReadinessGates {
		c, ok := kube.FindCondition(p.Status.Conditions, g.ConditionType)
		if !ok {
			unmet = append(unmet, g.ConditionType+" (never set)")
		} else if c.Status != "True" {
			unmet = append(unmet, fmt.Sprintf("%s (%s)", g.ConditionType, c.Status))
			missing = false
		}
	}
	if len(unmet) == 0 {
		return nil
	}
	gates := strings.Join(unmet, ", ")
	fix := "Find the controller that sets the gate's condition (an AWS or GKE load balancer controller sets target-health conditions) and why it has not; the pod stays out of every Service until it does."
	cause := fmt.Sprintf("the pod's containers are ready, but readiness gate %s is not True, so the pod is not Ready and its Services send it no traffic", gates)
	if missing {
		cause = fmt.Sprintf("the pod's containers are ready, but no controller has set its readiness gate %s, so the pod is not Ready and its Services send it no traffic", gates)
	}
	return newProblem(p, "", "KD128", "Readiness gate is not met", Critical, cause, "gate|"+gates, fix,
		Evidence{Object: p.Ref(), What: "pod readiness gates and conditions",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.spec.readinessGates}{"\n"}{.status.conditions}`)})
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
// jobSidecarAfter is how long a Job's pod may keep running after one of its containers has finished before the
// container still running is reported as holding the Job.
const jobSidecarAfter = time.Minute

// jobHeldBySidecar finds a Job's pod whose work is done, a container has exited 0, while another container of the
// pod keeps running: a proxy or log shipper declared as an ordinary container. A pod succeeds only when every
// container has exited, so the Job never completes and nothing fails.
func jobHeldBySidecar(ix *index, p kube.Pod) *problem {
	o, ok := p.Metadata.Controller()
	if !ok || o.Kind != "Job" || p.Status.Phase != "Running" {
		return nil
	}
	var done, running []kube.ContainerStatus
	for _, cs := range p.Status.ContainerStatuses {
		switch {
		case cs.State.Terminated != nil && cs.State.Terminated.ExitCode == 0:
			done = append(done, cs)
		case cs.State.Running != nil:
			running = append(running, cs)
		default:
			return nil
		}
	}
	if len(done) == 0 || len(running) == 0 {
		return nil
	}
	last := done[0].State.Terminated.FinishedAt
	for _, cs := range done {
		if cs.State.Terminated.FinishedAt.After(last) {
			last = cs.State.Terminated.FinishedAt
		}
	}
	if last.IsZero() || ix.s.CollectedAt.Sub(last) < jobSidecarAfter {
		return nil
	}
	names := func(l []kube.ContainerStatus) string {
		var out []string
		for _, cs := range l {
			out = append(out, cs.Name)
		}
		return strings.Join(out, ", ")
	}
	side := running[0].Name
	return newProblem(p, side, "KD292", "Job never completes: a sidecar keeps its pod running", Warning,
		fmt.Sprintf("Job %s's pod %s has done its work (%s %s exited 0, %s ago) but %s %s is still running, so the pod never succeeds and the Job never completes",
			o.Name, p.Metadata.Name, plural(len(done), "container"), names(done), ix.s.CollectedAt.Sub(last).Round(time.Minute), plural(len(running), "container"), names(running)),
		"jobsidecar|"+side,
		fmt.Sprintf("Declare %s under initContainers with restartPolicy: Always (a sidecar): the kubelet stops a sidecar once the pod's other containers have exited. Or have the work tell %s to quit when it ends.", side, side),
		Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s exited 0 at %s", done[0].Name, done[0].State.Terminated.FinishedAt.UTC().Format(time.RFC3339)),
			Command: cmdContainerState(p, done[0].Name, "state")},
		Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s is still running, and the pod's phase is Running", side), Command: cmdContainerState(p, side, "state")},
		Evidence{Object: kube.Ref{Kind: "Job", Namespace: p.Metadata.Namespace, Name: o.Name}, What: fmt.Sprintf("Job %s has not completed", o.Name),
			Command: cmdGet("job", p.Metadata.Namespace, o.Name, `{.status.active}{" "}{.status.succeeded}`)})
}

func initStuck(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	if p.Status.Phase != "Pending" || cs.State.Running == nil || cs.State.Running.StartedAt.IsZero() {
		return nil
	}
	if p.IsSidecar(cs.Name) {
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
	lines := ix.logs[logKey{p.Metadata.Namespace, p.Metadata.Name, cs.Name}].Lines
	if pr := initWaitsForItself(ix, p, cs, lines, ev); pr != nil {
		return pr
	}
	if svc, _, ok := refusedService(ix, p.Metadata.Namespace, lines); ok && len(svc.Spec.Selector) > 0 && readyBehind(ix, svc) == 0 {
		cause += fmt.Sprintf("; it waits for Service %s, which has no ready pods", svc.Metadata.Name)
		fix = fmt.Sprintf("Fix Service %s's pods (their own findings say why they are not ready, or the workload is scaled to 0); the init container finishes once they answer.", svc.Metadata.Name)
		ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s has no ready pods", svc.Metadata.Name),
			Command: "kubectl get endpointslices -n " + svc.Metadata.Namespace + " -l kubernetes.io/service-name=" + svc.Metadata.Name})
	}
	if svcNS, svc, _, ok := ix.missingService(p.Metadata.Namespace, lines); ok {
		cause += fmt.Sprintf("; it waits for %s, and there is no Service %s in namespace %s", svc, svc, svcNS)
		fix = fmt.Sprintf("Create Service %s in namespace %s (or deploy what it fronts), or correct the host name the init container waits for.", svc, svcNS)
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Service", Namespace: svcNS, Name: svc},
			What: fmt.Sprintf("there is no Service %s in namespace %s", svc, svcNS), Command: cmdGet("service", svcNS, svc, "")})
	}
	return newProblem(p, cs.Name, "KD119", "Init container never finishes", Critical, cause, "initstuck", fix, ev...)
}

// initWaitsForItself finds an init container that waits for a Service whose only pods are its own workload's. Those
// pods serve only once their app containers run, and the app containers start only after the init container exits:
// each waits for the other, so the workload never starts.
func initWaitsForItself(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	ns := p.Metadata.Namespace
	svc, line, ok := refusedService(ix, ns, lines)
	if !ok || len(svc.Spec.Selector) == 0 || !kube.MatchesMap(svc.Spec.Selector, p.Metadata.Labels) {
		return nil
	}
	owner := ix.owner(p)
	for _, q := range ix.s.Pods {
		if q.Metadata.Namespace == ns && kube.MatchesMap(svc.Spec.Selector, q.Metadata.Labels) && q.Status.Phase != "Succeeded" && q.Status.Phase != "Failed" && ix.owner(q) != owner {
			return nil // another workload serves the Service too: its pods are what the init container waits for
		}
	}
	name := svc.Metadata.Name
	ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s selects pods with %s: the pods of %s %s, this one included", name, kube.FormatMap(svc.Spec.Selector), owner.Kind, owner.Name),
		Command: "kubectl get pods -n " + ns + " -l " + kube.FormatMap(svc.Spec.Selector)})
	return newProblem(p, cs.Name, "KD220", "Init container waits for its own pod", Critical,
		fmt.Sprintf("init container %s waits for Service %s, and the only pods behind that Service are %s %s's own: they serve only once their app containers run, and those start only after this init container exits, so each waits for the other; its log says: %q",
			cs.Name, name, owner.Kind, owner.Name, clip(line, 200)),
		"initself|"+name,
		fmt.Sprintf("Remove the wait for %s from init container %s, or point it at what the pod really depends on. A pod cannot wait for itself: its readiness and startup probes are what hold traffic back until the app is up.", name, cs.Name), ev...)
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
		case "PostStartHookError":
			// Caught between a failed postStart hook and the kubelet's back-off, before the state reads
			// CrashLoopBackOff.
			if pr := hookFailed(ix, p, cs); pr != nil {
				return pr
			}
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
	// Exited just now with code 0, again: a container of a long-running workload whose process keeps finishing. The
	// kubelet restarts it each time, and between an exit and the back-off its state reads Completed, not
	// CrashLoopBackOff. An init container, and a Job's container, are meant to finish.
	if t := cs.State.Terminated; t != nil && t.ExitCode == 0 && cs.RestartCount >= 2 && p.Status.Phase == "Running" && !isInit(p, cs.Name) {
		if o, ok := p.Metadata.Controller(); !ok || o.Kind != "Job" {
			return crash(ix, p, cs)
		}
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
	reX509      = regexp.MustCompile(`x509: (certificate signed by unknown authority|certificate has expired or is not yet valid[^"]*|certificate is valid for [^"]+?, not [^\s"]+|[^"]+)`)
	rePlainHTTP = regexp.MustCompile(`(?i)server gave HTTP response to HTTPS client`)
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
	case reX509.MatchString(msg):
		why := strings.TrimRight(reX509.FindStringSubmatch(msg)[1], ".: ")
		host := registry(image)
		return newProblem(p, cs.Name, "KD103", "Registry cannot be reached", Critical,
			fmt.Sprintf("the node does not accept the TLS certificate of registry %s for image %s (x509: %s)", host, image, why), "x509|"+host,
			fmt.Sprintf("Give every node the CA that signed %s's certificate (for containerd, /etc/containerd/certs.d/%s/ca.crt), or serve the registry with a certificate the nodes already trust; an expired or wrong-host certificate has to be replaced.", host, host), ev...)
	case rePlainHTTP.MatchString(msg):
		host := registry(image)
		return newProblem(p, cs.Name, "KD103", "Registry cannot be reached", Critical,
			fmt.Sprintf("registry %s speaks plain HTTP and the node pulls image %s over HTTPS", host, image), "plainhttp|"+host,
			fmt.Sprintf("Serve %s over TLS, or configure every node's runtime to use HTTP for it (for containerd, a hosts.toml under /etc/containerd/certs.d/%s with server = \"http://%s\").", host, host, host), ev...)
	case reNetwork.MatchString(msg) && !reNotFound.MatchString(msg):
		if host := registry(image); localRegistry(host) {
			return newProblem(p, cs.Name, "KD103", "Registry cannot be reached", Critical,
				fmt.Sprintf("image %s names registry %s, and on node %s that is the node itself, where no registry answers: the image was built on a workstation (podman and buildah name local builds localhost/...) or pushed to a registry there, and the node cannot reach either", image, host, p.Spec.NodeName),
				"net|"+host, "Push the image to a registry the nodes can reach and use that name, or load it onto the nodes (kind load docker-image, minikube image load) and set imagePullPolicy: IfNotPresent so the kubelet does not pull it.", ev...)
		}
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
	// The first part is a registry when it has a dot or a port, or is localhost, as the container runtimes read it.
	if i := strings.Index(image, "/"); i > 0 && (strings.ContainsAny(image[:i], ".:") || image[:i] == "localhost") {
		return image[:i]
	}
	return "docker.io"
}

// localRegistry reports whether a registry host is the loopback address, which on a node is the node itself.
func localRegistry(host string) bool {
	h := host
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.HasSuffix(h, "]") {
		h = h[:i]
	}
	return h == "localhost" || h == "127.0.0.1" || h == "[::1]"
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
	cause := fmt.Sprintf("container %s reads key %s from %s %s, which has no such key", container, key, k, name)
	fix := fmt.Sprintf("Add key %s to %s %s, or correct the key name in the pod spec.", key, k, name)
	if ks, exists, _ := ix.keySet(strings.ToLower(k), ns, name); exists {
		if near := closeKey(key, ks.Keys); near != "" {
			cause += fmt.Sprintf("; it has %s, which differs only in %s", near, keyDifference(key, near))
			fix = fmt.Sprintf("Read key %s, as %s %s spells it, or rename the key in %s %s to %s.", near, k, name, k, name, key)
		}
		have := "no keys"
		if len(ks.Keys) > 0 {
			have = "keys " + strings.Join(ks.Keys, ", ")
		}
		ev = append(ev, Evidence{Object: kube.Ref{Kind: k, Namespace: ns, Name: name},
			What: fmt.Sprintf("%s %s has %s, not %s", k, name, have, key),
			Command: fmt.Sprintf("kubectl get %s %s -n %s -o go-template=%s", strings.ToLower(k), name, ns,
				shq(`{{range $k, $v := .data}}{{$k}}{{"\n"}}{{end}}`))})
	}
	return newProblem(p, container, "KD132", "Key missing from "+k, Critical, cause, k+"|"+name+"|"+key, fix, ev...)
}

// normalKey is a key name with case and separators (-, _, .) left out: DB_PASSWORD and db-password read the same.
func normalKey(k string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(k))
}

// closeKey returns the key that a missing key was most likely meant to be: the same name in another case or with
// other separators (DB_PASSWORD for db-password), or one a letter or two away in a name long enough to tell.
func closeKey(want string, have []string) string {
	for _, k := range have {
		if normalKey(k) == normalKey(want) {
			return k
		}
	}
	best, bestD := "", 3
	for _, k := range have {
		if len(want) < 6 || len(k) < 6 {
			continue
		}
		if d := editDistance(normalKey(k), normalKey(want)); d < bestD {
			best, bestD = k, d
		}
	}
	return best
}

// keyDifference says how a key differs from the one closeKey found.
func keyDifference(want, near string) string {
	lower := func(s string) bool { return strings.ToLower(s) == s }
	switch {
	case strings.EqualFold(want, near):
		return "case"
	case normalKey(want) == normalKey(near) && lower(want) == lower(near):
		return "its separators (- _ .)"
	case normalKey(want) == normalKey(near):
		return "case and separators (- _ .)"
	}
	return "spelling"
}

var (
	reMultiAttach = regexp.MustCompile(`Multi-Attach error for volume "([^"]+)"(?: Volume is already used by pod\(s\) ([^\s,]+))?`)
	reMountCM     = regexp.MustCompile(`configmap "([^"]+)" not found`)
	reMountSecret = regexp.MustCompile(`secret "([^"]+)" not found`)
	reMountKey    = regexp.MustCompile(`references non-existent (config|secret) key: (\S+)`)
	reCSIMissing  = regexp.MustCompile(`driver name (\S+) not found in the list of registered CSI drivers|timed out waiting for external-attacher of (\S+) CSI driver`)
	reHostPath    = regexp.MustCompile(`for volume "([^"]+)" : hostPath type check failed[:,] (\S+) is not a (directory|file|socket file|character device|block device)`)
)

// mountProblem finds a pod stuck creating its containers because a volume cannot be mounted.
func mountProblem(ix *index, p kube.Pod) *problem {
	if p.Status.Phase != "Pending" {
		return nil
	}
	for _, e := range ix.eventsFor(p.Ref(), "FailedAttachVolume", "FailedMount") {
		if m := reCSIMissing.FindStringSubmatch(e.Message); m != nil {
			return csiMissing(p, m[1]+m[2], e)
		}
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
		if m := reHostPath.FindStringSubmatch(e.Message); m != nil {
			node := orNode(p.Spec.NodeName)
			cause := fmt.Sprintf("volume %s mounts hostPath %s, which is not a %s on %s, and the volume's type requires one, so the pod cannot start", m[1], m[2], m[3], node)
			fix := fmt.Sprintf("Create %s on every node the pod may run on (a DaemonSet or the node image), use type DirectoryOrCreate or FileOrCreate if the pod may create it, or schedule the pod onto the nodes that have it.", m[2])
			ev = append(ev, Evidence{Object: p.Ref(), What: "volume " + m[1],
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.volumes[?(@.name=="%s")]}`, m[1]))})
			// The node's runtime is evidence whenever it is known: sockets and devices on a node depend on it.
			if rt := nodeRuntime(ix, p.Spec.NodeName); rt != "" {
				ev = append(ev, Evidence{Object: kube.Ref{Kind: "Node", Name: p.Spec.NodeName}, What: "container runtime " + rt,
					Command: cmdGet("node", "", p.Spec.NodeName, "{.status.nodeInfo.containerRuntimeVersion}")})
				if dockerSocket(m[2]) && !strings.HasPrefix(rt, "docker") {
					cause = fmt.Sprintf("volume %s mounts the Docker socket %s, and %s runs %s, not Docker, so there is no such socket and the pod cannot start", m[1], m[2], node, rt)
					fix = "Talk to the node's runtime through its own socket (/run/containerd/containerd.sock for containerd, with a client such as crictl or nerdctl), or, to build images, use a builder that needs no daemon (BuildKit rootless, kaniko, buildah); Kubernetes has not run on Docker Engine since 1.24 unless cri-dockerd was installed."
				}
			}
			return newProblem(p, "", "KD135", "hostPath does not exist on the node", Critical, cause, "hostpath|"+m[2], fix, ev...)
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

// reSeccompProfile is containerd's error for a Localhost seccomp profile it cannot read: "cannot load seccomp profile
// \"/var/lib/kubelet/seccomp/profiles/x.json\": open ...: no such file or directory". The kubelet does not check that
// the file exists; it passes the path on.
var reSeccompProfile = regexp.MustCompile(`cannot load seccomp profile \\?"([^"\\]+)\\?": (.*)`)

// bareSmallMemory reports whether a memory quantity is a bare number of bytes under 4 MiB, too little for any process.
func bareSmallMemory(v string) bool {
	n, err := strconv.ParseInt(v, 10, 64)
	return err == nil && n < 4<<20
}

// memoryInBytesMount finds a pod that never starts because a container's memory limit is a bare number of bytes: the
// kubelet sizes the pod's memory-backed volumes, the projected service account token among them, by the pod's memory
// limit, so it cannot even write the token ("no space left on device") and the pod stays in ContainerCreating.
func memoryInBytesMount(ix *index, p kube.Pod) *problem {
	var c kube.Container
	for _, x := range p.Spec.Containers {
		if bareSmallMemory(x.Resources.Limits["memory"]) {
			c = x
			break
		}
	}
	if c.Name == "" {
		return nil
	}
	for _, e := range ix.eventsFor(p.Ref(), "FailedMount") {
		if !strings.Contains(e.Message, "no space left on device") {
			continue
		}
		v := c.Resources.Limits["memory"]
		return newProblem(p, c.Name, "KD210", "Memory limit has no unit, so it is in bytes", Critical,
			fmt.Sprintf("container %s's memory limit is memory: %s, which Kubernetes reads as %s bytes: the kubelet sizes the pod's memory-backed volumes by that limit, so it cannot even write the service account token into one (no space left on device), and the pod never starts", c.Name, v, v),
			"membytes|"+c.Name,
			fmt.Sprintf("Give the limit a unit: %sMi if mebibytes were meant (Mi and Gi are powers of 1024; M and G are powers of 1000), and the request the same way.", v),
			eventEvidence(p.Ref(), e),
			Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's memory limit is %s, with no unit", c.Name, v),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].resources}`, c.Name))})
	}
	return nil
}

// memoryInBytes finds a failing container whose memory limit is a bare number under 4 MiB (memory: 512): Kubernetes
// reads a number without a unit as bytes, so the limit is far too small for any process, and the runtime cannot start
// the container ("container init was OOM-killed (memory limit too low?)") or the kernel kills it at once.
func memoryInBytes(p kube.Pod, cs kube.ContainerStatus, ev []Evidence) *problem {
	c, ok := containerSpec(p, cs.Name)
	if !ok {
		return nil
	}
	v := c.Resources.Limits["memory"]
	if !bareSmallMemory(v) {
		return nil
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's memory limit is %s, with no unit", cs.Name, v),
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].resources}`, cs.Name))})
	return newProblem(p, cs.Name, "KD210", "Memory limit has no unit, so it is in bytes", Critical,
		fmt.Sprintf("container %s's memory limit is memory: %s, which Kubernetes reads as %s bytes, too little for any process, so the runtime kills the container as it starts", cs.Name, v, v),
		"membytes|"+cs.Name,
		fmt.Sprintf("Give the limit a unit: %sMi if mebibytes were meant (Mi and Gi are powers of 1024; M and G are powers of 1000), and the request the same way.", v),
		ev...)
}

// failedByPolicy returns the Job that owns the pod when that Job failed because its podFailurePolicy matched a pod's
// failure (condition Failed with reason PodFailurePolicy), and the condition.
func failedByPolicy(ix *index, p kube.Pod) (*kube.Job, kube.Condition, bool) {
	o, ok := p.Metadata.Controller()
	if !ok || o.Kind != "Job" {
		return nil, kube.Condition{}, false
	}
	j, ok := ix.jobs[kube.Ref{Kind: "Job", Namespace: p.Metadata.Namespace, Name: o.Name}]
	if !ok {
		return nil, kube.Condition{}, false
	}
	c, ok := kube.FindCondition(j.Status.Conditions, "Failed")
	if !ok || c.Status != "True" || c.Reason != "PodFailurePolicy" {
		return nil, kube.Condition{}, false
	}
	return j, c, true
}

func startError(ix *index, p kube.Pod, cs kube.ContainerStatus, msg string) *problem {
	ev := []Evidence{{Object: p.Ref(), What: fmt.Sprintf("container %s did not start", cs.Name), Detail: msg,
		Command: cmdContainerState(p, cs.Name, "state")}}
	c, _ := containerSpec(p, cs.Name)
	if pr := memoryInBytes(p, cs, ev); pr != nil {
		return pr
	}
	if pr := subPathOntoFile(ix, p, cs.Name, msg, ev); pr != nil {
		return pr
	}
	if pr := appArmorNotLoaded(p, cs, msg, ev); pr != nil {
		return pr
	}
	if m := reSeccompProfile.FindStringSubmatch(msg); m != nil {
		path := m[1]
		cause := fmt.Sprintf("container %s uses the Localhost seccomp profile %s, which is not on node %s, so the container runtime cannot create the container", cs.Name, path, p.Spec.NodeName)
		if !strings.Contains(msg, "no such file") {
			cause = fmt.Sprintf("container %s uses the Localhost seccomp profile %s, which the container runtime on node %s cannot load (%s), so it cannot create the container", cs.Name, path, p.Spec.NodeName, clip(m[2], 120))
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: "the pod's and the container's seccompProfile",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.securityContext.seccompProfile}{"\n"}{.spec.containers[?(@.name=="%s")].securityContext.seccompProfile}`, cs.Name))})
		return newProblem(p, cs.Name, "KD207", "Seccomp profile is not on the node", Critical, cause, "seccomp|"+path,
			"Put the profile on every node that may run the pod, under the kubelet's seccomp directory (the Security Profiles Operator or a DaemonSet can install it), keep the pod to the nodes that have it, or use seccompProfile type RuntimeDefault.", ev...)
	}
	if pr := workingDirFails(p, cs, c, msg, ev); pr != nil {
		return pr
	}
	switch {
	case reExecFormat.MatchString(msg):
		return execFormat(p, cs, ev)
	case reExecDenied.MatchString(msg):
		return notExecutable(p, cs.Name, reExecDenied.FindStringSubmatch(msg)[1], "", ev)
	case reNoExec.MatchString(msg):
		if pr := commandOneString(p, cs, c, msg, ev); pr != nil {
			return pr
		}
		if pr := flagAsCommand(p, cs, c, ev); pr != nil {
			return pr
		}
		if len(c.Command) > 0 {
			if m, what, ok := missingVolumeFile(ix, p, cs.Name, c.Command[0]); ok {
				return volumeFileProblem(p, cs.Name, m, fmt.Sprintf("container %s runs %s, which does not exist: %s", cs.Name, c.Command[0], what), ev)
			}
			if pr := volumeHidesCommand(p, cs, c.Command[0], ev); pr != nil {
				return pr
			}
		}
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

// reChdir is runc failing to enter the container's working directory, the last step before it runs the command. runc
// tries as root first and again as the container's user only when root is refused, so permission denied means
// neither may enter it (a volume that squashes root, such as NFS). reMkdirCwd is runc creating a missing working
// directory, which fails on a path that is a file in the image, or that has one where a directory should be.
var (
	reChdir    = regexp.MustCompile(`chdir to cwd \(\\?"([^"\\]+)\\?"\) set in config\.json failed: ([a-z ]+)`)
	reMkdirCwd = regexp.MustCompile(`mkdir (/[^:\s]*): not a directory`)
)

// workingDirFails finds a container the runtime cannot start because it cannot create or enter the container's
// working directory: a path that is a file in the image (the program, not the directory that holds it), or a
// directory neither root nor the container's user may enter.
func workingDirFails(p kube.Pod, cs kube.ContainerStatus, c kube.Container, msg string, ev []Evidence) *problem {
	m := reChdir.FindStringSubmatch(msg)
	if m == nil {
		// The mkdir error names the path that is a file: the working directory itself, or one of its parents. A
		// volume's mount point that fails the same way is reported with the mount, so only these are read here.
		mk := reMkdirCwd.FindStringSubmatch(msg)
		if mk == nil || c.WorkingDir == "" || (mk[1] != c.WorkingDir && !strings.HasPrefix(c.WorkingDir, strings.TrimSuffix(mk[1], "/")+"/")) {
			return nil
		}
		m = []string{"", c.WorkingDir, "not a directory"}
		if mk[1] != c.WorkingDir {
			m[1] = mk[1]
		}
	}
	dir, why := m[1], strings.TrimSpace(m[2])
	from := "the image's WORKDIR"
	if c.WorkingDir != "" {
		from = "its workingDir"
	}
	cause := fmt.Sprintf("container %s cannot start: the runtime cannot enter %s, %s (%s)", cs.Name, dir, from, why)
	fix := "Set workingDir to a directory the container may enter (one under /tmp, or one the image creates for its user), or leave it unset to use the image's WORKDIR."
	switch {
	case strings.Contains(why, "permission denied"):
		user := "its user"
		if u, ok := p.RunAsUser(cs.Name); ok {
			user = fmt.Sprintf("user %d", u)
		}
		cause = fmt.Sprintf("container %s cannot start: neither the runtime, as root, nor %s may enter its working directory %s (%s) (permission denied); the runtime tries as root first, so this is a directory root is refused too, as on a volume that squashes root (NFS)", cs.Name, user, dir, from)
		fix = fmt.Sprintf("Give %s to %s where it lives (on the NFS server for a squashed volume), or use a working directory under /tmp or a volume %s owns.", dir, user, user)
	case strings.Contains(why, "not a directory"):
		file := dir
		if c.WorkingDir != "" && c.WorkingDir != dir {
			cause = fmt.Sprintf("container %s cannot start: its working directory %s (%s) is under %s, which is a file in the image, not a directory (not a directory), so the runtime cannot create it", cs.Name, c.WorkingDir, from, dir)
			dir = c.WorkingDir
		} else {
			cause = fmt.Sprintf("container %s cannot start: its working directory %s (%s) is a file in the image, not a directory (not a directory)", cs.Name, dir, from)
		}
		fix = fmt.Sprintf("Set workingDir to a directory: the one that holds the file, %s, or another the image has.", path.Dir(file))
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's workingDir and user", cs.Name),
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].workingDir}{" "}{.spec.securityContext}{" "}{.spec.containers[?(@.name=="%s")].securityContext}`, cs.Name, cs.Name))})
	return newProblem(p, cs.Name, "KD237", "Container cannot enter its working directory", Critical, cause, "cwd|"+dir, fix, ev...)
}

// volumeHidesCommand finds a command the runtime cannot find because a volume is mounted on the directory that holds
// it: an emptyDir, a claim or a hostPath mounted at /app replaces everything the image has under /app, the binary
// included. (A ConfigMap or Secret volume that lacks the file is told apart, with its keys.)
func volumeHidesCommand(p kube.Pod, cs kube.ContainerStatus, cmd string, ev []Evidence) *problem {
	if !strings.HasPrefix(cmd, "/") {
		return nil
	}
	m, ok := p.MountAt(cs.Name, cmd)
	if !ok || m.Rel == "" {
		return nil
	}
	kind := ""
	switch {
	case m.Volume.EmptyDir != nil:
		kind = "an emptyDir, which starts empty"
	case m.Volume.PersistentVolumeClaim != nil:
		kind = "PersistentVolumeClaim " + m.Volume.PersistentVolumeClaim.ClaimName
	case m.Volume.HostPath != nil:
		kind = "hostPath " + m.Volume.HostPath.Path
	default:
		return nil
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s mounts volume %s at %s, and its command is %s", cs.Name, m.Name, m.MountPath, cmd),
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].volumeMounts}`, cs.Name))})
	return newProblem(p, cs.Name, "KD214", "Volume mount hides the command", Critical,
		fmt.Sprintf("container %s runs %s, but volume %s (%s) is mounted at %s and replaces everything the image has there, so the command is not in the container", cs.Name, cmd, m.Name, kind, m.MountPath),
		"hidden|"+m.MountPath,
		fmt.Sprintf("Mount volume %s somewhere the image keeps no files (a subdirectory such as %s/data), or use subPath to mount only the directory the app writes to.", m.Name, strings.TrimRight(m.MountPath, "/")), ev...)
}

var reNoExecName = regexp.MustCompile(`exec: "([^"]+)": (?:executable file not found|stat [^:]+: no such file or directory)`)

// commandOneString finds a command written as one string, ["sleep 3600"] for ["sleep", "3600"]: the runtime looks for
// an executable whose name is the whole string, spaces included, and does not find it.
func commandOneString(p kube.Pod, cs kube.ContainerStatus, c kube.Container, msg string, ev []Evidence) *problem {
	m := reNoExecName.FindStringSubmatch(msg)
	if m == nil || !strings.ContainsAny(m[1], " \t") {
		return nil
	}
	exe, field := m[1], "command"
	if len(c.Command) == 0 || c.Command[0] != exe {
		if len(c.Command) > 0 || len(c.Args) == 0 || c.Args[0] != exe {
			return nil
		}
		field = "args" // no command: the image has no entrypoint, and the runtime runs args as the command
	}
	split := strings.Fields(exe)
	want := `["sh", "-c", ` + strconv.Quote(exe) + `]`
	if !strings.ContainsAny(exe, "|&;<>$`'\"*?(){}") {
		var q []string
		for _, w := range split {
			q = append(q, strconv.Quote(w))
		}
		want = "[" + strings.Join(q, ", ") + "]"
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's %s is %q, one string", cs.Name, field, exe),
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].%s}`, cs.Name, field))})
	return newProblem(p, cs.Name, "KD201", "Command and its arguments are one string", Critical,
		fmt.Sprintf("container %s's %s is the single string %q, so the runtime looks for an executable named %q, spaces included, and there is none; each argument has to be its own list item", cs.Name, field, exe, exe),
		"onestring|"+exe, fmt.Sprintf("Write the %s as a list with one item per word: %s instead of [%s].", field, want, strconv.Quote(exe)), ev...)
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
	if pr := memoryInBytes(p, cs, []Evidence{terminatedEvidence(p, cs, t)}); pr != nil {
		return pr
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
	if c, _ := containerSpec(p, cs.Name); t.ExitCode == 137 && c.Resources.Limits["memory"] != "" {
		// SIGKILL with no probe or hook behind it, in a container with a memory limit: the kernel's OOM killer. The
		// runtime sometimes reports such a kill as Error rather than OOMKilled, when it lands as the container starts.
		pr := oomKilled(ix, p, cs)
		if pr.rule == "KD111" {
			// Keep what oomKilled adds after its first clause: a limit the LimitRange set, the app's own setting.
			first := fmt.Sprintf("container %s uses more than its %s memory limit and is killed (OOMKilled)", cs.Name, c.Resources.Limits["memory"])
			pr.cause = fmt.Sprintf("container %s is killed by SIGKILL (exit 137) with no probe or hook behind it, and it has a %s memory limit: it runs out of memory, though the runtime reported the kill as %s, not OOMKilled",
				cs.Name, c.Resources.Limits["memory"], orReason(t.Reason)) + strings.TrimPrefix(pr.cause, first)
		}
		return pr
	}
	ev := []Evidence{terminatedEvidence(p, cs, t)}
	if len(log.Lines) > 0 {
		ev = append(ev, logEvidence(p, cs.Name, log))
	}
	if t.ExitCode == 126 {
		if pr := deniedScript(p, cs, log.Lines, ev); pr != nil {
			return pr
		}
	}
	if pr := windowsLineEndings(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := trailingNewline(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := shmTooSmall(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := undefinedVar(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := shellVar(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := shellOperators(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := envOrder(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := flagAndValueOneArg(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := serviceLinkOverride(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := interpreterMissing(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := subPathIsADirectory(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := downwardFieldMissing(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := envFromKeyName(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := optionalEnvMissing(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := mountedAsDirectory(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := initMountPath(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := keyFileTooOpen(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := fileNotInVolume(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := readOnlyVolume(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := volumeDenied(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := unknownUser(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := nonRootDenied(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := capabilityDropped(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := readOnlyRoot(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := portInUse(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := nodeDNS(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := customDNS(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := dnsBlocked(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := hostAliasService(ix, p, &cs, log.Lines, ev...); pr != nil {
		return pr
	}
	if pr := localhostForService(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := refusedByEmptyService(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := servicePortNotExposed(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := refusedByReadyPods(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := fixedServiceIP(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := apiServerBlocked(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := policyBlocksService(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := resizeRefused(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := tokenForAnotherAudience(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := tokenNotMounted(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := rbacBroken(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := grantNearMiss(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := rbacDenied(p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := subdomainProblem(ix, p, &cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := peerNotPublished(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if pr := externalNameUnresolved(ix, p, cs, log.Lines, ev); pr != nil {
		return pr
	}
	if svcNS, svc, line, ok := ix.missingService(p.Metadata.Namespace, log.Lines); ok {
		return newProblem(p, cs.Name, "KD121", "Container looks up a Service that does not exist", Critical,
			fmt.Sprintf("container %s exits because it cannot resolve %s: there is no Service %s in namespace %s; its log says: %q", cs.Name, svc, svc, svcNS, clip(line, 200)),
			"nosvc|"+svcNS+"/"+svc, fmt.Sprintf("Create Service %s in namespace %s (or deploy what it fronts), or correct the host name the app connects to in its configuration.", svc, svcNS),
			append(ev, Evidence{Object: kube.Ref{Kind: "Service", Namespace: svcNS, Name: svc},
				What: fmt.Sprintf("there is no Service %s in namespace %s", svc, svcNS), Command: cmdGet("service", svcNS, svc, "")})...)
	}
	if t.ExitCode == 0 {
		if pr := shellExits(p, cs, ev); pr != nil {
			return pr
		}
	}
	title, rule := "Container keeps crashing", "KD110"
	what, kind := "exits", "container"
	sidecar := p.IsSidecar(cs.Name)
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
	if j, c, ok := failedByPolicy(ix, p); ok {
		cause += fmt.Sprintf("; Job %s's podFailurePolicy matched that exit and failed the whole Job at once, without the retries backoffLimit allows (%s)", j.Metadata.Name, c.Message)
		fix += " The Job's podFailurePolicy marks this exit as not worth retrying; if it can succeed on a retry, change that rule's action to Ignore or Count."
		ev = append(ev, Evidence{Object: j.Ref(), What: "Job condition Failed: PodFailurePolicy", Detail: c.Message,
			Command: cmdGet("job", j.Metadata.Namespace, j.Metadata.Name, `{.spec.podFailurePolicy}{"\n"}{.status.conditions[?(@.type=="Failed")]}`)})
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
	if p.Spec.HostNetwork {
		port := 0
		if m := rePortInLine.FindAllStringSubmatch(line, -1); len(m) > 0 {
			port, _ = strconv.Atoi(m[len(m)-1][1])
		} else if len(c.Ports) == 1 {
			port = int(c.Ports[0].ContainerPort)
		}
		whose := ""
		if owner := nodePorts[port]; owner != "" {
			whose = fmt.Sprintf(", and %d is the %s's", port, owner)
		} else if port > 0 {
			whose = fmt.Sprintf(", and something on the node has %d", port)
		}
		cause = fmt.Sprintf("container %s exits because the port it listens on is already in use: the pod runs in the node's network (hostNetwork: true), so it shares ports with every process of the node%s; its log says: %q",
			cs.Name, whose, clip(line, 160))
		fix = "Listen on a port nothing on the node uses, or drop hostNetwork and reach the pod through a Service (or a hostPort, which the scheduler checks against the other pods' host ports)."
		key = fmt.Sprintf("addrinuse|host|%d", port)
		ev = append(ev, Evidence{Object: p.Ref(), What: "the pod has hostNetwork: true", Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.hostNetwork}")})
	}
	return newProblem(p, cs.Name, "KD122", "Port is already in use", Critical, cause, key, fix, ev...)
}

// rePortInLine is a port number at the end of an address in a log line: 0.0.0.0:10250, [::]:8080.
var rePortInLine = regexp.MustCompile(`:(\d{2,5})\b`)

// nodePorts are the ports Kubernetes' own components hold on a node, which a pod on the host network cannot take.
var nodePorts = map[int]string{10250: "kubelet", 10256: "kube-proxy health check", 6443: "API server", 2379: "etcd client", 2380: "etcd peer", 10257: "controller manager", 10259: "scheduler"}

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
	if pr := memoryEmptyDir(p, cs, c, limit, ev); pr != nil {
		return pr
	}
	fix := "Raise the container's memory limit to what it needs at peak, or reduce the app's memory use."
	// No limit of its own, but the pod has one: its containers share it, and the kernel kills within the pod.
	if r := p.Spec.Resources; limit == "" && r != nil && r.Limits["memory"] != "" {
		limit = r.Limits["memory"]
		cause = fmt.Sprintf("container %s is killed for memory (OOMKilled) under the pod's own %s memory limit (spec.resources.limits.memory): it sets no limit of its own, and that limit is shared by all %d of the pod's containers", cs.Name, limit, len(p.Spec.Containers)+len(p.Spec.InitContainers))
		fix = fmt.Sprintf("Raise the pod-level memory limit (spec.resources.limits.memory, now %s) to what all the pod's containers use together at peak, or give %s a limit of its own inside it so that one container's growth is told apart.", limit, cs.Name)
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("the pod has memory limit %s, and container %s has none", limit, cs.Name),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.resources}{" "}{.spec.containers[?(@.name=="%s")].resources}`, cs.Name))})
	}
	if lim, err := kube.ParseQuantity(limit); err == nil && lim > 0 {
		if where, setting, size, ok := memorySetting(c); ok && size >= lim {
			cause += fmt.Sprintf("; the app is told to use more than that: %s, %s, in %s", setting, kube.FormatQuantity("memory", size), where)
			fix = fmt.Sprintf("Set %s below the %s limit, leaving room for the rest of the process (for a JVM heap, about three quarters of the limit), or raise the limit above it.", setting, limit)
			ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s sets %s in %s", cs.Name, setting, where),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")]['command','args','env']}`, cs.Name))})
		}
	}
	if limit != "" && limitRangerSetKind(p, "memory", "limit") == cs.Name {
		cause += fmt.Sprintf("; the pod template sets no memory limit for %s: the namespace's LimitRange gave it its default", cs.Name)
		fix = fmt.Sprintf("Set container %s's own memory limit in the pod template to what it needs at peak, or raise the default for memory in the namespace's LimitRange.", cs.Name)
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("the LimitRanger admission plugin set container %s's memory limit", cs.Name),
			Detail:  p.Metadata.Annotations[limitRangerAnnotation],
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.metadata.annotations.kubernetes\.io/limit-ranger}`)},
			Evidence{Object: kube.Ref{Kind: "LimitRange", Namespace: p.Metadata.Namespace, Name: "*"}, What: "the namespace's LimitRanges",
				Command: "kubectl get limitranges -n " + p.Metadata.Namespace + " -o yaml"})
	}
	return newProblem(p, cs.Name, "KD111", "Container runs out of memory", Critical, cause, "oom|"+limit, fix, ev...)
}

// memoryEmptyDir finds an OOMKilled container that mounts an emptyDir with medium Memory: a tmpfs whose pages are
// charged to the memory limit of the container that writes them, and which keeps its files across restarts, so a
// container that fills it is killed again each time it starts.
func memoryEmptyDir(p kube.Pod, cs kube.ContainerStatus, c kube.Container, limit string, ev []Evidence) *problem {
	for _, vm := range c.VolumeMounts {
		for _, v := range p.Spec.Volumes {
			if v.Name != vm.Name || v.EmptyDir == nil || v.EmptyDir.Medium != "Memory" {
				continue
			}
			size := "no sizeLimit"
			if v.EmptyDir.SizeLimit != "" {
				size = "sizeLimit " + v.EmptyDir.SizeLimit
			}
			lim := "its memory limit"
			if limit != "" {
				lim = "its " + limit + " memory limit"
			}
			ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("volume %s is an emptyDir with medium Memory (%s), mounted by container %s at %s", v.Name, size, cs.Name, vm.MountPath),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.volumes[?(@.name=="%s")]}`, v.Name))})
			return newProblem(p, cs.Name, "KD204", "Memory-backed emptyDir fills the memory limit", Critical,
				fmt.Sprintf("container %s is OOMKilled, and it writes to emptyDir %s at %s, which has medium Memory: the volume is a tmpfs whose files count against %s, and they outlive each restart, so the container is killed again as it starts",
					cs.Name, v.Name, vm.MountPath, lim),
				"memdir|"+v.Name,
				fmt.Sprintf("Raise %s's memory limit above what it keeps in %s plus its own use, set a sizeLimit on the volume so writes fail with no space instead, or drop medium: Memory to keep the files on the node's disk.", cs.Name, v.Name), ev...)
		}
	}
	return nil
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
	for _, k := range []string{"startup", "liveness"} {
		if pr := probeScheme(ix, p, cs, k); pr != nil {
			return pr
		}
		if pr := probeHost(ix, p, cs, k); pr != nil {
			return pr
		}
		if pr := probeGRPC(ix, p, cs, k); pr != nil {
			return pr
		}
		if pr := probeUDP(ix, p, cs, k); pr != nil {
			return pr
		}
		if pr := probeLoopback(ix, p, cs, k); pr != nil {
			return pr
		}
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
	if what, how := probeStatus(ix, p, cs.Name, kind); what != "" {
		cause += ": " + what
		fix = how
	}
	if probeTimedOut(ix, p, cs.Name, kind) && probe != nil {
		limit := probe.TimeoutSeconds
		if limit == 0 {
			limit = 1 // the API's default
		}
		cause = fmt.Sprintf("container %s's %s probe times out: the app does not answer within the probe's %ds timeoutSeconds, so the kubelet restarts it (%d restarts)", cs.Name, kind, limit, cs.RestartCount)
		fix = fmt.Sprintf("Raise the probe's timeoutSeconds above how long the check takes under load (it is %ds), keep the health endpoint cheap, or find why the app stops answering.", limit)
	}
	if exe := probeExecMissing(ix, p, cs.Name, kind); exe != "" {
		cause = fmt.Sprintf("container %s's %s probe %s, so the probe can never pass and the kubelet restarts the container (%d restarts)", cs.Name, kind, probeExecWhy(exe, imageOf(p, cs)), cs.RestartCount)
		fix = probeExecFix(exe)
	}
	if pr := killedWhileStarting(ix, p, cs, c, ev); pr != nil {
		return pr
	}
	if blocked := sidecarBlocks(p, cs.Name, kind); blocked != "" {
		cause += fmt.Sprintf("; it is a sidecar (an init container with restartPolicy: Always), and the containers after it start only once its startup probe passes, so %s never %s", blocked, map[bool]string{true: "starts", false: "start"}[!strings.Contains(blocked, ",")])
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

// probeExecWhy says why an exec probe's command cannot be run. A command with spaces in it is a whole command line
// written as one item (command: ["cat /tmp/healthy"]): the kubelet runs it as one program name, and no shell splits it.
func probeExecWhy(exe, image string) string {
	if len(strings.Fields(exe)) > 1 {
		return fmt.Sprintf("has the command line %q as one item, so the kubelet looks for a program with that whole name, spaces included, and there is none: an exec probe's command is a list of arguments, and no shell splits it", exe)
	}
	return fmt.Sprintf("runs %s, which is not in image %s", exe, image)
}

func probeExecFix(exe string) string {
	if words := strings.Fields(exe); len(words) > 1 {
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = strconv.Quote(w)
		}
		return fmt.Sprintf("Write each word of the probe's command as its own item: command: [%s]. If it needs a pipe, && or a variable, run it through a shell: [\"sh\", \"-c\", %s].", strings.Join(quoted, ", "), strconv.Quote(exe))
	}
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
	if pr := probeScheme(ix, p, cs, "readiness"); pr != nil {
		return pr
	}
	if pr := probeHost(ix, p, cs, "readiness"); pr != nil {
		return pr
	}
	if pr := probeGRPC(ix, p, cs, "readiness"); pr != nil {
		return pr
	}
	if pr := probeUDP(ix, p, cs, "readiness"); pr != nil {
		return pr
	}
	if pr := probeLoopback(ix, p, cs, "readiness"); pr != nil {
		return pr
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
		if what, how := probeStatus(ix, p, cs.Name, "readiness"); what != "" {
			cause += ": " + what
			fix = how
		}
		if probeTimedOut(ix, p, cs.Name, "readiness") && c.ReadinessProbe != nil {
			limit := c.ReadinessProbe.TimeoutSeconds
			if limit == 0 {
				limit = 1 // the API's default
			}
			cause = fmt.Sprintf("container %s runs but its readiness probe times out: the app does not answer within the probe's %ds timeoutSeconds, so it gets no traffic", cs.Name, limit)
			fix = fmt.Sprintf("Raise the readiness probe's timeoutSeconds above how long the check takes (it is %ds), or make the health check cheaper: one that waits on a database or another service is slow whenever they are.", limit)
		}
		if exe := probeExecMissing(ix, p, cs.Name, "readiness"); exe != "" {
			cause = fmt.Sprintf("container %s's readiness probe %s, so the probe can never pass and the container gets no traffic", cs.Name, probeExecWhy(exe, imageOf(p, cs)))
			fix = probeExecFix(exe)
		}
		return newProblem(p, cs.Name, "KD120", "Readiness probe failing", Critical, cause, "ready|"+describeProbe(c, c.ReadinessProbe), fix,
			eventEvidence(p.Ref(), e), Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s is running but not ready", cs.Name),
				Command: cmdContainerState(p, cs.Name, "ready")})
	}
	return readinessNotYet(ix, p, cs)
}

// readinessDelayLong is the initialDelaySeconds past which a readiness probe that has not run yet is reported: a
// delay that long keeps the pod out of its Services after every start and restart, which a startupProbe would not.
const readinessDelayLong = 300

// readinessNotYet finds a running container that is not ready because its readiness probe has not run yet: its
// initialDelaySeconds is long and has not passed since the container started, and no probe has failed.
func readinessNotYet(ix *index, p kube.Pod, cs kube.ContainerStatus) *problem {
	c, _ := containerSpec(p, cs.Name)
	pr := c.ReadinessProbe
	if pr == nil || pr.InitialDelaySeconds < readinessDelayLong || cs.State.Running == nil || cs.State.Running.StartedAt.IsZero() {
		return nil
	}
	delay := time.Duration(pr.InitialDelaySeconds) * time.Second
	up := ix.s.CollectedAt.Sub(cs.State.Running.StartedAt)
	if up >= delay {
		return nil
	}
	return newProblem(p, cs.Name, "KD211", "Readiness probe has not run yet", Warning,
		fmt.Sprintf("container %s has run for %s and is not ready because its readiness probe waits initialDelaySeconds %d (%s) before its first check, so the pod gets no traffic until then, after every start and restart", cs.Name, up.Round(time.Second), pr.InitialDelaySeconds, delay),
		"readydelay|"+cs.Name,
		"For an app that starts slowly, give it a startupProbe (it holds the other probes back only until the app is up) and a short readiness initialDelaySeconds.",
		Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's readiness probe has initialDelaySeconds %d", cs.Name, pr.InitialDelaySeconds),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].readinessProbe}`, cs.Name))},
		Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s started %s ago and is not ready", cs.Name, up.Round(time.Second)),
			Command: cmdContainerState(p, cs.Name, "state")})
}

var (
	reEmptyDirLimit  = regexp.MustCompile(`Usage of EmptyDir volume "([^"]+)" exceeds the limit "([^"]+)"`)
	reEphemeralLimit = regexp.MustCompile(`(?i)(?:Container (\S+) exceeded its local ephemeral storage limit "([^"]+)"|Pod ephemeral local storage usage exceeds the total limit of containers (\S+?)\.?\s*$)`)
	reNodeLow        = regexp.MustCompile(`The node was low on resource: ([a-z.-]+)`)
)

func evicted(p kube.Pod) *problem {
	msg := p.Status.Message
	ev := []Evidence{{Object: p.Ref(), What: "pod status is Failed, reason Evicted", Detail: msg,
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.status.message}")}}
	if m := reEmptyDirLimit.FindStringSubmatch(msg); m != nil {
		return &problem{rule: "KD193", title: "emptyDir volume exceeded its size limit", severity: Warning, pod: p,
			cause: fmt.Sprintf("the pod was evicted because emptyDir volume %s holds more than its %s sizeLimit", m[1], m[2]), key: "KD193|emptydir|" + m[1], evidence: ev,
			fix: fmt.Sprintf("Raise the sizeLimit of emptyDir volume %s, or have the app clean up what it writes there. With medium: Memory, what it holds also counts against the containers' memory limits.", m[1])}
	}
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

// deadlineExceeded explains a pod the kubelet stopped at its own spec.activeDeadlineSeconds. In a Job's pod template the
// field limits each attempt, not the Job, so a pod that needs longer fails every retry; the Job's
// spec.activeDeadlineSeconds is the one that bounds the whole Job.
func deadlineExceeded(ix *index, p kube.Pod) *problem {
	ev := []Evidence{{Object: p.Ref(), What: "pod status is Failed, reason DeadlineExceeded", Detail: p.Status.Message,
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.activeDeadlineSeconds}{\"\\n\"}{.status.message}")}}
	limit := "its spec.activeDeadlineSeconds"
	if d := p.Spec.ActiveDeadlineSeconds; d != nil {
		limit = fmt.Sprintf("its spec.activeDeadlineSeconds (%d s)", *d)
	}
	cause := fmt.Sprintf("the kubelet stopped the pod when it had run longer than %s (DeadlineExceeded), whatever its containers were doing", limit)
	fix := "Raise or remove activeDeadlineSeconds in the pod spec, or find why the pod runs that long (its logs)."
	if o, ok := p.Metadata.Controller(); ok && o.Kind == "Job" {
		cause += "; in a Job's pod template the deadline applies to each attempt, so every retry is stopped the same way"
		fix = "Remove activeDeadlineSeconds from the Job's pod template, or raise it above how long one attempt takes; to bound the whole Job, set the Job's own spec.activeDeadlineSeconds."
	}
	return &problem{rule: "KD195", title: "Pod ran past its activeDeadlineSeconds", severity: Critical, pod: p,
		cause: cause, key: "KD195", evidence: ev, fix: fix}
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

// csiMissing reports a volume whose CSI driver is not running: not registered with the kubelet on the pod's node,
// or with no attacher to attach the volume.
func csiMissing(p kube.Pod, driver string, e kube.Event) *problem {
	node := orNode(p.Spec.NodeName)
	cause := fmt.Sprintf("a volume of the pod uses CSI driver %s, which is not registered on %s, so the volume cannot be mounted", driver, node)
	if strings.Contains(e.Message, "external-attacher") {
		cause = fmt.Sprintf("a volume of the pod uses CSI driver %s, and no attacher for it answered, so the volume is never attached", driver)
	}
	return newProblem(p, "", "KD136", "CSI driver is not running", Critical, cause, "csi|"+driver,
		fmt.Sprintf("Install the %s CSI driver, or check that its node DaemonSet runs on %s and its controller is up (their pods are usually in kube-system or the driver's namespace).", driver, node),
		eventEvidence(p.Ref(), e),
		Evidence{Object: kube.Ref{Kind: "CSINode", Name: p.Spec.NodeName}, What: "the CSI drivers registered on " + node,
			Command: "kubectl get csinodes -o custom-columns=NODE:.metadata.name,DRIVERS:.spec.drivers[*].name"})
}

// reProbeTimeout matches the kubelet's report that an HTTP, TCP or exec probe ran out of time.
var reProbeTimeout = regexp.MustCompile(`Client\.Timeout exceeded|context deadline exceeded|command timed out|command ".*" timed out|i/o timeout`)

// probeTimedOut reports whether the newest failure of the probe of the given kind was a timeout.
func probeTimedOut(ix *index, p kube.Pod, container, kind string) bool {
	for _, e := range ix.eventsFor(p.Ref(), "Unhealthy") {
		if mentionsContainer(e, container) && strings.HasPrefix(strings.ToLower(e.Message), kind+" probe") {
			return reProbeTimeout.MatchString(e.Message)
		}
	}
	return false
}

func orReason(r string) string {
	if r == "" {
		return "a plain exit"
	}
	return r
}

// nodeRuntime returns the container runtime a node reports, such as containerd://2.1.4; empty when not known.
func nodeRuntime(ix *index, name string) string {
	for _, n := range ix.s.Nodes {
		if n.Metadata.Name == name {
			return n.Status.NodeInfo.ContainerRuntimeVersion
		}
	}
	return ""
}

// dockerSocket reports whether a path is Docker Engine's socket.
func dockerSocket(path string) bool {
	return path == "/var/run/docker.sock" || path == "/run/docker.sock"
}

var (
	reXmx         = regexp.MustCompile(`-Xmx(\d+)([kKmMgGtT]?)\b`)
	reNodeHeap    = regexp.MustCompile(`--max-old-space-size=(\d+)`)
	reMemEnvName  = regexp.MustCompile(`(?i)(MEMORY|HEAP|CACHE|BUFFER)\w*_(MB|MIB)$`)
	reGoMemLimit  = regexp.MustCompile(`^(\d+)(B|KiB|MiB|GiB|TiB)$`)
	memUnitFactor = map[string]float64{"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40, "B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}
)

// memorySetting finds the memory an app is told it may use, in its command, arguments or environment: a JVM's -Xmx
// (also in JAVA_OPTS and the like), Node's --max-old-space-size, Go's GOMEMLIMIT, or a variable such as
// CACHE_SIZE_MB. It returns where the setting is, the setting as written, and its size in bytes.
func memorySetting(c kube.Container) (where, setting string, size float64, ok bool) {
	for _, a := range append(append([]string{}, c.Command...), c.Args...) {
		if w, s, n, ok := memoryIn(a); ok {
			return w, s, n, true
		}
	}
	for _, e := range c.Env {
		if w, s, n, ok := memoryIn(e.Value); ok && w != "" {
			return "variable " + e.Name, s, n, true
		}
		if m := reGoMemLimit.FindStringSubmatch(e.Value); m != nil && e.Name == "GOMEMLIMIT" {
			n, _ := strconv.ParseFloat(m[1], 64)
			return "the environment", e.Name + "=" + e.Value, n * memUnitFactor[m[2]], true
		}
		if v, err := strconv.ParseFloat(e.Value, 64); err == nil && reMemEnvName.MatchString(e.Name) {
			return "the environment", e.Name + "=" + e.Value, v * (1 << 20), true
		}
	}
	return "", "", 0, false
}

// memoryIn reads a JVM or Node heap flag out of one argument or variable value.
func memoryIn(s string) (where, setting string, size float64, ok bool) {
	if m := reXmx.FindStringSubmatch(s); m != nil {
		n, _ := strconv.ParseFloat(m[1], 64)
		return "the command line", m[0], n * memUnitFactor[strings.ToLower(m[2])], true
	}
	if m := reNodeHeap.FindStringSubmatch(s); m != nil {
		n, _ := strconv.ParseFloat(m[1], 64)
		return "the command line", m[0], n * (1 << 20), true
	}
	return "", "", 0, false
}

// sidecarBlocks names the containers that wait for a sidecar whose startup probe has not passed: the init containers
// after it and every app container. The kubelet starts them only once each sidecar before them has started.
func sidecarBlocks(p kube.Pod, sidecar, kind string) string {
	if kind != "startup" || !p.IsSidecar(sidecar) {
		return ""
	}
	var waiting []string
	after := false
	for _, c := range p.Spec.InitContainers {
		if after {
			waiting = append(waiting, c.Name)
		}
		after = after || c.Name == sidecar
	}
	for _, c := range p.Spec.Containers {
		waiting = append(waiting, c.Name)
	}
	if len(waiting) == 0 {
		return ""
	}
	return "container " + strings.Join(waiting, ", ")
}
