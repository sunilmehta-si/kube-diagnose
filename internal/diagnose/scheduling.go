package diagnose

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// schedReason is one clause of the scheduler's "0/N nodes are available: ..." message.
type schedReason struct {
	nodes int
	text  string
}

var (
	reSchedClause = regexp.MustCompile(`^(\d+) (.+)$`)
	reSchedTotal  = regexp.MustCompile(`\d+/(\d+) nodes are available: `)
)

// parseSchedulerMessage splits "0/3 nodes are available: 1 Insufficient cpu, 2 node(s) had untolerated taint {a: b}.
// preemption: ..." into its clauses. The preemption part repeats the same nodes and is dropped.
func parseSchedulerMessage(msg string) []schedReason {
	if i := strings.Index(msg, " preemption:"); i >= 0 {
		msg = msg[:i]
	}
	m := reSchedTotal.FindStringSubmatchIndex(msg)
	if m == nil {
		return nil
	}
	total, _ := strconv.Atoi(msg[m[2]:m[3]])
	body := strings.TrimSuffix(strings.TrimSpace(msg[m[1]:]), ".")
	var out []schedReason
	// Clauses are separated by ", "; a clause names how many nodes it rejected, or none when it is about the pod
	// itself ("pod has unbound immediate PersistentVolumeClaims"), which rejects every node.
	for _, part := range splitClauses(body) {
		part = strings.TrimSpace(part)
		if m := reSchedClause.FindStringSubmatch(part); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, schedReason{nodes: n, text: m[2]})
		} else if part != "" {
			out = append(out, schedReason{nodes: total, text: part})
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].nodes > out[b].nodes })
	return out
}

func splitClauses(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			depth--
		case ',':
			if depth == 0 && i+1 < len(s) && s[i+1] == ' ' && i+2 < len(s) && s[i+2] >= '0' && s[i+2] <= '9' {
				out = append(out, s[start:i])
				start = i + 2
			}
		}
	}
	return append(out, s[start:])
}

var (
	reInsufficient = regexp.MustCompile(`^Insufficient (\S+)$`)
	reTaint        = regexp.MustCompile(`taint \{([^}]*)\}`)
)

func unschedulable(ix *index, p kube.Pod, c kube.Condition) *problem {
	msg := c.Message
	ev := []Evidence{{Object: p.Ref(), What: "pod is not scheduled: " + c.Reason, Detail: msg,
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.status.conditions[?(@.type=="PodScheduled")].message}`)}}
	reasons := parseSchedulerMessage(msg)
	if len(reasons) == 0 {
		for _, e := range ix.eventsFor(p.Ref(), "FailedScheduling") {
			if reasons = parseSchedulerMessage(e.Message); len(reasons) > 0 {
				ev = append(ev, eventEvidence(p.Ref(), e))
				break
			}
		}
	}
	var parts []string
	var first *problem
	for _, r := range reasons {
		pr, part := classifySched(ix, p, r)
		parts = append(parts, part)
		if first == nil {
			first = pr
		}
	}
	if first == nil {
		return newProblem(p, "", "KD149", "Pod cannot be scheduled", Critical,
			"the scheduler places the pod on no node: "+msg, "sched|"+msg,
			"Read the scheduler's message in the evidence; it lists why each node was rejected.", ev...)
	}
	first.evidence = append(ev, first.evidence...)
	if len(parts) > 1 {
		first.cause = "no node can run the pod: " + strings.Join(parts, "; ")
	}
	return first
}

// classifySched turns one scheduler clause into a problem with its own evidence, and a short phrase for the cause.
func classifySched(ix *index, p kube.Pod, r schedReason) (*problem, string) {
	nodes := plural(r.nodes, "node")
	switch {
	case reInsufficient.MatchString(r.text):
		res := reInsufficient.FindStringSubmatch(r.text)[1]
		return insufficient(ix, p, res, r.nodes)
	case strings.Contains(r.text, "didn't match Pod's node affinity/selector"):
		phrase := nodesVerb(r.nodes, "does not match", "do not match") + " its node selector or affinity"
		cause := "no node matches the pod's node selector or affinity"
		var ev []Evidence
		if len(p.Spec.NodeSelector) > 0 {
			sel := kube.FormatMap(p.Spec.NodeSelector)
			cause = fmt.Sprintf("no node has the labels %s that the pod's nodeSelector requires", sel)
			phrase = nodesVerb(r.nodes, "lacks", "lack") + " the labels " + sel
			ev = append(ev, Evidence{Object: p.Ref(), What: "pod requires node labels " + sel,
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.nodeSelector}")})
			if ix.read("nodes") {
				ev = append(ev, Evidence{Object: kube.Ref{Kind: "Node", Name: "*"},
					What:    fmt.Sprintf("none of the %d nodes has %s", len(ix.s.Nodes), sel),
					Command: "kubectl get nodes -l " + sel})
			}
		}
		return newProblem(p, "", "KD141", "No node matches the pod's node selector", Critical, cause,
			"selector|"+kube.FormatMap(p.Spec.NodeSelector),
			"Label a node to match (kubectl label node), or correct the pod's nodeSelector or affinity.", ev...), phrase
	case strings.Contains(r.text, "taint"):
		taint := ""
		if m := reTaint.FindStringSubmatch(r.text); m != nil {
			taint = m[1]
		}
		cause := nodesVerb(r.nodes, "has", "have") + " a taint the pod does not tolerate"
		if taint != "" {
			cause = fmt.Sprintf("%s taint %s, which the pod does not tolerate", nodesVerb(r.nodes, "has", "have"), taint)
		}
		return newProblem(p, "", "KD142", "Nodes have taints the pod does not tolerate", Critical, cause, "taint|"+taint,
			"Add a matching toleration to the pod if it belongs on those nodes, or remove the taint from them.",
			Evidence{Object: kube.Ref{Kind: "Node", Name: "*"}, What: "node taints",
				Command: `kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints`}), cause
	case strings.Contains(r.text, "were unschedulable"):
		cause := nodesVerb(r.nodes, "is", "are") + " cordoned (unschedulable)"
		return newProblem(p, "", "KD142", "Nodes are cordoned", Critical, cause, "cordoned",
			"Uncordon a node (kubectl uncordon) once its maintenance is done, or add nodes.",
			Evidence{Object: kube.Ref{Kind: "Node", Name: "*"}, What: "cordoned nodes",
				Command: `kubectl get nodes -o custom-columns=NAME:.metadata.name,UNSCHEDULABLE:.spec.unschedulable`}), cause
	case strings.Contains(r.text, "ReadWriteOncePod"):
		pr := claimHeld(ix, p, r.text)
		return pr, pr.cause
	case strings.Contains(r.text, "PersistentVolumeClaim") || strings.Contains(r.text, "persistentvolumeclaim"):
		return pvcBlocked(ix, p, r.text), "it waits for a PersistentVolumeClaim"
	case strings.Contains(r.text, "topology spread constraints") || strings.Contains(r.text, "pod affinity rules") ||
		strings.Contains(r.text, "pod anti-affinity rules"):
		what := "its pod anti-affinity rules"
		switch {
		case strings.Contains(r.text, "topology spread"):
			what = "its topology spread constraints"
		case strings.Contains(r.text, "pod affinity rules"):
			what = "its pod affinity rules"
		}
		cause := fmt.Sprintf("%s %s", nodesVerb(r.nodes, "fails", "fail"), what)
		if strings.Contains(r.text, "missing required label") {
			cause += " (they lack the label the constraint's topologyKey names)"
		}
		return newProblem(p, "", "KD144", "Pod spread or affinity rules cannot be met", Critical,
			"no node can run the pod: "+cause, "spread|"+what,
			"Add nodes in the missing topology domains, relax the rule (whenUnsatisfiable: ScheduleAnyway, preferred instead of required affinity), or lower the replica count.",
			Evidence{Object: p.Ref(), What: "pod scheduling constraints",
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.topologySpreadConstraints}{\"\\n\"}{.spec.affinity}")}), cause
	case strings.Contains(r.text, "volume node affinity conflict"):
		var vols []string
		var ev []Evidence
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim == nil {
				continue
			}
			if pvc, ok := ix.pvcs[nsName{p.Metadata.Namespace, v.PersistentVolumeClaim.ClaimName}]; ok && pvc.Spec.VolumeName != "" {
				vols = append(vols, fmt.Sprintf("%s (claim %s)", pvc.Spec.VolumeName, pvc.Metadata.Name))
				ev = append(ev, Evidence{Object: kube.Ref{Kind: "PersistentVolume", Name: pvc.Spec.VolumeName},
					What:    fmt.Sprintf("claim %s is bound to PersistentVolume %s", pvc.Metadata.Name, pvc.Spec.VolumeName),
					Command: cmdGet("pv", "", pvc.Spec.VolumeName, "{.spec.nodeAffinity}")})
			}
		}
		cause := nodesVerb(r.nodes, "is", "are") + " outside the node or zone the pod's volume is pinned to"
		if len(vols) > 0 {
			cause = fmt.Sprintf("%s outside the node or zone that volume %s is pinned to", nodesVerb(r.nodes, "is", "are"), strings.Join(vols, ", "))
		}
		return newProblem(p, "", "KD154", "Volume is pinned to a node or zone the pod cannot use", Critical,
			"no node can run the pod: "+cause, "volaffinity|"+strings.Join(vols, ","),
			"Make a node in the volume's zone available to the pod (capacity, taints, nodeSelector), or use a StorageClass with volumeBindingMode: WaitForFirstConsumer so new volumes are created where the pod can run.",
			ev...), cause
	case strings.Contains(r.text, "didn't have free ports"):
		ports := hostPorts(p)
		cause := nodesVerb(r.nodes, "has", "have") + " the pod's hostPort in use already"
		if len(ports) > 0 {
			cause = fmt.Sprintf("%s hostPort %s in use already", nodesVerb(r.nodes, "has", "have"), strings.Join(ports, ", "))
		}
		return newProblem(p, "", "KD145", "Host port is taken on every node", Critical, "no node can run the pod: "+cause,
			"hostport|"+strings.Join(ports, ","),
			"Drop hostPort and reach the pod through a Service, or run at most one such pod per node (a DaemonSet, or fewer replicas than nodes).",
			Evidence{Object: p.Ref(), What: "pod requests host ports " + strings.Join(ports, ", "),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.containers[*].ports}")}), cause
	case r.text == "Too many pods":
		return insufficient(ix, p, "pods", r.nodes)
	}
	cause := fmt.Sprintf("%s: %s", nodes, r.text)
	return newProblem(p, "", "KD149", "Pod cannot be scheduled", Critical, "no node can run the pod: "+cause,
		"sched|"+r.text, "Read the scheduler's message in the evidence; it lists why each node was rejected."), cause
}

// nodesVerb writes "1 node has" or "3 nodes have".
func nodesVerb(n int, one, many string) string {
	if n == 1 {
		return "1 node " + one
	}
	return fmt.Sprintf("%d nodes %s", n, many)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// podRequest is what the scheduler counts: the sum over containers, or the largest init container if that is more.
func podRequest(p kube.Pod, res string) float64 {
	var sum, initMax float64
	for _, c := range p.Spec.Containers {
		if q, err := kube.ParseQuantity(c.Resources.Requests[res]); err == nil {
			sum += q
		} else if q, err := kube.ParseQuantity(c.Resources.Limits[res]); err == nil {
			sum += q // a limit without a request defaults the request to the limit
		}
	}
	for _, c := range p.Spec.InitContainers {
		if q, err := kube.ParseQuantity(c.Resources.Requests[res]); err == nil && q > initMax {
			initMax = q
		}
	}
	if initMax > sum {
		return initMax
	}
	return sum
}

// cpuUnitSlip finds a container whose cpu request is a bare whole number of 100 or more (cpu: 500): Kubernetes reads it
// as that many cores, and no node has them, where 500m, half a core, was almost certainly meant. A request a LimitRange
// filled in is not the pod's own writing, and is left to the LimitRange explanation.
func cpuUnitSlip(p kube.Pod, res string) (container, value string) {
	if res != "cpu" {
		return "", ""
	}
	for _, c := range append(append([]kube.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
		v := c.Resources.Requests["cpu"]
		if n, err := strconv.Atoi(v); err == nil && n >= 100 {
			return c.Name, v
		}
	}
	return "", ""
}

// coreFraction says what n millicores are, as a fraction of a core.
func coreFraction(v string) string {
	n, _ := strconv.Atoi(v)
	switch {
	case n == 500:
		return "half"
	case n == 250:
		return "a quarter"
	case n == 100:
		return "a tenth"
	}
	return fmt.Sprintf("%g", float64(n)/1000)
}

func insufficient(ix *index, p kube.Pod, res string, nodes int) (*problem, string) {
	req := podRequest(p, res)
	var best float64
	var bestNode string
	for _, n := range ix.s.Nodes {
		if q, err := kube.ParseQuantity(n.Status.Allocatable[res]); err == nil && q > best {
			best, bestNode = q, n.Metadata.Name
		}
	}
	phrase := nodesVerb(nodes, "has", "have") + " too little free " + res
	cause := fmt.Sprintf("no node has enough free %s for the pod", res)
	var ev []Evidence
	if req > 0 {
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("pod requests %s %s", kube.FormatQuantity(res, req), res),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.containers[*].resources.requests}")})
	}
	fix := fmt.Sprintf("Lower the pod's %s request to what it needs, free %s on a node, or add a node with more.", res, res)
	if bestNode == "" && strings.Contains(res, "/") && ix.read("nodes") && len(ix.s.Nodes) > 0 {
		cause = fmt.Sprintf("the pod requests %s, and no node advertises any (%s checked): the device plugin that provides it is not running", res, plural(len(ix.s.Nodes), "node"))
		phrase = "no node advertises " + res
		fix = fmt.Sprintf("Install or fix the device plugin that provides %s (for nvidia.com/gpu, the NVIDIA device plugin or GPU Operator) and check its DaemonSet runs on the nodes that have the hardware; or remove the request.", res)
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Node", Name: "*"}, What: fmt.Sprintf("no node lists %s in its allocatable resources", res),
			Command: fmt.Sprintf("kubectl get nodes -o custom-columns=NAME:.metadata.name,%s:.status.allocatable.%s", strings.ToUpper(strings.NewReplacer(".", "_", "/", "_").Replace(res)), strings.ReplaceAll(res, ".", `\.`))})
	} else if bestNode != "" && req > best {
		cause = fmt.Sprintf("the pod requests %s %s, more than any node can offer (the largest, %s, has %s allocatable)",
			kube.FormatQuantity(res, req), res, bestNode, kube.FormatQuantity(res, best))
		phrase = fmt.Sprintf("it requests %s %s and the largest node has %s", kube.FormatQuantity(res, req), res, kube.FormatQuantity(res, best))
		fix = fmt.Sprintf("Lower the pod's %s request below %s, or add a node with more %s.", res, kube.FormatQuantity(res, best), res)
	} else if req > 0 {
		cause = fmt.Sprintf("the pod requests %s %s and no node has that much free (other pods hold the rest)", kube.FormatQuantity(res, req), res)
	}
	if c, v := cpuUnitSlip(p, res); c != "" && limitRangerSet(p, res) == "" {
		cause += fmt.Sprintf("; container %s asks for cpu: %s, which is %s whole cores: millicores need the m suffix (%sm is %s of a core)", c, v, v, v, coreFraction(v))
		fix = fmt.Sprintf("Write container %s's cpu request as %sm if it means millicores, and its limit the same way.", c, v)
	}
	if c := limitRangerSet(p, res); c != "" && req > 0 {
		cause += fmt.Sprintf("; the pod template sets no %s request for container %s: the namespace's LimitRange gave it its default", res, c)
		fix = fmt.Sprintf("Set container %s's own %s request in the pod template, or lower the defaultRequest for %s in the namespace's LimitRange.", c, res, res)
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("the LimitRanger admission plugin set container %s's %s request", c, res),
			Detail:  p.Metadata.Annotations[limitRangerAnnotation],
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.metadata.annotations.kubernetes\.io/limit-ranger}`)},
			Evidence{Object: kube.Ref{Kind: "LimitRange", Namespace: p.Metadata.Namespace, Name: "*"}, What: "the namespace's LimitRanges",
				Command: "kubectl get limitranges -n " + p.Metadata.Namespace + " -o yaml"})
	}
	if bestNode != "" {
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Node", Name: bestNode},
			What:    fmt.Sprintf("the largest node, %s, has %s %s allocatable", bestNode, kube.FormatQuantity(res, best), res),
			Command: fmt.Sprintf("kubectl get nodes -o custom-columns=NAME:.metadata.name,%s:.status.allocatable.%s", strings.ToUpper(strings.NewReplacer(".", "_", "/", "_").Replace(res)), strings.ReplaceAll(res, ".", `\.`))})
	}
	return newProblem(p, "", "KD140", "No node has enough "+res, Critical, cause, "insufficient|"+res, fix, ev...), phrase
}

// pvcBlocked points the pod at the claim it waits for, so it joins that claim's finding.
// claimHeld explains a pod the scheduler holds back because a ReadWriteOncePod claim it mounts is in use by another
// pod: only one pod in the cluster may use such a claim, so a second replica waits until the first is gone.
func claimHeld(ix *index, p kube.Pod, text string) *problem {
	ns := p.Metadata.Namespace
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		claim := v.PersistentVolumeClaim.ClaimName
		pvc, ok := ix.pvcs[nsName{ns, claim}]
		if !ok || !slices.Contains(pvc.Spec.AccessModes, "ReadWriteOncePod") {
			continue
		}
		ev := []Evidence{{Object: kube.Ref{Kind: "PersistentVolumeClaim", Namespace: ns, Name: claim},
			What: fmt.Sprintf("PersistentVolumeClaim %s has access mode ReadWriteOncePod", claim), Command: cmdGet("pvc", ns, claim, "{.spec.accessModes}")}}
		holder := "another pod"
		for _, o := range ix.s.Pods {
			if o.Metadata.Namespace != ns || o.Metadata.Name == p.Metadata.Name || o.Spec.NodeName == "" || o.Status.Phase == "Succeeded" || o.Status.Phase == "Failed" {
				continue
			}
			for _, ov := range o.Spec.Volumes {
				if ov.PersistentVolumeClaim != nil && ov.PersistentVolumeClaim.ClaimName == claim {
					holder = "pod " + o.Metadata.Name
					ev = append(ev, Evidence{Object: o.Ref(), What: fmt.Sprintf("pod %s mounts %s on node %s", o.Metadata.Name, claim, o.Spec.NodeName),
						Command: cmdGet("pod", ns, o.Metadata.Name, "{.spec.nodeName}")})
				}
			}
			if holder != "another pod" {
				break
			}
		}
		owner := "the workload"
		if o := ix.owner(p); o != p.Ref() {
			owner = o.Kind + " " + o.Name
		}
		return newProblem(p, "", "KD147", "Another pod holds the ReadWriteOncePod claim", Critical,
			fmt.Sprintf("the pod mounts PersistentVolumeClaim %s, whose access mode ReadWriteOncePod lets only one pod in the cluster use it, and %s already does, so the scheduler keeps this one Pending", claim, holder),
			"rwop|"+claim,
			fmt.Sprintf("Run one replica of %s (a claim per replica needs a StatefulSet's volumeClaimTemplates), or use ReadWriteOnce if pods on one node may share the volume; with a rolling update, use strategy Recreate so the old pod lets go of the claim first.", owner),
			ev...)
	}
	return newProblem(p, "", "KD147", "Another pod holds the ReadWriteOncePod claim", Critical,
		"a ReadWriteOncePod claim the pod mounts is in use by another pod: "+text, "rwop|"+text,
		"Only one pod may use a ReadWriteOncePod claim: run one replica, or give each pod its own claim.")
}

func pvcBlocked(ix *index, p kube.Pod, text string) *problem {
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		claim := v.PersistentVolumeClaim.ClaimName
		pvc, ok := ix.pvcs[nsName{p.Metadata.Namespace, claim}]
		ref := kube.Ref{Kind: "PersistentVolumeClaim", Namespace: p.Metadata.Namespace, Name: claim}
		if !ok && ix.read("persistentvolumeclaims") {
			return newProblem(p, "", "KD153", "PersistentVolumeClaim does not exist", Critical,
				fmt.Sprintf("the pod mounts PersistentVolumeClaim %s, which does not exist in namespace %s", claim, p.Metadata.Namespace),
				"nopvc|"+claim, fmt.Sprintf("Create PersistentVolumeClaim %s, or correct the claimName in the pod spec.", claim),
				Evidence{Object: ref, What: "there is no PersistentVolumeClaim " + claim, Command: cmdGet("pvc", p.Metadata.Namespace, claim, "")})
		}
		if ok && pvc.Status.Phase != "Bound" {
			pr := newProblem(p, "", "KD143", "Pod waits for a PersistentVolumeClaim", Critical,
				fmt.Sprintf("the pod waits for PersistentVolumeClaim %s, which is %s", claim, pvc.Status.Phase), "pvc|"+claim, "")
			pr.linkTo = &ref
			return pr
		}
	}
	return newProblem(p, "", "KD143", "Pod waits for a PersistentVolumeClaim", Critical,
		"the pod waits for a PersistentVolumeClaim: "+text, "pvc|"+text, "Check the pod's PersistentVolumeClaims.")
}

// gatedAfter is how long a pod may sit behind a scheduling gate before it is reported: a controller that gates
// pods normally releases them within seconds.
const gatedAfter = 2 * time.Minute

// kueueGate is the gate Kueue puts on the plain pods it manages until it admits them.
const kueueGate = "kueue.x-k8s.io/admission"

// gated finds a pod that the scheduler has not been allowed to look at: it carries scheduling gates, and whatever
// set them has not removed them. The scheduler reports no error for such a pod, and it has no events.
func gated(ix *index, p kube.Pod) *problem {
	age := ix.s.CollectedAt.Sub(p.Metadata.CreationTimestamp)
	if len(p.Spec.SchedulingGates) == 0 || p.Metadata.CreationTimestamp.IsZero() || age < gatedAfter {
		return nil
	}
	var names []string
	kueue := false
	for _, g := range p.Spec.SchedulingGates {
		names = append(names, g.Name)
		kueue = kueue || g.Name == kueueGate
	}
	gates := strings.Join(names, ", ")
	ns := p.Metadata.Namespace
	ev := []Evidence{{Object: p.Ref(), What: "pod is not scheduled: SchedulingGated, with gates " + gates,
		Command: cmdGet("pod", ns, p.Metadata.Name, `{.spec.schedulingGates}{"\n"}{.status.conditions[?(@.type=="PodScheduled")]}`)}}
	cause := fmt.Sprintf("the pod has waited %s behind scheduling gate %s: the scheduler does not look at a pod until every gate is removed, and whatever set this one has not removed it", age.Round(time.Minute), gates)
	fix := fmt.Sprintf("Find the controller that owns gate %s and why it has not released the pod (it may not be running). If nothing owns the gate, remove schedulingGates from the pod template.", gates)
	if kueue {
		queue := p.Metadata.Labels["kueue.x-k8s.io/queue-name"]
		cause = fmt.Sprintf("the pod has waited %s behind Kueue's scheduling gate %s: Kueue has not admitted it, so the scheduler has not looked at it", age.Round(time.Minute), kueueGate)
		fix = "Read the pod's Workload (its conditions say why it is not admitted): the queue has no quota left, or the queue does not exist. The pod starts when Kueue admits it."
		if queue != "" {
			cause += fmt.Sprintf("; it is queued in LocalQueue %s", queue)
		}
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Workload", Namespace: ns, Name: "*"}, What: "Kueue's Workloads in the namespace, with their admission status",
			Command: "kubectl get workloads.kueue.x-k8s.io -n " + ns})
	}
	return newProblem(p, "", "KD146", "Pod is held by a scheduling gate", Critical, cause, "gate|"+gates, fix, ev...)
}

// nodeMissing finds a pod bound by spec.nodeName to a node the cluster does not have. nodeName skips the scheduler,
// so nothing reports it: no kubelet picks the pod up, and the pod garbage collector deletes it as an orphan, which
// its controller answers with a new pod bound the same way.
func nodeMissing(ix *index, p kube.Pod) *problem {
	if p.Status.Phase != "Pending" || p.Spec.NodeName == "" || !ix.read("nodes") || len(ix.s.Nodes) == 0 {
		return nil
	}
	names := make([]string, 0, len(ix.s.Nodes))
	for _, n := range ix.s.Nodes {
		if n.Metadata.Name == p.Spec.NodeName {
			return nil
		}
		names = append(names, n.Metadata.Name)
	}
	if len(names) > 5 {
		names = append(names[:5], fmt.Sprintf("and %d more", len(names)-5))
	}
	node := p.Spec.NodeName
	ev := []Evidence{
		{Object: p.Ref(), What: fmt.Sprintf("pod sets spec.nodeName %s", node), Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.nodeName}")},
		{Object: kube.Ref{Kind: "Node", Name: node}, What: fmt.Sprintf("there is no node %s", node), Command: "kubectl get nodes"},
	}
	return newProblem(p, "", "KD240", "Pod is bound to a node that does not exist", Critical,
		fmt.Sprintf("the pod sets spec.nodeName %s, which bypasses the scheduler, and the cluster has no such node (it has %s), so no kubelet runs the pod and the pod garbage collector deletes it", node, strings.Join(names, ", ")),
		"nonode|"+node, "Remove nodeName from the pod template and let the scheduler place the pod; to pin it to a node, use a nodeSelector on kubernetes.io/hostname with a node that exists.", ev...)
}

const limitRangerAnnotation = "kubernetes.io/limit-ranger"

// limitRangerSet returns the first container whose request for res the LimitRanger admission plugin filled in from
// a LimitRange default, as its annotation records: "LimitRanger plugin set: cpu, memory request for container web;
// cpu limit for container web".
func limitRangerSet(p kube.Pod, res string) string { return limitRangerSetKind(p, res, "request") }

// limitRangerSetKind returns the container whose request or limit (kind) for the resource the LimitRanger admission
// plugin filled in from a LimitRange default, as its annotation on the pod records, or "".
func limitRangerSetKind(p kube.Pod, res, kind string) string {
	a := strings.TrimPrefix(p.Metadata.Annotations[limitRangerAnnotation], "LimitRanger plugin set: ")
	for _, clause := range strings.Split(a, ";") {
		what, container, ok := strings.Cut(strings.TrimSpace(clause), " "+kind+" for container ")
		if !ok {
			continue
		}
		for _, r := range strings.Split(what, ",") {
			if strings.TrimSpace(r) == res {
				return strings.TrimSpace(container)
			}
		}
	}
	return ""
}
