package diagnose

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

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
	case strings.Contains(r.text, "PersistentVolumeClaim") || strings.Contains(r.text, "persistentvolumeclaim"):
		return pvcBlocked(ix, p, r.text), "it waits for a PersistentVolumeClaim"
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
	if bestNode != "" && req > best {
		cause = fmt.Sprintf("the pod requests %s %s, more than any node can offer (the largest, %s, has %s allocatable)",
			kube.FormatQuantity(res, req), res, bestNode, kube.FormatQuantity(res, best))
		phrase = fmt.Sprintf("it requests %s %s and the largest node has %s", kube.FormatQuantity(res, req), res, kube.FormatQuantity(res, best))
		fix = fmt.Sprintf("Lower the pod's %s request below %s, or add a node with more %s.", res, kube.FormatQuantity(res, best), res)
	} else if req > 0 {
		cause = fmt.Sprintf("the pod requests %s %s and no node has that much free (other pods hold the rest)", kube.FormatQuantity(res, req), res)
	}
	if bestNode != "" {
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Node", Name: bestNode},
			What:    fmt.Sprintf("the largest node, %s, has %s %s allocatable", bestNode, kube.FormatQuantity(res, best), res),
			Command: fmt.Sprintf("kubectl get nodes -o custom-columns=NAME:.metadata.name,%s:.status.allocatable.%s", strings.ToUpper(strings.NewReplacer(".", "_", "/", "_").Replace(res)), strings.ReplaceAll(res, ".", `\.`))})
	}
	return newProblem(p, "", "KD140", "No node has enough "+res, Critical, cause, "insufficient|"+res, fix, ev...), phrase
}

// pvcBlocked points the pod at the claim it waits for, so it joins that claim's finding.
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
