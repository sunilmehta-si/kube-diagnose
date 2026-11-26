package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// resizeInfeasible finds a pod whose in-place resize the kubelet will never carry out: the new requests do not fit
// the node at all (PodResizePending, reason Infeasible). The pod keeps running at its old size, the spec says the
// new one, and nothing else reports the mismatch.
func resizeInfeasible(p kube.Pod) *problem {
	c, ok := kube.FindCondition(p.Status.Conditions, "PodResizePending")
	if !ok || c.Status != "True" || c.Reason != "Infeasible" {
		return nil
	}
	node := p.Spec.NodeName
	cause := fmt.Sprintf("the pod's resources were resized in place, and node %s cannot hold the new size at all, so the kubelet leaves the containers at their old size: %s", node, strings.TrimSpace(c.Message))
	fix := fmt.Sprintf("Resize to what node %s can hold (its allocatable less what its other pods request), or recreate the pod with the new requests so the scheduler places it on a node that has room: a resize never moves a pod.", node)
	return newProblem(p, "", "KD247", "In-place resize cannot fit the node", Warning, cause, "resize|infeasible", fix,
		Evidence{Object: p.Ref(), What: "PodResizePending is True, reason Infeasible", Detail: c.Message,
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.status.conditions[?(@.type=="PodResizePending")]}`)},
		Evidence{Object: p.Ref(), What: "the containers' requests in the spec, and what they run with",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.spec.containers[*].resources}{"\n"}{.status.containerStatuses[*].resources}`)},
		Evidence{Object: kube.Ref{Kind: "Node", Name: node}, What: "the node's allocatable resources", Command: cmdGet("node", "", node, `{.status.allocatable}`)})
}

// reResizeRefused is the API server's refusal of an in-place resize the node cannot hold (Kubernetes 1.35 and later
// check it at admission), as a client that asked for it prints it.
var reResizeRefused = regexp.MustCompile(`pods "([^"]+)" is forbidden: node didn't have enough allocatable resources: (\w[\w.-]*), requested: (\d+), allocatable: (\d+)`)

// resizeRefused finds a container that exits because the API server refused the in-place resize it asked for: the
// new requests exceed what the pod's node has allocatable, and a resize never moves a pod to a bigger node.
func resizeRefused(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	for i := len(lines) - 1; i >= 0; i-- {
		m := reResizeRefused.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		target, res, req, alloc := m[1], m[2], m[3], m[4]
		unit := ""
		if res == "cpu" {
			unit = "m"
		}
		cause := fmt.Sprintf("container %s exits because the API server refused the in-place resize it asked for: pod %s's node has %s%s %s allocatable, and the resize asks for %s%s; a resize never moves a pod to a bigger node; its log says: %q",
			cs.Name, target, alloc, unit, res, req, unit, clip(lines[i], 200))
		fix := fmt.Sprintf("Ask for no more %s than pod %s's node can hold, or recreate the pod with the new requests so the scheduler places it on a node with room.", res, target)
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Pod", Namespace: p.Metadata.Namespace, Name: target}, What: fmt.Sprintf("pod %s's requests and its node", target),
			Command: cmdGet("pod", p.Metadata.Namespace, target, `{.spec.nodeName}{" "}{.spec.containers[*].resources}`)})
		return newProblem(p, cs.Name, "KD247", "In-place resize cannot fit the node", Critical, cause, "resize|refused|"+res, fix, ev...)
	}
	return nil
}
