package diagnose

import (
	"fmt"
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
