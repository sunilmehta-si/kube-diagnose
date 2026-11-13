package diagnose

import (
	"fmt"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// nodeFindings reports nodes that are not ready or under pressure, with the pods on them that it affects.
func nodeFindings(ix *index) []Finding {
	var out []Finding
	for _, n := range ix.s.Nodes {
		ref := kube.Ref{Kind: "Node", Name: n.Metadata.Name}
		var affects []kube.Ref
		for _, p := range ix.s.Pods {
			if p.Spec.NodeName == n.Metadata.Name && p.Status.Phase != "Succeeded" && p.Status.Phase != "Failed" {
				affects = append(affects, p.Ref())
			}
		}
		if c, ok := kube.FindCondition(n.Status.Conditions, "Ready"); ok && c.Status != "True" {
			cause := fmt.Sprintf("node %s is not ready (%s): %s", n.Metadata.Name, c.Reason, c.Message)
			if c.Status == "Unknown" {
				cause = fmt.Sprintf("node %s has stopped reporting (its kubelet is down or unreachable): %s", n.Metadata.Name, c.Message)
			}
			out = append(out, Finding{Rule: "KD190", Title: "Node is not ready", Severity: Critical, Object: ref, Cause: cause,
				Evidence: []Evidence{{Object: ref, What: "Ready condition is " + c.Status + ", reason " + c.Reason, Detail: c.Message,
					Command: cmdGet("node", "", n.Metadata.Name, `{.status.conditions[?(@.type=="Ready")]}`)}},
				Fix:     "Check the node's kubelet and container runtime (systemctl status kubelet, journalctl -u kubelet) and its network; replace the node if it does not recover.",
				Affects: affects})
			continue
		}
		for _, typ := range []string{"MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"} {
			c, ok := kube.FindCondition(n.Status.Conditions, typ)
			if !ok || c.Status != "True" {
				continue
			}
			out = append(out, Finding{Rule: "KD191", Title: "Node is under " + typ, Severity: Warning, Object: ref,
				Cause: fmt.Sprintf("node %s reports %s: %s", n.Metadata.Name, typ, c.Message),
				Evidence: []Evidence{{Object: ref, What: typ + " is True", Detail: c.Message,
					Command: cmdGet("node", "", n.Metadata.Name, fmt.Sprintf(`{.status.conditions[?(@.type=="%s")]}`, typ))}},
				Fix:     "Free the resource on the node (large logs and images for disk, memory-hungry pods for memory) or move pods off it; pods may be evicted until it recovers.",
				Affects: affects})
		}
	}
	return out
}
