package diagnose

import (
	"fmt"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// nodeFindings reports nodes that are not ready or under pressure, with the pods on them that it affects.
// When the snapshot covers some namespaces only, a node is reported only if it runs pods in them: a node problem
// is cluster-wide, and would otherwise appear in every namespace's diagnosis.
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
		if len(ix.s.Namespaces) > 0 && len(affects) == 0 {
			continue
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

// stuckTerminatingAfter is how long past its deletion deadline a pod may linger before it is reported. The deletion
// timestamp is already the end of the grace period, so a healthy pod is gone well before this.
const stuckTerminatingAfter = 2 * time.Minute

// terminating finds a pod that was deleted and is still there long after its grace period ended: a finalizer nobody
// removes, or a node that cannot confirm the pod stopped.
func terminating(ix *index, p kube.Pod) *problem {
	over := ix.s.CollectedAt.Sub(*p.Metadata.DeletionTimestamp)
	if over < stuckTerminatingAfter {
		return nil
	}
	ns, name, node := p.Metadata.Namespace, p.Metadata.Name, p.Spec.NodeName
	ev := []Evidence{{Object: p.Ref(), What: fmt.Sprintf("pod was due to be gone at %s and is still terminating", p.Metadata.DeletionTimestamp.UTC().Format(time.RFC3339)),
		Command: cmdGet("pod", ns, name, `{.metadata.deletionTimestamp}{" "}{.metadata.finalizers}{" "}{.spec.nodeName}`)}}
	head := fmt.Sprintf("the pod was deleted and is still terminating %s after its grace period ended", over.Round(time.Minute))
	switch {
	case len(p.Metadata.Finalizers) > 0:
		fins := strings.Join(p.Metadata.Finalizers, ", ")
		return &problem{rule: "KD194", title: "Pod is stuck terminating", severity: Warning, pod: p, key: "KD194|finalizer|" + fins, evidence: ev,
			cause: fmt.Sprintf("%s: finalizer %s has not been removed, and a pod with a finalizer is not deleted until it is", head, fins),
			fix:   fmt.Sprintf("Find the controller that owns finalizer %s and why it has not finished (it may not be running). Only when it is gone for good, remove the finalizer by hand (kubectl patch pod %s -n %s --type=json -p '[{\"op\":\"remove\",\"path\":\"/metadata/finalizers\"}]').", fins, name, ns)}
	case node != "" && !nodeReady(ix, node):
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Node", Name: node}, What: "node " + node + " is not ready",
			Command: cmdGet("node", "", node, `{.status.conditions[?(@.type=="Ready")]}`)})
		return &problem{rule: "KD194", title: "Pod is stuck terminating", severity: Warning, pod: p, key: "KD194|node|" + node, evidence: ev,
			cause: fmt.Sprintf("%s: its node %s is not ready, so no kubelet can confirm the pod has stopped", head, node),
			fix:   fmt.Sprintf("Bring node %s back, or, if it is gone for good, delete the Node object, which lets the pods on it go. Force-deleting the pod (--grace-period=0 --force) is safe only when the node is really down.", node)}
	}
	return &problem{rule: "KD194", title: "Pod is stuck terminating", severity: Warning, pod: p, key: "KD194|kubelet", evidence: append(ev, eventsEvidence(p)),
		cause: fmt.Sprintf("%s: the kubelet on %s has not finished stopping it, usually because a container ignores SIGTERM past its grace period or a volume will not unmount", head, orNode(node)),
		fix:   "Read the pod's events (a FailedKillPod or volume unmount error names the cause) and the kubelet's log on that node."}
}

func nodeReady(ix *index, name string) bool {
	for _, n := range ix.s.Nodes {
		if n.Metadata.Name == name {
			c, ok := kube.FindCondition(n.Status.Conditions, "Ready")
			return ok && c.Status == "True"
		}
	}
	return true // not listed (another scope, or nodes not read): claim nothing about it
}

func eventsEvidence(p kube.Pod) Evidence {
	return Evidence{Object: p.Ref(), What: "the pod's events", Command: cmdEvents(p.Ref())}
}

func orNode(n string) string {
	if n == "" {
		return "its node"
	}
	return "node " + n
}
