package diagnose

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	reSysctl   = regexp.MustCompile(`forbidden sysctl: "([^"]+)"`) // "Pod was rejected: forbidden sysctl: \"net.core.somaxconn\" not allowlisted"
	reOutOfRes = regexp.MustCompile(`Node didn't have enough resource: ([a-zA-Z0-9./-]+), requested: (\d+), used: (\d+), capacity: (\d+)`)
)

// nodeRejected explains a pod the kubelet refused to run (phase Failed with the kubelet's admission reason): a sysctl
// the node does not allow, a pod that needs more of a resource than the node has left, or a pod that names its node in
// spec.nodeName and so skips the scheduler's checks of the node's labels and host ports. A Deployment's ReplicaSet
// replaces each rejected pod with another that is rejected the same way.
func nodeRejected(ix *index, p kube.Pod) *problem {
	reason, msg := p.Status.Reason, p.Status.Message
	ev := []Evidence{{Object: p.Ref(), What: fmt.Sprintf("pod status is Failed, reason %s", reason), Detail: msg,
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.status.reason}{\"\\n\"}{.status.message}")}}
	node := p.Spec.NodeName
	switch {
	case reason == "SysctlForbidden":
		name := "a sysctl"
		if m := reSysctl.FindStringSubmatch(msg); m != nil {
			name = m[1]
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: "the pod's sysctls",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.securityContext.sysctls}")})
		return newProblem(p, "", "KD232", "Node forbids the pod's sysctl", Critical,
			fmt.Sprintf("the pod sets sysctl %s, which is not on the kubelet's allowlist on %s (its safe set plus --allowed-unsafe-sysctls), so the kubelet rejects the pod (SysctlForbidden)", name, orNode(node)),
			"sysctl|"+name,
			fmt.Sprintf("Drop %s from securityContext.sysctls, or allow it on the nodes that should run the pod (kubelet --allowed-unsafe-sysctls=%s, then a nodeSelector or taint to keep the pod there); Pod Security baseline also refuses unsafe sysctls.", name, name), ev...)
	case strings.HasPrefix(reason, "OutOf"):
		res := strings.TrimPrefix(reason, "OutOf")
		detail := ""
		if m := reOutOfRes.FindStringSubmatch(msg); m != nil {
			res = m[1]
			detail = fmt.Sprintf(" (it asks for %s, %s of the node's %s are in use)", m[2], m[3], m[4])
		}
		bypass := ""
		if _, ok := kube.FindCondition(p.Status.Conditions, "PodScheduled"); !ok && node != "" {
			bypass = "; the pod sets spec.nodeName, so it skipped the scheduler, which would have kept it Pending and said why"
		}
		return newProblem(p, "", "KD241", "Node rejects the pod for lack of a resource", Critical,
			fmt.Sprintf("%s does not have enough %s left for the pod%s, so the kubelet rejects it (%s)%s", orNode(node), res, detail, reason, bypass),
			"outof|"+res,
			fmt.Sprintf("Lower the pod's %s request to what a node has free, or free that much on the node; leave spec.nodeName unset (use a nodeSelector) so the scheduler places the pod where it fits.", res), ev...)
	case reason == "NodeAffinity":
		want := kube.FormatMap(p.Spec.NodeSelector)
		missing := ""
		if n := findNode(ix, node); n != nil && len(p.Spec.NodeSelector) > 0 {
			var m []string
			for _, k := range sortedKeys(p.Spec.NodeSelector) {
				if v, ok := n.Metadata.Labels[k]; !ok || v != p.Spec.NodeSelector[k] {
					m = append(m, k+"="+p.Spec.NodeSelector[k])
				}
			}
			if len(m) > 0 {
				missing = fmt.Sprintf(" (the node lacks %s)", strings.Join(m, ", "))
			}
		}
		what := "its node affinity"
		if want != "" {
			what = "its nodeSelector " + want + missing
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: "the pod's nodeName, nodeSelector and affinity",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.nodeName}{\"\\n\"}{.spec.nodeSelector}{\"\\n\"}{.spec.affinity}")})
		return newProblem(p, "", "KD242", "Node rejects the pod: its labels do not match", Critical,
			fmt.Sprintf("the pod names %s in spec.nodeName, which skips the scheduler, but %s does not match that node's labels, so the kubelet rejects it (NodeAffinity)", orNode(node), what),
			"affinity|"+node,
			"Choose one way to place the pod: drop spec.nodeName and let the scheduler use the nodeSelector or affinity, or name a node whose labels match (kubectl get nodes --show-labels).", ev...)
	case reason == "PodOSNotSupported" || reason == "PodOSSelectorNodeLabelDoesNotMatch":
		nodeOS := "another operating system"
		if n := findNode(ix, node); n != nil && n.Metadata.Labels["kubernetes.io/os"] != "" {
			nodeOS = n.Metadata.Labels["kubernetes.io/os"]
		}
		what := "its kubernetes.io/os node selector"
		if p.Spec.OS != nil && p.Spec.OS.Name != "" {
			what = "spec.os.name " + p.Spec.OS.Name
		}
		bypass := "the scheduler does not compare spec.os with the node, so it placed the pod there"
		if reason == "PodOSSelectorNodeLabelDoesNotMatch" {
			bypass = "the pod names its node in spec.nodeName, which skips the scheduler's check of the label"
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: "the pod's spec.os and kubernetes.io/os node selector",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.spec.os}{"\n"}{.spec.nodeSelector}`)})
		return newProblem(p, "", "KD244", "Node rejects the pod: it is for another operating system", Critical,
			fmt.Sprintf("the pod's %s does not match %s, which runs %s; %s, and the kubelet rejects it (%s)", what, orNode(node), nodeOS, bypass, reason),
			"os|"+node,
			"Give the pod a nodeSelector kubernetes.io/os that matches spec.os.name, so the scheduler places it only on nodes of that operating system, or drop spec.os if the image is built for the nodes the cluster has.", ev...)
	case reason == "NodePorts":
		ports := strings.Join(hostPorts(p), ", ")
		ev = append(ev, Evidence{Object: p.Ref(), What: "the pod's host ports",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.containers[*].ports[*].hostPort}")})
		return newProblem(p, "", "KD243", "Node rejects the pod: its host port is taken", Critical,
			fmt.Sprintf("the pod names %s in spec.nodeName, which skips the scheduler, and asks for host port %s, which another pod on that node already holds, so the kubelet rejects it (NodePorts)", orNode(node), ports),
			"ports|"+node,
			"Drop hostPort if a Service can reach the pod instead, or leave spec.nodeName unset so the scheduler puts the pod on a node where the port is free (kubectl get pods -A -o wide shows what runs on the node).", ev...)
	}
	return nil
}

// findNode returns the named node from the snapshot, or nil.
func findNode(ix *index, name string) *kube.Node {
	for i := range ix.s.Nodes {
		if ix.s.Nodes[i].Metadata.Name == name {
			return &ix.s.Nodes[i]
		}
	}
	return nil
}

// hostPorts lists the host ports the pod's containers ask for.
func hostPorts(p kube.Pod) []string {
	var out []string
	for _, c := range p.Spec.Containers {
		for _, cp := range c.Ports {
			if cp.HostPort != 0 {
				out = append(out, strconv.Itoa(int(cp.HostPort)))
			}
		}
	}
	return out
}
