package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	reSysctl   = regexp.MustCompile(`forbidden sysctl: "([^"]+)"`)
	reOutOfRes = regexp.MustCompile(`Node didn't have enough resource: ([a-zA-Z0-9./-]+), requested: (\d+), used: (\d+), capacity: (\d+)`)
)

// nodeRejected explains a pod the kubelet refused to run (phase Failed with the kubelet's admission reason): a sysctl
// the node does not allow, or a pod that needs more of a resource than the node has left. A Deployment's ReplicaSet
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
			fmt.Sprintf("the pod sets sysctl %s, which is not in the kubelet's safe set and not allowed on %s, so the kubelet rejects the pod (SysctlForbidden)", name, orNode(node)),
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
	}
	return nil
}
