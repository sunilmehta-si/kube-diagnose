package diagnose

import (
	"fmt"
	"regexp"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// appArmorOf returns the AppArmor profile a container runs under: its own, else the pod's; nil when neither sets
// one.
func appArmorOf(p kube.Pod, container string) *kube.AppArmorProfile {
	if c, ok := containerSpec(p, container); ok && c.SecurityContext != nil && c.SecurityContext.AppArmorProfile != nil {
		return c.SecurityContext.AppArmorProfile
	}
	if p.Spec.SecurityContext != nil {
		return p.Spec.SecurityContext.AppArmorProfile
	}
	return nil
}

// reAppArmor matches the container runtime's refusal to apply an AppArmor profile it does not have.
var reAppArmor = regexp.MustCompile(`(?i)apparmor`)

func appArmorEvidence(p kube.Pod, container string) Evidence {
	return Evidence{Object: p.Ref(), What: "the pod's and the container's appArmorProfile",
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.securityContext.appArmorProfile}{"\n"}{.spec.containers[?(@.name=="%s")].securityContext.appArmorProfile}`, container))}
}

const appArmorFix = "Load the profile on every node that may run the pod (apparmor_parser, from a DaemonSet or the Security Profiles Operator), keep the pod to the nodes that have it, or use appArmorProfile type RuntimeDefault."

// appArmorNotLoaded finds a container the runtime cannot create because its Localhost AppArmor profile is not
// loaded on the node. The kubelet does not check that the profile exists; the runtime finds out when it creates the
// container, and keeps failing.
func appArmorNotLoaded(p kube.Pod, cs kube.ContainerStatus, msg string, ev []Evidence) *problem {
	prof := appArmorOf(p, cs.Name)
	if prof == nil || prof.Type != "Localhost" || !reAppArmor.MatchString(msg) {
		return nil
	}
	cause := fmt.Sprintf("container %s runs under the Localhost AppArmor profile %s, which is not loaded on node %s, so the container runtime cannot create the container", cs.Name, prof.LocalhostProfile, p.Spec.NodeName)
	ev = append(ev, appArmorEvidence(p, cs.Name))
	return newProblem(p, cs.Name, "KD314", "AppArmor profile is not loaded on the node", Critical, cause, "apparmor|"+prof.LocalhostProfile, appArmorFix, ev...)
}
