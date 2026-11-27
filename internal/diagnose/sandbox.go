package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	reSandboxPrefix = regexp.MustCompile(`^Failed to create pod sandbox: (?:rpc error: code = \w+ desc = )?`)
	reNoIPs         = regexp.MustCompile(`(?i)no IP addresses available|failed to assign an IP address|failed to allocate for range|no available IP`)
	reCNIPlugin     = regexp.MustCompile(`plugin type="([^"]+)" failed`)
	reCNI           = regexp.MustCompile(`(?i)failed to setup network for sandbox|cni plugin not initialized|network plugin is not ready|failed to find plugin`)
	// containerd: "failed to get sandbox runtime: no runtime for \"nvidia\" is configured"
	reNoRuntime = regexp.MustCompile(`no runtime for "([^"]+)" is configured`)
	// The kubelet, building the sandbox's hostname for a pod with setHostnameAsFQDN.
	reFQDNTooLong = regexp.MustCompile(`FQDN (\S+) is too long \((\d+) characters is the max, (\d+) characters requested\)`)
)

// sandboxProblem finds a pod that is assigned to a node and still has no container started because the node cannot
// create its sandbox: the network namespace and pause container every pod starts in. The container statuses say
// only ContainerCreating; the reason is in FailedCreatePodSandBox events.
func sandboxProblem(ix *index, p kube.Pod) *problem {
	if p.Status.Phase != "Pending" || p.Spec.NodeName == "" {
		return nil
	}
	for _, cs := range append(append([]kube.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if cs.State.Running != nil || cs.State.Terminated != nil || cs.RestartCount > 0 {
			return nil // a container has started, so the sandbox exists
		}
	}
	evs := ix.eventsFor(p.Ref(), "FailedCreatePodSandBox")
	if len(evs) == 0 {
		return nil
	}
	e := evs[0]
	msg := reSandboxPrefix.ReplaceAllString(e.Message, "")
	node := p.Spec.NodeName
	ev := []Evidence{eventEvidence(p.Ref(), e)}
	switch {
	case reFQDNTooLong.MatchString(msg):
		m := reFQDNTooLong.FindStringSubmatch(msg)
		ev = append(ev, Evidence{Object: p.Ref(), What: "the pod's hostname, subdomain and setHostnameAsFQDN",
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.spec.hostname}{" "}{.spec.subdomain}{" "}{.spec.setHostnameAsFQDN}`)})
		return newProblem(p, "", "KD239", "Pod's FQDN is too long to be its hostname", Critical,
			fmt.Sprintf("the pod sets setHostnameAsFQDN, so the kubelet makes its full name %s (hostname, subdomain, namespace and cluster domain) the hostname, and at %s characters it is longer than the %s a Linux hostname may have, so the sandbox is never created", m[1], m[3], m[2]),
			"sandbox|fqdn",
			fmt.Sprintf("Shorten the names that make up the FQDN to %s characters or fewer (a StatefulSet's name and serviceName give its pods their hostname and subdomain, and the namespace counts too), or drop setHostnameAsFQDN: the pod's FQDN still resolves in DNS, and only the hostname inside the container is short.", m[2]),
			ev...)
	case reNoRuntime.MatchString(msg):
		handler := reNoRuntime.FindStringSubmatch(msg)[1]
		class := "its RuntimeClass"
		if rc := p.Spec.RuntimeClassName; rc != "" {
			class = "RuntimeClass " + rc
			ev = append(ev, Evidence{Object: kube.Ref{Kind: "RuntimeClass", Name: rc}, What: fmt.Sprintf("the pod's runtimeClassName is %s", rc),
				Command: cmdGet("runtimeclass", "", rc, `{.handler}{" "}{.scheduling}`)})
		}
		return newProblem(p, "", "KD196", "Node's container runtime has no handler for the RuntimeClass", Critical,
			fmt.Sprintf("the pod runs with %s, whose handler %s is not configured in the container runtime on node %s, so its sandbox is never created", class, handler, node),
			"sandbox|runtime|"+handler,
			fmt.Sprintf("Run the pod only on nodes that have handler %s: give the RuntimeClass a scheduling.nodeSelector for them (for nvidia, the nodes where the NVIDIA container toolkit configured containerd), or configure the handler on node %s.", handler, node),
			ev...)
	case reNoIPs.MatchString(msg):
		return newProblem(p, "", "KD134", "Pod sandbox cannot be created", Critical,
			fmt.Sprintf("node %s cannot give the pod an IP address, so its sandbox is never created: %s", node, clip(msg, 200)), "sandbox|ips",
			"The node's pod IP range is used up: remove pods from the node, add nodes, or enlarge the range the network plugin allocates from (on AWS, the subnet or prefix delegation).", ev...)
	case reCNI.MatchString(msg) || reCNIPlugin.MatchString(msg):
		plugin := "the node's network plugin"
		if m := reCNIPlugin.FindStringSubmatch(msg); m != nil {
			plugin = "network plugin " + m[1]
		}
		return newProblem(p, "", "KD134", "Pod sandbox cannot be created", Critical,
			fmt.Sprintf("%s on node %s fails to set up the pod's network, so its sandbox is never created: %s", plugin, node, clip(msg, 200)), "sandbox|cni",
			"Check the network plugin's pods on that node (kubectl get pods -n kube-system -o wide) and their logs; every pod on the node is affected until it works.",
			append(ev, Evidence{Object: kube.Ref{Kind: "Pod", Namespace: "kube-system", Name: "*"}, What: "the pods that run on node " + node,
				Command: "kubectl get pods -A -o wide --field-selector spec.nodeName=" + node})...)
	}
	return newProblem(p, "", "KD134", "Pod sandbox cannot be created", Critical,
		fmt.Sprintf("node %s cannot create the pod's sandbox, so no container starts: %s", node, clip(msg, 200)), "sandbox|"+strings.SplitN(msg, ":", 2)[0],
		"Read the error in the evidence; it comes from the node's container runtime or network plugin, and affects pods on that node.", ev...)
}
