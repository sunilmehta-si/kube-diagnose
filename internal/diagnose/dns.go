package diagnose

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// reUnresolved matches the ways common clients report a host name that DNS does not know, capturing the name:
// busybox wget, curl, Go's resolver, glibc-based clients via Python, Node, Java and libpq.
var reUnresolved = []*regexp.Regexp{
	regexp.MustCompile(`bad address '([A-Za-z0-9.-]+)`),
	regexp.MustCompile(`(?i)could not resolve host:? ['"]?([A-Za-z0-9.-]+)`),
	regexp.MustCompile(`lookup ([A-Za-z0-9.-]+)(?: on [0-9a-fA-F.:\[\]]+)?: no such host`),
	regexp.MustCompile(`(?i)failed to resolve '([A-Za-z0-9.-]+)'`),
	regexp.MustCompile(`getaddrinfo (?:ENOTFOUND|EAI_AGAIN) ([A-Za-z0-9.-]+)`),
	regexp.MustCompile(`UnknownHostException: ([A-Za-z0-9.-]+)`),
	regexp.MustCompile(`could not translate host name "([A-Za-z0-9.-]+)"`),
	regexp.MustCompile(`server can't find ([A-Za-z0-9.-]+): NXDOMAIN`),
}

// unresolvedHost returns the host name the newest log line failed to resolve, and that line.
func unresolvedHost(lines []string) (host, line string) {
	for i := len(lines) - 1; i >= 0; i-- {
		for _, re := range reUnresolved {
			if m := re.FindStringSubmatch(lines[i]); m != nil {
				return strings.TrimSuffix(m[1], "."), lines[i]
			}
		}
	}
	return "", ""
}

// serviceName turns a host name a pod in namespace ns looked up into the Service it means: a bare name is a
// Service in the pod's namespace, name.namespace and name.namespace.svc[.cluster.local] name one elsewhere. Any
// other name is outside the cluster.
func serviceName(ns, host string) (svcNS, svc string, ok bool) {
	host = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(host), ".cluster.local"), ".svc")
	parts := strings.Split(host, ".")
	switch len(parts) {
	case 1:
		return ns, parts[0], parts[0] != ""
	case 2:
		return parts[1], parts[0], parts[0] != "" && parts[1] != ""
	}
	return "", "", false
}

// serviceExists reports whether a Service exists, and whether the snapshot can tell: the Service list must have been
// read and the namespace collected.
func (ix *index) serviceExists(ns, name string) (exists, known bool) {
	if !ix.read("services") || (len(ix.s.Namespaces) > 0 && !slices.Contains(ix.s.Namespaces, ns)) {
		return false, false
	}
	for _, s := range ix.s.Services {
		if s.Metadata.Namespace == ns && s.Metadata.Name == name {
			return true, true
		}
	}
	return false, true
}

// missingService finds, in a container's log, a failed lookup of a Service name that has no Service behind it.
func (ix *index) missingService(podNS string, lines []string) (svcNS, svc, line string, ok bool) {
	host, line := unresolvedHost(lines)
	if host == "" {
		return "", "", "", false
	}
	svcNS, svc, isSvc := serviceName(podNS, host)
	if !isSvc {
		return "", "", "", false
	}
	if exists, known := ix.serviceExists(svcNS, svc); exists || !known {
		return "", "", "", false
	}
	return svcNS, svc, line, true
}

// dnsBlockedBy returns the egress NetworkPolicy that leaves a pod no way to reach DNS: the pod is selected by
// egress policies and none of their rules allows port 53 (a rule without ports allows every port to its peers).
// It returns nil when the pod's egress is not restricted or DNS is allowed.
func dnsBlockedBy(ix *index, p kube.Pod) *kube.NetworkPolicy {
	var first *kube.NetworkPolicy
	for i, np := range ix.s.NetworkPolicies {
		if np.Metadata.Namespace != p.Metadata.Namespace || !np.AppliesToEgress() || !np.Spec.PodSelector.Matches(p.Metadata.Labels) {
			continue
		}
		if first == nil {
			first = &ix.s.NetworkPolicies[i]
		}
		for _, rule := range np.Spec.Egress {
			if len(rule.Ports) == 0 {
				return nil
			}
			for _, port := range rule.Ports {
				if port.Port == nil || (!port.Port.IsName && port.Port.Int == 53) || (port.Port.IsName && strings.HasPrefix(port.Port.Str, "dns")) {
					return nil
				}
			}
		}
	}
	return first
}

// dnsBlocked finds a container that exits after a failed lookup while an egress NetworkPolicy blocks its DNS.
func dnsBlocked(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, line := unresolvedHost(lines)
	if host == "" {
		return nil
	}
	np := dnsBlockedBy(ix, p)
	if np == nil {
		return nil
	}
	ns := p.Metadata.Namespace
	ref := kube.Ref{Kind: "NetworkPolicy", Namespace: ns, Name: np.Metadata.Name}
	ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("NetworkPolicy %s restricts the pod's egress and allows no traffic to port 53", np.Metadata.Name),
		Command: cmdGet("networkpolicy", ns, np.Metadata.Name, "{.spec.egress}")})
	return newProblem(p, cs.Name, "KD123", "NetworkPolicy blocks the pod's DNS lookups", Critical,
		fmt.Sprintf("container %s exits because it cannot resolve %s: NetworkPolicy %s restricts its egress and allows nothing to port 53, so no DNS lookup gets out; its log says: %q", cs.Name, host, np.Metadata.Name, clip(line, 200)),
		"dnsblocked|"+np.Metadata.Name, fmt.Sprintf("Add an egress rule to %s (or another policy selecting these pods) that allows UDP and TCP port 53 to the cluster DNS (namespace kube-system, k8s-app: kube-dns).", np.Metadata.Name), ev...)
}
