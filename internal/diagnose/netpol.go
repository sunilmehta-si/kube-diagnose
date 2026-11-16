package diagnose

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// Connection timeouts as clients print them. A NetworkPolicy drops packets rather than refusing them, so a blocked
// connection times out. Each pattern captures the host or IP and, when the line has it, the port.
var (
	reConnecting = regexp.MustCompile(`Connecting to ([A-Za-z0-9.-]+) \(([0-9.]+):(\d+)\)`) // busybox wget, before it times out
	reTimedOut   = []*regexp.Regexp{
		regexp.MustCompile(`dial tcp ([0-9.]+):(\d+): (?:i/o timeout|connect: connection timed out)`),
		regexp.MustCompile(`(?i)failed to connect to ([A-Za-z0-9.-]+) port (\d+).*(?:timed out|Timeout was reached)`),
		regexp.MustCompile(`ETIMEDOUT ([0-9.]+):(\d+)`),
		regexp.MustCompile(`connection to server at "([A-Za-z0-9.-]+)"[^,]*, port (\d+) failed: (?:timeout expired|Connection timed out)`),
	}
	reBareTimeout = regexp.MustCompile(`(?i)download timed out|connection timed out|operation timed out`)
)

// timedOutHost returns the host or IP and port of the newest connection that timed out, and the line that says so.
func timedOutHost(lines []string) (host string, port int32, line string) {
	for i := len(lines) - 1; i >= 0; i-- {
		for _, re := range reTimedOut {
			if m := re.FindStringSubmatch(lines[i]); m != nil {
				n, _ := strconv.Atoi(m[2])
				return m[1], int32(n), lines[i]
			}
		}
		if reBareTimeout.MatchString(lines[i]) {
			for j := i - 1; j >= 0; j-- {
				if m := reConnecting.FindStringSubmatch(lines[j]); m != nil {
					n, _ := strconv.Atoi(m[3])
					return m[1], int32(n), lines[i]
				}
			}
		}
	}
	return "", 0, ""
}

// serviceByHost finds a Service of namespace ns that a host name or cluster IP refers to.
func serviceByHost(ix *index, ns, host string) (kube.Service, bool) {
	for _, svc := range ix.s.Services {
		if svc.Metadata.Namespace != ns {
			continue
		}
		name := svc.Metadata.Name
		if svc.Spec.ClusterIP == host || host == name || host == name+"."+ns || host == name+"."+ns+".svc" || host == name+"."+ns+".svc.cluster.local" {
			return svc, true
		}
	}
	return kube.Service{}, false
}

// backendPort resolves the Service port a client connected to into the port number and name on a backend pod.
func backendPort(svc kube.Service, port int32, backend kube.Pod) (int32, string) {
	sp := kube.ServicePort{}
	for _, p := range svc.Spec.Ports {
		if p.Port == port || len(svc.Spec.Ports) == 1 {
			sp = p
			break
		}
	}
	for _, c := range backend.Spec.Containers {
		for _, cp := range c.Ports {
			if (sp.TargetPort.IsName && cp.Name == sp.TargetPort.Str) || (!sp.TargetPort.IsName && cp.ContainerPort == sp.TargetPort.Int) {
				return cp.ContainerPort, cp.Name
			}
		}
	}
	if !sp.TargetPort.IsName && sp.TargetPort.Int != 0 {
		return sp.TargetPort.Int, ""
	}
	return sp.Port, ""
}

// policyVerdict says whether the NetworkPolicies of one direction ("Egress" or "Ingress") in namespace ns that select
// a pod allow its traffic with a peer pod of the same namespace on a port. A peer chosen by namespace selector or
// IP block counts as allowed, since the snapshot holds neither namespace labels nor pod IP ranges: the rule only
// reports a block it can prove.
func policyVerdict(ix *index, ns, dir string, subject, peer map[string]string, port int32, portName string) (selected bool, blocker string) {
	for _, np := range ix.s.NetworkPolicies {
		applies := np.AppliesToIngress()
		rules := np.Spec.Ingress
		if dir == "Egress" {
			applies, rules = np.AppliesToEgress(), np.Spec.Egress
		}
		if np.Metadata.Namespace != ns || !applies || !np.Spec.PodSelector.Matches(subject) {
			continue
		}
		if !selected {
			selected, blocker = true, np.Metadata.Name
		}
		for _, r := range rules {
			peers := r.From
			if dir == "Egress" {
				peers = r.To
			}
			peerOK := len(peers) == 0
			for _, pe := range peers {
				if pe.NamespaceSelector != nil || pe.IPBlock != nil || (pe.PodSelector != nil && pe.PodSelector.Matches(peer)) {
					peerOK = true
				}
			}
			portOK := len(r.Ports) == 0
			for _, pp := range r.Ports {
				if pp.Port == nil || (!pp.Port.IsName && pp.Port.Int == port) || (pp.Port.IsName && pp.Port.Str == portName && portName != "") {
					portOK = true
				}
			}
			if peerOK && portOK {
				return true, ""
			}
		}
	}
	return selected, blocker
}

// policyBlocksService finds a container that exits after its connection to a Service of its namespace timed out,
// while the Service has ready pods and NetworkPolicies, on the client's egress or the backends' ingress, allow
// nothing between them on that port.
func policyBlocksService(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, port, line := timedOutHost(lines)
	if host == "" || len(ix.s.NetworkPolicies) == 0 {
		return nil
	}
	ns := p.Metadata.Namespace
	svc, ok := serviceByHost(ix, ns, host)
	if !ok || len(svc.Spec.Selector) == 0 {
		return nil
	}
	var backend *kube.Pod
	for i, q := range ix.s.Pods {
		if q.Metadata.Namespace == ns && q.Ready() && kube.MatchesMap(svc.Spec.Selector, q.Metadata.Labels) {
			backend = &ix.s.Pods[i]
			break
		}
	}
	if backend == nil {
		return nil // no ready pods: the timeout has another explanation
	}
	bport, bname := backendPort(svc, port, *backend)
	dir, np := "", ""
	if sel, blk := policyVerdict(ix, ns, "Egress", p.Metadata.Labels, backend.Metadata.Labels, bport, bname); sel && blk != "" {
		dir, np = "egress", blk
	} else if sel, blk := policyVerdict(ix, ns, "Ingress", backend.Metadata.Labels, p.Metadata.Labels, bport, bname); sel && blk != "" {
		dir, np = "ingress", blk
	}
	if np == "" {
		return nil
	}
	ref := kube.Ref{Kind: "NetworkPolicy", Namespace: ns, Name: np}
	ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("NetworkPolicy %s restricts %s and no %s rule in the namespace allows %s pods to port %d of %s pods",
		np, map[string]string{"egress": "the client's egress", "ingress": "the backends' ingress"}[dir], dir, kube.FormatMap(p.Metadata.Labels), bport, kube.FormatMap(backend.Metadata.Labels)),
		Command: "kubectl get networkpolicies -n " + ns + " -o yaml"})
	fix := fmt.Sprintf("Add an egress rule to %s (or another policy selecting the client pods) that allows pods with %s on port %d.", np, kube.FormatMap(svc.Spec.Selector), bport)
	if dir == "ingress" {
		fix = fmt.Sprintf("Add an ingress rule to %s (or another policy selecting Service %s's pods) that allows pods with %s on port %d.", np, svc.Metadata.Name, kube.FormatMap(p.Metadata.Labels), bport)
	}
	return newProblem(p, cs.Name, "KD127", "NetworkPolicy blocks the connection to a Service", Critical,
		fmt.Sprintf("container %s exits because its connection to Service %s times out: NetworkPolicy %s allows no %s traffic between them on port %d, and a blocked connection is dropped, not refused; its log says: %q",
			cs.Name, svc.Metadata.Name, np, dir, bport, clip(line, 200)),
		"npblock|"+svc.Metadata.Name+"|"+np, fix, ev...)
}
