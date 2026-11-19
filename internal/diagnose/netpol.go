package diagnose

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

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

// apiServerHost reports whether a host a pod connected to is the Kubernetes API server's Service: its DNS names, or its
// cluster IP when the snapshot holds default/kubernetes (else the first address of the usual Service range).
func apiServerHost(ix *index, host string, port int32) bool {
	switch strings.TrimSuffix(host, ".") {
	case "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local":
		return true
	}
	for _, svc := range ix.s.Services {
		if svc.Metadata.Namespace == "default" && svc.Metadata.Name == "kubernetes" {
			return host == svc.Spec.ClusterIP
		}
	}
	return port == 443 && (host == "10.96.0.1" || host == "10.0.0.1" || host == "172.20.0.1")
}

// apiServerBlocked finds a container that exits after its connection to the API server timed out while an egress
// NetworkPolicy selects the pod and no rule could let it through. Egress rules see a connection after the Service
// address is translated, so the API server appears as its own endpoints (the control plane's addresses, on 6443 or
// 443), which pod and namespace selectors do not match: only an ipBlock rule, or one without peers, allows it.
func apiServerBlocked(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, port, line := timedOutHost(lines)
	if host == "" || !apiServerHost(ix, host, port) {
		return nil
	}
	var blocker string
	for _, np := range ix.s.NetworkPolicies {
		if np.Metadata.Namespace != p.Metadata.Namespace || !np.AppliesToEgress() || !np.Spec.PodSelector.Matches(p.Metadata.Labels) {
			continue
		}
		if blocker == "" {
			blocker = np.Metadata.Name
		}
		for _, rule := range np.Spec.Egress {
			peers := len(rule.To) == 0
			for _, to := range rule.To {
				if to.IPBlock != nil {
					peers = true
				}
			}
			ports := len(rule.Ports) == 0
			for _, pp := range rule.Ports {
				if pp.Port == nil || (!pp.Port.IsName && (pp.Port.Int == 443 || pp.Port.Int == 6443)) {
					ports = true
				}
			}
			if peers && ports {
				return nil // some rule might allow it: claim nothing
			}
		}
	}
	if blocker == "" {
		return nil
	}
	ns := p.Metadata.Namespace
	ref := kube.Ref{Kind: "NetworkPolicy", Namespace: ns, Name: blocker}
	ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("NetworkPolicy %s restricts the pod's egress, and no egress rule in the namespace has an ipBlock (or no peers) on the API server's port", blocker),
		Command: "kubectl get networkpolicies -n " + ns + " -o yaml"},
		Evidence{Object: kube.Ref{Kind: "Endpoints", Namespace: "default", Name: "kubernetes"}, What: "the API server's own addresses and port, which egress rules see",
			Command: "kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes"})
	return newProblem(p, cs.Name, "KD267", "NetworkPolicy blocks the pod's connection to the API server", Critical,
		fmt.Sprintf("container %s exits because its connection to the Kubernetes API server (%s) times out: NetworkPolicy %s restricts its egress and allows nothing that reaches the API server, which egress rules see at its own endpoint addresses, usually on port 6443, not at the Service's; its log says: %q",
			cs.Name, host, blocker, clip(line, 200)),
		"npapi|"+blocker,
		fmt.Sprintf("Add an egress rule to %s that allows the API server's endpoint addresses (kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes) as an ipBlock, on their port (6443 on kubeadm and kind) and on 443.", blocker),
		ev...)
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

// policySelectsNothing reports a NetworkPolicy whose pod selector matches no pod and no pod template in its
// namespace (Deployments and the like, Jobs and CronJobs): it restricts nothing, usually because its labels do not
// match the pods it was written for. An empty selector selects every pod.
func policySelectsNothing(ix *index, np kube.NetworkPolicy) *Finding {
	sel := np.Spec.PodSelector
	if len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0 || !ix.read("pods") {
		return nil
	}
	ns := np.Metadata.Namespace
	var templates []map[string]string
	for _, p := range ix.s.Pods {
		if p.Metadata.Namespace == ns {
			templates = append(templates, p.Metadata.Labels)
		}
	}
	for _, w := range ix.s.Workloads {
		if w.Metadata.Namespace == ns {
			templates = append(templates, w.Spec.Template.Metadata.Labels)
		}
	}
	for _, j := range ix.s.Jobs {
		if j.Metadata.Namespace == ns {
			templates = append(templates, j.Spec.Template.Metadata.Labels)
		}
	}
	for _, c := range ix.s.CronJobs {
		if c.Metadata.Namespace == ns {
			templates = append(templates, c.Spec.JobTemplate.Spec.Template.Metadata.Labels)
		}
	}
	for _, l := range templates {
		if sel.Matches(l) {
			return nil
		}
	}
	if !ix.read("deployments.apps") || !ix.read("jobs.batch") || !ix.read("cronjobs.batch") {
		return nil // a template we could not read might match
	}
	cause := fmt.Sprintf("NetworkPolicy %s selects pods with %s, and no pod or workload in namespace %s has those labels, so it restricts nothing",
		np.Metadata.Name, selectorString(sel), ns)
	fix := "Change the policy's podSelector to match the pods it should restrict, or delete it if they are gone."
	if near := nearestLabels(ix, ns, sel.MatchLabels); near != "" {
		cause += fmt.Sprintf(" (the closest pod labels are %s)", near)
		fix = fmt.Sprintf("Change the policy's podSelector to match the pods it should restrict (%s).", near)
	}
	return &Finding{Rule: "KD262", Title: "NetworkPolicy selects no pods", Severity: Warning, Object: np.Ref(), Cause: cause,
		Evidence: []Evidence{{Object: np.Ref(), What: "the policy's podSelector", Command: cmdGet("networkpolicy", ns, np.Metadata.Name, "{.spec.podSelector}")},
			{Object: kube.Ref{Kind: "Pod", Namespace: ns, Name: "*"}, What: "pod labels in the namespace", Command: "kubectl get pods -n " + ns + " --show-labels"}},
		Fix: fix}
}

func networkPolicyFindings(ix *index) []Finding {
	var out []Finding
	for _, np := range ix.s.NetworkPolicies {
		if f := policySelectsNothing(ix, np); f != nil {
			out = append(out, *f)
		} else if f := policyPortNameUnknown(ix, np); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// policyPortNameUnknown reports an ingress rule that allows a port by name (port: metrics) when none of the pods the
// policy selects declares a container port of that name. A named port matches only the selected pods' own port
// names, so the rule allows nothing, and with the policy in place that traffic is dropped.
func policyPortNameUnknown(ix *index, np kube.NetworkPolicy) *Finding {
	if !np.AppliesToIngress() {
		return nil
	}
	ns := np.Metadata.Namespace
	var selected []kube.Pod
	for _, p := range ix.s.Pods {
		if p.Metadata.Namespace == ns && p.Status.Phase == "Running" && np.Spec.PodSelector.Matches(p.Metadata.Labels) {
			selected = append(selected, p)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	declared := map[string]int32{}
	for _, p := range selected {
		for _, c := range p.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name != "" {
					declared[cp.Name] = cp.ContainerPort
				}
			}
		}
	}
	for _, rule := range np.Spec.Ingress {
		for _, pp := range rule.Ports {
			if pp.Port == nil || !pp.Port.IsName {
				continue
			}
			if _, ok := declared[pp.Port.Str]; ok {
				continue
			}
			have := "no named ports"
			if len(declared) > 0 {
				var names []string
				for _, n := range sortedKeys(declared) {
					names = append(names, fmt.Sprintf("%s (%d)", n, declared[n]))
				}
				have = "the named ports " + strings.Join(names, ", ")
			}
			name := np.Metadata.Name
			return &Finding{Rule: "KD268", Title: "NetworkPolicy allows a port name the pods do not declare", Severity: Warning, Object: np.Ref(),
				Cause: fmt.Sprintf("NetworkPolicy %s allows ingress on port %q, but the %s it selects declare %s; a named port matches only the selected pods' own port names, so the rule allows nothing and that traffic is dropped",
					name, pp.Port.Str, plural(len(selected), "pod"), have),
				Evidence: []Evidence{{Object: np.Ref(), What: fmt.Sprintf("an ingress rule of %s allows port %s", name, pp.Port.Str),
					Command: cmdGet("networkpolicy", ns, name, "{.spec.ingress}")},
					{Object: selected[0].Ref(), What: fmt.Sprintf("the selected pods declare %s", have),
						Command: cmdGet("pod", ns, selected[0].Metadata.Name, "{.spec.containers[*].ports}")}},
				Fix: fmt.Sprintf("Name the port in the rule as the pods do, or use the port number; or add name: %s to the containers' port that should be reachable.", pp.Port.Str)}
		}
	}
	return nil
}
