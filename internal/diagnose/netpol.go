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
	reConnecting = regexp.MustCompile(`Connecting to ([A-Za-z0-9.-]+)(?::\d+)? \(([0-9.]+):(\d+)\)`) // busybox wget, before it times out
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
// a pod allow its traffic with a peer pod of the same namespace on a port. A peer chosen by IP block counts as allowed,
// since the snapshot holds no pod IP ranges, and so does one chosen by namespace selector when the namespaces'
// labels were not read: the rule only reports a block it can prove.
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
			peerOK := peerAllowed(ix, ns, peers, peer)
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

// peerAllowed says whether a rule's peers admit a pod of the policy's own namespace with the given labels. No peers
// means every peer.
func peerAllowed(ix *index, ns string, peers []kube.NetworkPolicyPeer, peer map[string]string) bool {
	if len(peers) == 0 {
		return true
	}
	for _, pe := range peers {
		switch {
		case pe.IPBlock != nil:
			return true
		case pe.NamespaceSelector != nil:
			// The selector must match the namespace's labels, when they were read, and the pod selector beside
			// it, if any, the pod.
			if labels, known := ix.namespaceLabels(ns); !known || pe.NamespaceSelector.Matches(labels) && (pe.PodSelector == nil || pe.PodSelector.Matches(peer)) {
				return true
			}
		case pe.PodSelector != nil && pe.PodSelector.Matches(peer):
			return true
		}
	}
	return false
}

// allowsServicePort finds a rule that would let the connection through if policies were checked against the
// Service's port: its peers admit the other pod, and its ports name the Service's port and not the pods'. Policies
// see a connection after the Service has forwarded it, so such a rule allows nothing that goes through the Service.
func allowsServicePort(ix *index, ns, dir string, subject, peer map[string]string, servicePort int32) (string, bool) {
	for _, np := range ix.s.NetworkPolicies {
		applies, rules := np.AppliesToIngress(), np.Spec.Ingress
		if dir == "egress" {
			applies, rules = np.AppliesToEgress(), np.Spec.Egress
		}
		if np.Metadata.Namespace != ns || !applies || !np.Spec.PodSelector.Matches(subject) {
			continue
		}
		for _, r := range rules {
			peers := r.From
			if dir == "egress" {
				peers = r.To
			}
			if !peerAllowed(ix, ns, peers, peer) {
				continue
			}
			for _, pp := range r.Ports {
				if pp.Port != nil && !pp.Port.IsName && pp.Port.Int == servicePort {
					return np.Metadata.Name, true
				}
			}
		}
	}
	return "", false
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
	if pr := blockedByNamespaceSelector(ix, p, cs, svc, dir, p.Metadata.Labels, backend.Metadata.Labels, bport, bname, line, ev); pr != nil {
		return pr
	}
	ref := kube.Ref{Kind: "NetworkPolicy", Namespace: ns, Name: np}
	ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("NetworkPolicy %s restricts %s and no %s rule in the namespace allows %s pods to port %d of %s pods",
		np, map[string]string{"egress": "the client's egress", "ingress": "the backends' ingress"}[dir], dir, kube.FormatMap(p.Metadata.Labels), bport, kube.FormatMap(backend.Metadata.Labels)),
		Command: "kubectl get networkpolicies -n " + ns + " -o yaml"})
	// The Service port the client dialled: the one in its log, or the Service's only port.
	sport := port
	if sport == 0 && len(svc.Spec.Ports) == 1 {
		sport = svc.Spec.Ports[0].Port
	}
	if sport != 0 && sport != bport {
		subject, peer := p.Metadata.Labels, backend.Metadata.Labels
		if dir == "ingress" {
			subject, peer = backend.Metadata.Labels, p.Metadata.Labels
		}
		if by, ok := allowsServicePort(ix, ns, dir, subject, peer, sport); ok {
			ev[len(ev)-1] = Evidence{Object: kube.Ref{Kind: "NetworkPolicy", Namespace: ns, Name: by},
				What:    fmt.Sprintf("NetworkPolicy %s allows %s on port %d, and no rule allows port %d", by, dir, sport, bport),
				Command: cmdGet("networkpolicy", ns, by, "{.spec."+dir+"}")}
			ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s forwards port %d to the pods' port %d", svc.Metadata.Name, sport, bport),
				Command: cmdGet("service", ns, svc.Metadata.Name, `{range .spec.ports[*]}{.port}{" -> "}{.targetPort}{"\n"}{end}`)})
			return newProblem(p, cs.Name, "KD127", "NetworkPolicy blocks the connection to a Service", Critical,
				fmt.Sprintf("container %s exits because its connection to Service %s times out: NetworkPolicy %s allows %s between them on port %d, the Service's port, but a policy is checked after the Service has forwarded the connection, against the pods' own port %d (the targetPort), which no rule allows; a blocked connection is dropped, not refused; its log says: %q",
					cs.Name, svc.Metadata.Name, by, dir, sport, bport, clip(line, 200)),
				"npblock|"+svc.Metadata.Name+"|"+by,
				fmt.Sprintf("In NetworkPolicy %s, allow port %d, the pods' port, in place of %d: NetworkPolicy ports are the ports of pods, never of Services.", by, bport, sport), ev...)
		}
	}
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
		} else if f := policyNamespaceUnmatched(ix, np); f != nil {
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

// namespaceLabels returns a namespace's labels, and whether the cluster's namespaces were read at all.
func (ix *index) namespaceLabels(ns string) (map[string]string, bool) {
	for _, n := range ix.s.NamespaceObjects {
		if n.Metadata.Name == ns {
			return n.Metadata.Labels, true
		}
	}
	return nil, len(ix.s.NamespaceObjects) > 0
}

// deadSelector is a namespaceSelector of a NetworkPolicy rule that matches no namespace of the cluster.
type deadSelector struct {
	policy kube.NetworkPolicy
	dir    string // "ingress" or "egress"
	sel    kube.LabelSelector
	rule   kube.NetworkPolicyRule
}

// deadNamespaceSelectors lists the namespace selectors of a policy that match no namespace, when the cluster's
// namespaces were read. An empty selector matches every namespace.
func deadNamespaceSelectors(ix *index, np kube.NetworkPolicy) []deadSelector {
	if len(ix.s.NamespaceObjects) == 0 {
		return nil
	}
	var out []deadSelector
	scan := func(dir string, rules []kube.NetworkPolicyRule, peersOf func(kube.NetworkPolicyRule) []kube.NetworkPolicyPeer) {
		for _, r := range rules {
			for _, pe := range peersOf(r) {
				if pe.NamespaceSelector == nil {
					continue
				}
				matched := false
				for _, n := range ix.s.NamespaceObjects {
					matched = matched || pe.NamespaceSelector.Matches(n.Metadata.Labels)
				}
				if !matched {
					out = append(out, deadSelector{np, dir, *pe.NamespaceSelector, r})
				}
			}
		}
	}
	if np.AppliesToIngress() {
		scan("ingress", np.Spec.Ingress, func(r kube.NetworkPolicyRule) []kube.NetworkPolicyPeer { return r.From })
	}
	if np.AppliesToEgress() {
		scan("egress", np.Spec.Egress, func(r kube.NetworkPolicyRule) []kube.NetworkPolicyPeer { return r.To })
	}
	return out
}

// namespaceHint says how the namespaces a dead selector was most likely written for can be selected: every
// namespace carries kubernetes.io/metadata.name=<its name>, and no other label unless someone adds it.
func namespaceHint(ix *index, sel kube.LabelSelector) (meant, text string) {
	for _, v := range sortedKeys(sel.MatchLabels) {
		value := sel.MatchLabels[v]
		for _, n := range ix.s.NamespaceObjects {
			if n.Metadata.Name == value {
				return value, fmt.Sprintf("namespace %s exists, and its labels are %s", value, kube.FormatMap(n.Metadata.Labels))
			}
		}
	}
	return "", ""
}

func namespaceSelectorFix(np kube.NetworkPolicy, d deadSelector, meant string) string {
	if meant != "" {
		return fmt.Sprintf("Select the namespace by the label Kubernetes sets on every namespace: namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: %s}} in NetworkPolicy %s. Or add the label the policy expects (kubectl label namespace %s %s). For pods of the policy's own namespace a podSelector alone is enough.",
			meant, np.Metadata.Name, meant, kube.FormatMap(d.sel.MatchLabels))
	}
	return fmt.Sprintf("Change the namespaceSelector of NetworkPolicy %s to labels the namespaces have (kubectl get namespaces --show-labels; every namespace carries kubernetes.io/metadata.name=<its name>), or add the label to the namespaces meant.", np.Metadata.Name)
}

// policyNamespaceUnmatched reports a NetworkPolicy rule whose namespaceSelector matches no namespace of the cluster:
// the rule allows nothing. The usual cause is a label such as name=frontend that nobody put on the namespace.
func policyNamespaceUnmatched(ix *index, np kube.NetworkPolicy) *Finding {
	dead := deadNamespaceSelectors(ix, np)
	if len(dead) == 0 {
		return nil
	}
	d := dead[0]
	ns := np.Metadata.Namespace
	meant, hint := namespaceHint(ix, d.sel)
	fromTo := map[string]string{"ingress": "from", "egress": "to"}[d.dir]
	cause := fmt.Sprintf("NetworkPolicy %s has an %s rule that allows traffic %s namespaces labelled %s, and no namespace of the cluster has those labels, so the rule allows nothing",
		np.Metadata.Name, d.dir, fromTo, selectorString(d.sel))
	if hint != "" {
		cause += " (" + hint + ")"
	}
	return &Finding{Rule: "KD274", Title: "NetworkPolicy's namespaceSelector matches no namespace", Severity: Warning, Object: np.Ref(), Cause: cause,
		Evidence: []Evidence{{Object: np.Ref(), What: fmt.Sprintf("the policy's %s rules", d.dir), Command: cmdGet("networkpolicy", ns, np.Metadata.Name, "{.spec."+d.dir+"}")},
			{Object: kube.Ref{Kind: "Namespace", Name: "*"}, What: fmt.Sprintf("none of the %d namespaces has labels %s", len(ix.s.NamespaceObjects), selectorString(d.sel)), Command: "kubectl get namespaces --show-labels"}},
		Fix: namespaceSelectorFix(np, d, meant)}
}

// blockedByNamespaceSelector refines a blocked connection between two pods of one namespace: when a policy that
// selects the restricted pod has a rule for this port whose only fault is a namespaceSelector that matches no
// namespace, that selector is the cause, and the client's finding names it.
func blockedByNamespaceSelector(ix *index, p kube.Pod, cs kube.ContainerStatus, svc kube.Service, dir string, client, backend map[string]string, port int32, portName, line string, ev []Evidence) *problem {
	ns := p.Metadata.Namespace
	subject := backend
	if dir == "egress" {
		subject = client
	}
	for _, np := range ix.s.NetworkPolicies {
		if np.Metadata.Namespace != ns || !np.Spec.PodSelector.Matches(subject) {
			continue
		}
		for _, d := range deadNamespaceSelectors(ix, np) {
			if d.dir != dir {
				continue
			}
			portOK := len(d.rule.Ports) == 0
			for _, pp := range d.rule.Ports {
				portOK = portOK || pp.Port == nil || (!pp.Port.IsName && pp.Port.Int == port) || (pp.Port.IsName && pp.Port.Str == portName && portName != "")
			}
			if !portOK {
				continue
			}
			meant, hint := namespaceHint(ix, d.sel)
			fromTo := map[string]string{"ingress": "from", "egress": "to"}[dir]
			cause := fmt.Sprintf("container %s exits because its connection to Service %s times out: NetworkPolicy %s allows %s on port %d only %s namespaces labelled %s, and no namespace of the cluster has those labels, so the rule admits nothing and the connection is dropped",
				cs.Name, svc.Metadata.Name, np.Metadata.Name, dir, port, fromTo, selectorString(d.sel))
			if hint != "" {
				cause += " (" + hint + ")"
			}
			cause += fmt.Sprintf("; its log says: %q", clip(line, 200))
			ev = append(ev, Evidence{Object: np.Ref(), What: fmt.Sprintf("NetworkPolicy %s's %s rule selects namespaces labelled %s", np.Metadata.Name, dir, selectorString(d.sel)),
				Command: cmdGet("networkpolicy", ns, np.Metadata.Name, "{.spec."+dir+"}")},
				Evidence{Object: kube.Ref{Kind: "Namespace", Name: "*"}, What: fmt.Sprintf("none of the %d namespaces has labels %s", len(ix.s.NamespaceObjects), selectorString(d.sel)), Command: "kubectl get namespaces --show-labels"})
			return newProblem(p, cs.Name, "KD274", "NetworkPolicy's namespaceSelector matches no namespace", Critical, cause,
				"npns|"+svc.Metadata.Name+"|"+np.Metadata.Name, namespaceSelectorFix(np, d, meant), ev...)
		}
	}
	return nil
}
