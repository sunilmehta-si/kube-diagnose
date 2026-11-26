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
	// Go when no DNS server answers, as behind a NetworkPolicy that blocks port 53.
	regexp.MustCompile(`lookup ([A-Za-z0-9.-]+) on [0-9a-fA-F.:\[\]]+:53: .*(?:i/o timeout|connection refused|server misbehaving)`),
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
func dnsBlockedBy(ix *index, p kube.Pod) (*kube.NetworkPolicy, *kube.NetworkPolicyPeer) {
	var first *kube.NetworkPolicy
	var local *kube.NetworkPolicyPeer // a port-53 rule's peer that names pods of the policy's own namespace only
	for i, np := range ix.s.NetworkPolicies {
		if np.Metadata.Namespace != p.Metadata.Namespace || !np.AppliesToEgress() || !np.Spec.PodSelector.Matches(p.Metadata.Labels) {
			continue
		}
		if first == nil {
			first = &ix.s.NetworkPolicies[i]
		}
		for r, rule := range np.Spec.Egress {
			dns := len(rule.Ports) == 0
			for _, port := range rule.Ports {
				if port.Port == nil || (!port.Port.IsName && port.Port.Int == 53) || (port.Port.IsName && strings.HasPrefix(port.Port.Str, "dns")) {
					dns = true
				}
			}
			if !dns {
				continue
			}
			// The rule lets port 53 out; to where? A podSelector with no namespaceSelector picks pods of the policy's
			// own namespace, and cluster DNS runs in kube-system, so such a peer lets no lookup out.
			if len(rule.To) == 0 {
				return nil, nil
			}
			for j, peer := range rule.To {
				if peer.NamespaceSelector != nil || peer.IPBlock != nil {
					return nil, nil
				}
				if local == nil && p.Metadata.Namespace != "kube-system" {
					local = &ix.s.NetworkPolicies[i].Spec.Egress[r].To[j]
					first = &ix.s.NetworkPolicies[i]
				}
			}
		}
	}
	return first, local
}

// dnsBlocked finds a container that exits after a failed lookup while an egress NetworkPolicy blocks its DNS.
func dnsBlocked(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, line := unresolvedHost(lines)
	if host == "" {
		return nil
	}
	np, local := dnsBlockedBy(ix, p)
	if np == nil {
		return nil
	}
	ns := p.Metadata.Namespace
	ref := kube.Ref{Kind: "NetworkPolicy", Namespace: ns, Name: np.Metadata.Name}
	if local != nil {
		sel := "{}"
		if local.PodSelector != nil {
			sel = selectorString(*local.PodSelector)
		}
		ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("NetworkPolicy %s allows port 53 only to pods matching %s, with no namespaceSelector", np.Metadata.Name, sel),
			Command: cmdGet("networkpolicy", ns, np.Metadata.Name, "{.spec.egress}")})
		return newProblem(p, cs.Name, "KD123", "NetworkPolicy blocks the pod's DNS lookups", Critical,
			fmt.Sprintf("container %s exits because it cannot resolve %s: NetworkPolicy %s allows port 53 only to pods matching %s, and a podSelector with no namespaceSelector picks pods of namespace %s alone, while cluster DNS runs in kube-system, so no DNS lookup gets out; its log says: %q",
				cs.Name, host, np.Metadata.Name, sel, ns, clip(line, 200)),
			"dnsblocked|"+np.Metadata.Name, fmt.Sprintf("Add namespaceSelector {matchLabels: {kubernetes.io/metadata.name: kube-system}} to that peer of %s, in the same entry as its podSelector, so it picks the DNS pods in kube-system.", np.Metadata.Name), ev...)
	}
	ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("NetworkPolicy %s restricts the pod's egress and allows no traffic to port 53", np.Metadata.Name),
		Command: cmdGet("networkpolicy", ns, np.Metadata.Name, "{.spec.egress}")})
	return newProblem(p, cs.Name, "KD123", "NetworkPolicy blocks the pod's DNS lookups", Critical,
		fmt.Sprintf("container %s exits because it cannot resolve %s: NetworkPolicy %s restricts its egress and allows nothing to port 53, so no DNS lookup gets out; its log says: %q", cs.Name, host, np.Metadata.Name, clip(line, 200)),
		"dnsblocked|"+np.Metadata.Name, fmt.Sprintf("Add an egress rule to %s (or another policy selecting these pods) that allows UDP and TCP port 53 to the cluster DNS (namespace kube-system, k8s-app: kube-dns).", np.Metadata.Name), ev...)
}

// reRefused matches a refused connection and captures the host or IP it went to: busybox wget, curl, Go, Node and
// libpq.
var reRefused = []*regexp.Regexp{
	regexp.MustCompile(`can't connect to remote host \(([0-9.]+)\): Connection refused`),
	regexp.MustCompile(`(?i)failed to connect to ([A-Za-z0-9.-]+) port \d+.*(?:Connection refused|Couldn't connect to server)`),
	regexp.MustCompile(`dial tcp ([0-9.]+):\d+: connect: connection refused`),
	regexp.MustCompile(`ECONNREFUSED ([0-9.]+):\d+`),
	regexp.MustCompile(`connection to server at "([A-Za-z0-9.-]+)".*Connection refused`),
}

// refusedService finds, in a container's log, a refused connection to a Service of the pod's namespace, by name or
// by cluster IP, and returns the Service.
func refusedService(ix *index, ns string, lines []string) (kube.Service, string, bool) {
	for i := len(lines) - 1; i >= 0; i-- {
		for _, re := range reRefused {
			m := re.FindStringSubmatch(lines[i])
			if m == nil {
				continue
			}
			for _, svc := range ix.s.Services {
				if svc.Metadata.Namespace != ns {
					continue
				}
				if svc.Spec.ClusterIP == m[1] || svc.Metadata.Name == m[1] || strings.HasPrefix(m[1], svc.Metadata.Name+"."+ns+".") || m[1] == svc.Metadata.Name+"."+ns {
					return svc, lines[i], true
				}
			}
		}
	}
	return kube.Service{}, "", false
}

// refusedByEmptyService finds a container that exits because the Service it connects to has no ready pods: the
// cluster refuses connections to a Service without endpoints.
func refusedByEmptyService(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	svc, line, ok := refusedService(ix, p.Metadata.Namespace, lines)
	if !ok || len(svc.Spec.Selector) == 0 {
		return nil
	}
	ns := svc.Metadata.Namespace
	matching, ready := 0, 0
	for _, q := range ix.s.Pods {
		if q.Metadata.Namespace == ns && kube.MatchesMap(svc.Spec.Selector, q.Metadata.Labels) && q.Status.Phase != "Succeeded" && q.Status.Phase != "Failed" {
			matching++
			if q.Ready() {
				ready++
			}
		}
	}
	if ready > 0 {
		return nil
	}
	why := fmt.Sprintf("it selects %d pods and none is ready", matching)
	if matching == 0 {
		why = "no pod has its selector's labels " + kube.FormatMap(svc.Spec.Selector)
	}
	ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s has no ready pods: %s", svc.Metadata.Name, why),
		Command: "kubectl get endpointslices -n " + ns + " -l kubernetes.io/service-name=" + svc.Metadata.Name})
	return newProblem(p, cs.Name, "KD124", "Container connects to a Service with no ready pods", Critical,
		fmt.Sprintf("container %s exits because Service %s refuses its connection: the Service has no ready pods (%s); its log says: %q", cs.Name, svc.Metadata.Name, why, clip(line, 200)),
		"refused|"+svc.Metadata.Name, fmt.Sprintf("Fix Service %s's pods (the findings for them say why they are not ready, or scale them up), or make %s wait and retry rather than exit.", svc.Metadata.Name, cs.Name), ev...)
}

// reTokenMissing matches a container failing to read the ServiceAccount files the kubelet mounts for API access.
var reTokenMissing = regexp.MustCompile(`(?i)(?:/var)?/run/secrets/kubernetes\.io/serviceaccount/?([a-z.]*)['"]?:? .*(?:no such file|not exist|can't open)`)

// tokenNotMounted finds a container that exits because it cannot read its ServiceAccount token, while the pod or its
// ServiceAccount sets automountServiceAccountToken: false, so the token was never mounted.
func tokenNotMounted(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	line := ""
	for i := len(lines) - 1; i >= 0 && line == ""; i-- {
		if reTokenMissing.MatchString(lines[i]) {
			line = lines[i]
		}
	}
	if line == "" {
		return nil
	}
	ns := p.Metadata.Namespace
	sa := p.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	where := ""
	switch {
	case p.Spec.AutomountServiceAccountToken != nil && !*p.Spec.AutomountServiceAccountToken:
		where = "the pod sets automountServiceAccountToken: false"
		ev = append(ev, Evidence{Object: p.Ref(), What: where, Command: cmdGet("pod", ns, p.Metadata.Name, "{.spec.automountServiceAccountToken}")})
	case p.Spec.AutomountServiceAccountToken == nil:
		for _, a := range ix.s.ServiceAccounts {
			if a.Metadata.Namespace == ns && a.Metadata.Name == sa && a.AutomountServiceAccountToken != nil && !*a.AutomountServiceAccountToken {
				where = fmt.Sprintf("its ServiceAccount %s sets automountServiceAccountToken: false", sa)
				ev = append(ev, Evidence{Object: kube.Ref{Kind: "ServiceAccount", Namespace: ns, Name: sa}, What: where,
					Command: cmdGet("serviceaccount", ns, sa, "{.automountServiceAccountToken}")})
			}
		}
	}
	if where == "" {
		return nil // the token should be there; something else removed or hid it
	}
	return newProblem(p, cs.Name, "KD125", "Container needs a ServiceAccount token that is not mounted", Critical,
		fmt.Sprintf("container %s exits because it cannot read its ServiceAccount token, and %s, so the kubelet never mounted it; its log says: %q", cs.Name, where, clip(line, 200)),
		"notoken|"+sa, "If the app talks to the Kubernetes API, set automountServiceAccountToken: true on the pod (it overrides the ServiceAccount), or mount a projected serviceAccountToken volume; if it does not, find why it tries.", ev...)
}

// reForbidden matches the API server's RBAC denial as clients print it, capturing the ServiceAccount's namespace and
// name, the verb, the resource, its API group, and the namespace (empty at the cluster scope).
var reForbidden = regexp.MustCompile(`User "system:serviceaccount:([^:"]+):([^"]+)" cannot (\S+) resource "([^"]+)" in API group "([^"]*)"(?: in the namespace "([^"]+)"| at the cluster scope)`)

// rbacDenied finds a container that exits because the API server refuses its ServiceAccount a request.
func rbacDenied(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	var m []string
	for i := len(lines) - 1; i >= 0 && m == nil; i-- {
		m = reForbidden.FindStringSubmatch(lines[i])
	}
	if m == nil {
		return nil
	}
	saNS, sa, verb, resource, group, ns := m[1], m[2], m[3], m[4], m[5], m[6]
	res := resource
	if group != "" {
		res = resource + "." + group
	}
	scope := "in namespace " + ns
	fix := fmt.Sprintf("Grant it: kubectl create role %s-%s -n %s --verb=%s --resource=%s, then kubectl create rolebinding %s-%s -n %s --role=%s-%s --serviceaccount=%s:%s (or add the rule to a Role it already has).",
		sa, resource, ns, verb, res, sa, resource, ns, sa, resource, saNS, sa)
	if ns == "" {
		scope = "across the cluster"
		fix = fmt.Sprintf("Grant it: kubectl create clusterrole %s-%s --verb=%s --resource=%s, then kubectl create clusterrolebinding %s-%s --clusterrole=%s-%s --serviceaccount=%s:%s; or, if namespaced access is enough, make the app read only its namespace and use a Role.",
			sa, resource, verb, res, sa, resource, sa, resource, saNS, sa)
	}
	ev = append(ev, Evidence{Object: kube.Ref{Kind: "RoleBinding", Namespace: saNS, Name: "*"}, What: "the RoleBindings and ClusterRoleBindings and the subjects they name",
		Command: "kubectl get rolebindings,clusterrolebindings -A -o wide"})
	return newProblem(p, cs.Name, "KD126", "ServiceAccount lacks RBAC permission", Critical,
		fmt.Sprintf("container %s exits because the API server refuses its ServiceAccount %s: it may not %s %s %s", cs.Name, sa, verb, res, scope),
		"rbac|"+sa+"|"+verb+"|"+res, fix, ev...)
}

// readyBehind counts the ready pods a Service's selector matches.
func readyBehind(ix *index, svc kube.Service) int {
	n := 0
	for _, q := range ix.s.Pods {
		if q.Metadata.Namespace == svc.Metadata.Namespace && kube.MatchesMap(svc.Spec.Selector, q.Metadata.Labels) && q.Ready() {
			n++
		}
	}
	return n
}

// nodeDNS finds a container that exits because a cluster name does not resolve, in a pod that uses the node's
// resolver instead of cluster DNS: dnsPolicy Default, or a pod on the host network with dnsPolicy ClusterFirst (the
// default), which there falls back to the node's resolver. The node's resolver knows no Services.
func nodeDNS(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	policy := p.Spec.DNSPolicy
	if policy == "" {
		policy = "ClusterFirst"
	}
	hostNet := p.Spec.HostNetwork && policy == "ClusterFirst"
	if !hostNet && policy != "Default" {
		return nil
	}
	host, line := unresolvedHost(lines)
	if host == "" {
		return nil
	}
	lower := strings.ToLower(host)
	if !strings.HasSuffix(lower, ".svc") && !strings.Contains(lower, ".svc.") {
		svcNS, svc, isSvc := serviceName(p.Metadata.Namespace, host)
		if !isSvc {
			return nil
		}
		if exists, _ := ix.serviceExists(svcNS, svc); !exists {
			return nil
		}
	}
	why := "the pod sets dnsPolicy Default, which means the node's resolver"
	fix := "Set dnsPolicy: ClusterFirst (or remove dnsPolicy), so the pod uses cluster DNS and falls back to the node's resolver for outside names."
	what := "the pod sets dnsPolicy Default"
	if hostNet {
		why = "the pod runs on the host network with dnsPolicy ClusterFirst, which for such pods means the node's resolver"
		fix = "Set dnsPolicy: ClusterFirstWithHostNet in the pod spec, so a pod on the host network uses cluster DNS."
		what = "the pod sets hostNetwork: true and dnsPolicy ClusterFirst"
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: what,
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.spec.hostNetwork}{" "}{.spec.dnsPolicy}`)})
	return newProblem(p, cs.Name, "KD261", "Pod resolves names with the node's DNS", Critical,
		fmt.Sprintf("container %s exits because %s does not resolve: %s, and that resolver knows no Services; its log says: %q", cs.Name, host, why, clip(line, 160)),
		"nodedns|"+what, fix, ev...)
}

// customDNS finds a container that exits because a Service of the cluster does not resolve, in a pod with dnsPolicy
// None: its resolv.conf holds only the nameservers and search domains in spec.dnsConfig. Unless one of those
// nameservers is cluster DNS and the search domains include the namespace's svc domain, Service names do not resolve.
func customDNS(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	if p.Spec.DNSPolicy != "None" {
		return nil
	}
	host, line := unresolvedHost(lines)
	if host == "" {
		return nil
	}
	lower := strings.ToLower(host)
	if !strings.HasSuffix(lower, ".svc") && !strings.Contains(lower, ".svc.") {
		svcNS, svc, isSvc := serviceName(p.Metadata.Namespace, host)
		if !isSvc {
			return nil
		}
		if exists, _ := ix.serviceExists(svcNS, svc); !exists {
			return nil
		}
	}
	servers, searches := "no nameservers", "no search domains"
	if d := p.Spec.DNSConfig; d != nil {
		if len(d.Nameservers) > 0 {
			servers = "nameservers " + strings.Join(d.Nameservers, ", ")
		}
		if len(d.Searches) > 0 {
			searches = "search domains " + strings.Join(d.Searches, ", ")
		}
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("the pod sets dnsPolicy None, with %s and %s", servers, searches),
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, `{.spec.dnsPolicy}{" "}{.spec.dnsConfig}`)})
	return newProblem(p, cs.Name, "KD269", "Pod's DNS settings leave out cluster DNS", Critical,
		fmt.Sprintf("container %s exits because %s does not resolve: the pod sets dnsPolicy None, so its resolv.conf has only its dnsConfig (%s, %s), and those do not answer for the cluster's Services; its log says: %q", cs.Name, host, servers, searches, clip(line, 160)),
		"nonedns|"+p.Metadata.Namespace,
		fmt.Sprintf("Use dnsPolicy ClusterFirst and put extra nameservers or search domains in dnsConfig, which ClusterFirst adds to cluster DNS; or, keeping None, list the cluster DNS Service's IP (kubectl get svc -n kube-system kube-dns) and the search domains %s.svc.cluster.local, svc.cluster.local and cluster.local.", p.Metadata.Namespace),
		ev...)
}

// subdomainUnserved says why a pod's spec.subdomain gives it no DNS name: cluster DNS answers
// hostname.subdomain.namespace.svc only for a headless Service named subdomain that selects the pod. A StatefulSet's
// pods get their subdomain from its serviceName, which KD182 checks. It returns "" when the name exists or the
// Services were not read.
func subdomainUnserved(ix *index, p kube.Pod) string {
	sub := p.Spec.Subdomain
	if sub == "" || !ix.read("services") {
		return ""
	}
	if o, ok := p.Metadata.Controller(); ok && o.Kind == "StatefulSet" {
		return ""
	}
	for _, svc := range ix.s.Services {
		if svc.Metadata.Namespace != p.Metadata.Namespace || svc.Metadata.Name != sub {
			continue
		}
		switch {
		case svc.Spec.ClusterIP != "None":
			return fmt.Sprintf("Service %s is not headless (it has clusterIP %s), and only a headless Service publishes its pods' own names", sub, svc.Spec.ClusterIP)
		case len(svc.Spec.Selector) == 0 || !kube.MatchesMap(svc.Spec.Selector, p.Metadata.Labels):
			return fmt.Sprintf("headless Service %s does not select the pod (its selector is %s)", sub, orNone(kube.FormatMap(svc.Spec.Selector)))
		}
		return ""
	}
	return fmt.Sprintf("there is no Service %s in namespace %s", sub, p.Metadata.Namespace)
}

func orNone(s string) string {
	if s == "" {
		return "empty"
	}
	return s
}

// podDNSName is the name a pod with a subdomain is meant to have: its hostname (or, for a Job's indexed pods, the
// name the Job gives it) and subdomain.
func podDNSName(p kube.Pod) string {
	h := p.Spec.Hostname
	if h == "" {
		h = p.Metadata.Name
	}
	return h + "." + p.Spec.Subdomain
}

// subdomainProblem finds a pod whose spec.subdomain no headless Service serves. A container that fails to resolve a
// name under that subdomain, as a worker looking up its peers does, makes it critical; otherwise it is a warning that
// the name the pod was given does not exist.
func subdomainProblem(ix *index, p kube.Pod, cs *kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	why := subdomainUnserved(ix, p)
	if why == "" {
		return nil
	}
	sub, ns := p.Spec.Subdomain, p.Metadata.Namespace
	spec := Evidence{Object: p.Ref(), What: fmt.Sprintf("the pod sets subdomain %s; %s", sub, why),
		Command: cmdGet("pod", ns, p.Metadata.Name, "{.spec.hostname}{\" \"}{.spec.subdomain}")}
	svcEv := Evidence{Object: kube.Ref{Kind: "Service", Namespace: ns, Name: sub}, What: "the Service named for the subdomain",
		Command: cmdGet("service", ns, sub, `{.spec.clusterIP}{" "}{.spec.selector}`)}
	fix := fmt.Sprintf("Create a headless Service named %s (clusterIP: None) whose selector matches the pods, or point spec.subdomain at the one that does; peers then resolve each other as HOSTNAME.%s.", sub, sub)
	if cs != nil {
		host, line := unresolvedHost(lines)
		labels := strings.Split(strings.ToLower(host), ".")
		if len(labels) < 2 || labels[1] != strings.ToLower(sub) {
			return nil
		}
		return newProblem(p, cs.Name, "KD266", "Pod's subdomain has no headless Service", Critical,
			fmt.Sprintf("container %s exits because it cannot resolve %s: pods with subdomain %s get names under it only from a headless Service of that name, and %s; its log says: %q", cs.Name, host, sub, why, clip(line, 200)),
			"subdomain|"+sub, fix, append(ev, spec, svcEv)...)
	}
	return newProblem(p, "", "KD266", "Pod's subdomain has no headless Service", Warning,
		fmt.Sprintf("the pod sets hostname and subdomain for the DNS name %s.%s.svc, but %s, so that name does not resolve and peers that look it up fail", podDNSName(p), ns, why),
		"subdomain|"+sub, fix, spec, svcEv)
}

// externalNameUnresolved finds a container that exits because it cannot resolve a Service that exists and is of type
// ExternalName: cluster DNS answers the Service's name with a CNAME to its externalName, so when that name does not
// resolve (a typo, an internal name the cluster's DNS cannot see, a record since removed) neither does the Service.
func externalNameUnresolved(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, line := unresolvedHost(lines)
	if host == "" {
		return nil
	}
	svcNS, name, ok := serviceName(p.Metadata.Namespace, host)
	if !ok {
		return nil
	}
	for _, svc := range ix.s.Services {
		if svc.Metadata.Namespace != svcNS || svc.Metadata.Name != name || svc.Spec.Type != "ExternalName" {
			continue
		}
		target := svc.Spec.ExternalName
		ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s is of type ExternalName and points at %s", name, target),
			Command: cmdGet("service", svcNS, name, `{.spec.type}{" "}{.spec.externalName}`)})
		return newProblem(p, cs.Name, "KD270", "ExternalName Service points at a name that does not resolve", Critical,
			fmt.Sprintf("container %s exits because %s does not resolve: Service %s is of type ExternalName, so cluster DNS answers it with a CNAME to %s, and that name does not resolve from the cluster; its log says: %q", cs.Name, host, name, target, clip(line, 200)),
			"extname|"+svcNS+"/"+name,
			fmt.Sprintf("Correct Service %s's externalName to a name the cluster's DNS can resolve (check it from a pod: nslookup %s), or, for an address, use a Service without a selector and an EndpointSlice.", name, target),
			ev...)
	}
	return nil
}

// rePeerHost matches a StatefulSet pod's DNS name, NAME-N.SERVICE, with whatever follows.
var rePeerHost = regexp.MustCompile(`^([a-z0-9-]+)-(\d+)\.([a-z0-9-]+)(?:\.|$)`)

// peerNotPublished finds a StatefulSet's pod that exits because it cannot resolve a peer's DNS name, while the
// governing Service publishes only ready pods: a peer gets its record once it is ready, and it is ready only once the
// cluster has formed, so pods that look each other up while they start wait for each other for ever.
func peerNotPublished(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	o, ok := p.Metadata.Controller()
	if !ok || o.Kind != "StatefulSet" {
		return nil
	}
	ns := p.Metadata.Namespace
	sts := ix.workloads[kube.Ref{Kind: "StatefulSet", Namespace: ns, Name: o.Name}]
	host, line := unresolvedHost(lines)
	m := rePeerHost.FindStringSubmatch(strings.ToLower(host))
	if sts == nil || m == nil || m[1] != o.Name || m[3] != sts.Spec.ServiceName {
		return nil
	}
	var svc *kube.Service
	for i := range ix.s.Services {
		if s := &ix.s.Services[i]; s.Metadata.Namespace == ns && s.Metadata.Name == m[3] {
			svc = s
		}
	}
	if svc == nil || svc.Spec.ClusterIP != "None" || svc.Spec.PublishNotReadyAddresses {
		return nil // no headless Service is KD182's, and one that publishes every pod is not this
	}
	peer := m[1] + "-" + m[2]
	cause := fmt.Sprintf("container %s exits because it cannot resolve its peer %s: headless Service %s publishes a pod's DNS record only once the pod is ready, and the peers become ready only after they find each other, so they wait on each other for ever; its log says: %q",
		cs.Name, host, svc.Metadata.Name, clip(line, 200))
	if sts.Spec.PodManagementPolicy != "Parallel" {
		cause += fmt.Sprintf("; with podManagementPolicy OrderedReady, %s is not even created until the pods before it are ready", peer)
	}
	ev = append(ev, Evidence{Object: kube.Ref{Kind: "Service", Namespace: ns, Name: svc.Metadata.Name},
		What:    fmt.Sprintf("headless Service %s, the StatefulSet's serviceName, publishes ready pods only", svc.Metadata.Name),
		Command: cmdGet("service", ns, svc.Metadata.Name, `{.spec.clusterIP}{" "}{.spec.publishNotReadyAddresses}`)})
	fix := fmt.Sprintf("Set publishNotReadyAddresses: true on Service %s, so each pod's name resolves as soon as it has an address (the usual setting for the Service of a database or consensus cluster's peers); keep a separate Service for clients that should reach ready pods only.", svc.Metadata.Name)
	if sts.Spec.PodManagementPolicy != "Parallel" {
		fix += " Add podManagementPolicy: Parallel to the StatefulSet as well, so every peer is created at once."
	}
	return newProblem(p, cs.Name, "KD373", "StatefulSet's peers have no DNS records until they are ready", Critical, cause, "peerdns|"+svc.Metadata.Name, fix, ev...)
}
