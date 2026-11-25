package diagnose

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// The Gateway API's resources, as the collector reads them.
const (
	gatewaysResource       = "gateways.gateway.networking.k8s.io"
	gatewayClassesResource = "gatewayclasses.gateway.networking.k8s.io"
)

// gatewayFindings checks what the Gateway API's objects name: a Gateway's class, a route's Gateways and listeners,
// and the Services its rules send traffic to. Each is a reference a controller resolves; one that resolves to nothing
// leaves the route, or the Gateway, serving nothing, whatever controller runs it.
func gatewayFindings(ix *index) []Finding {
	var out []Finding
	for _, gw := range ix.s.Gateways {
		if f := gatewayClassMissing(ix, gw); f != nil {
			out = append(out, *f)
		}
		if f := listenerCertificate(ix, gw); f != nil {
			out = append(out, *f)
		}
	}
	out = append(out, routeConflicts(ix)...)
	for _, rt := range ix.s.Routes {
		out = append(out, routeParentFindings(ix, rt)...)
		out = append(out, routeBackendFindings(ix, rt)...)
		out = append(out, routePortFindings(ix, rt)...)
		out = append(out, routeZeroWeights(rt)...)
		if f := backendNotGranted(ix, rt); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// routeBackend is a Service a route rule sends traffic to.
type routeBackend struct {
	rule int // 1-based, as people count a route's rules
	ref  kube.BackendRef
	ns   string
}

func routeBackends(rt kube.Route) []routeBackend {
	var out []routeBackend
	for i, r := range rt.Spec.Rules {
		for _, b := range r.BackendRefs {
			if (b.Group != "" && b.Group != "core") || (b.Kind != "" && b.Kind != "Service") {
				continue
			}
			ns := b.Namespace
			if ns == "" {
				ns = rt.Metadata.Namespace
			}
			out = append(out, routeBackend{i + 1, b, ns})
		}
	}
	return out
}

func routeEvidence(rt kube.Route, what, jsonpath string) Evidence {
	return Evidence{Object: rt.Ref(), What: what, Command: cmdGet(strings.ToLower(rt.Kind), rt.Metadata.Namespace, rt.Metadata.Name, jsonpath)}
}

// routeBackendFindings finds a route rule that sends traffic to a Service that does not exist.
func routeBackendFindings(ix *index, rt kube.Route) []Finding {
	if !ix.read("services") {
		return nil
	}
	services := map[nsName]kube.Service{}
	for _, s := range ix.s.Services {
		services[nsName{s.Metadata.Namespace, s.Metadata.Name}] = s
	}
	missing := map[string][]string{}
	var ev []Evidence
	for _, b := range routeBackends(rt) {
		if !ix.nsRead(b.ns) {
			continue
		}
		if _, ok := services[nsName{b.ns, b.ref.Name}]; !ok {
			name := b.ref.Name
			if b.ns != rt.Metadata.Namespace {
				name = b.ns + "/" + name
			}
			if len(missing[name]) == 0 {
				ev = append(ev, Evidence{Object: kube.Ref{Kind: "Service", Namespace: b.ns, Name: b.ref.Name},
					What: fmt.Sprintf("there is no Service %s in namespace %s", b.ref.Name, b.ns), Command: cmdGet("service", b.ns, b.ref.Name, "")})
			}
			missing[name] = append(missing[name], "rule "+strconv.Itoa(b.rule))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	var parts []string
	for _, n := range sortedKeys(missing) {
		parts = append(parts, fmt.Sprintf("%s (from %s)", n, strings.Join(missing[n], ", ")))
	}
	sort.Strings(parts)
	return []Finding{{Rule: "KD362", Title: "Route sends traffic to a Service that does not exist", Severity: Critical, Object: rt.Ref(),
		Cause: fmt.Sprintf("%s %s sends traffic to Service %s, which does not exist, so the Gateway answers the requests that rule matches with an error (HTTP 500, as the Gateway API requires for a backend it cannot resolve)",
			rt.Kind, rt.Metadata.Name, strings.Join(parts, " and ")),
		Evidence: append([]Evidence{routeEvidence(rt, rt.Kind+" backendRefs", "{.spec.rules[*].backendRefs}")}, ev...),
		Fix:      fmt.Sprintf("Correct the backendRef's name in %s %s, or create the Service.", rt.Kind, rt.Metadata.Name)}}
}

// routePortFindings finds a route rule that sends traffic to a port its Service does not expose. A backendRef's port
// is the Service's port, not the pods' targetPort, and a route naming the container's port reaches nothing.
func routePortFindings(ix *index, rt kube.Route) []Finding {
	if !ix.read("services") {
		return nil
	}
	var bad []string
	var ev []Evidence
	seen := map[string]bool{}
	for _, b := range routeBackends(rt) {
		if b.ref.Port == nil {
			continue
		}
		for _, svc := range ix.s.Services {
			if svc.Metadata.Namespace != b.ns || svc.Metadata.Name != b.ref.Name {
				continue
			}
			var have []string
			found := false
			for _, sp := range svc.Spec.Ports {
				found = found || sp.Port == *b.ref.Port
				desc := strconv.Itoa(int(sp.Port))
				if sp.TargetPort.String() != "" && sp.TargetPort.String() != desc {
					desc += " (to the pods' " + sp.TargetPort.String() + ")"
				}
				have = append(have, desc)
			}
			if found {
				continue
			}
			bad = append(bad, fmt.Sprintf("port %d of Service %s (from rule %d), which exposes port %s", *b.ref.Port, svc.Metadata.Name, b.rule, strings.Join(have, ", ")))
			if !seen[svc.Metadata.Name] {
				seen[svc.Metadata.Name] = true
				ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s exposes port %s", svc.Metadata.Name, strings.Join(have, ", ")),
					Command: cmdGet("service", svc.Metadata.Namespace, svc.Metadata.Name, "{.spec.ports}")})
			}
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return []Finding{{Rule: "KD363", Title: "Route sends traffic to a port the Service does not expose", Severity: Critical, Object: rt.Ref(),
		Cause: fmt.Sprintf("%s %s sends traffic to %s, so the Gateway has no endpoints for that rule and answers its requests with an error",
			rt.Kind, rt.Metadata.Name, strings.Join(bad, "; ")),
		Evidence: append([]Evidence{routeEvidence(rt, rt.Kind+" backendRefs", "{.spec.rules[*].backendRefs}")}, ev...),
		Fix:      "Set the backendRef's port to a port the Service exposes (its port, not the container's targetPort)."}}
}

// routeParentFindings checks each Gateway a route attaches to: that it exists, and what of it the route names.
func routeParentFindings(ix *index, rt kube.Route) []Finding {
	if len(rt.Spec.ParentRefs) == 0 {
		return []Finding{{Rule: "KD372", Title: "Route is attached to no Gateway", Severity: Critical, Object: rt.Ref(),
			Cause:    fmt.Sprintf("%s %s has no parentRefs, so it is attached to no Gateway, and no Gateway sends it a request", rt.Kind, rt.Metadata.Name),
			Evidence: []Evidence{routeEvidence(rt, rt.Kind+" parentRefs", "{.spec.parentRefs}")},
			Fix:      fmt.Sprintf("Add a parentRef to %s %s naming the Gateway (and its listener, by sectionName) that should serve it; kubectl get gateways -A lists them.", rt.Kind, rt.Metadata.Name)}}
	}
	if !ix.read(gatewaysResource) {
		return nil
	}
	var out []Finding
	for _, p := range rt.Spec.ParentRefs {
		if (p.Group != "" && p.Group != "gateway.networking.k8s.io") || (p.Kind != "" && p.Kind != "Gateway") {
			continue
		}
		ns := p.Namespace
		if ns == "" {
			ns = rt.Metadata.Namespace
		}
		if !ix.nsRead(ns) {
			continue
		}
		gw, ok := findGateway(ix, ns, p.Name)
		if !ok {
			out = append(out, parentMissing(ix, rt, p, ns))
			continue
		}
		ls := listenersFor(gw, p)
		if len(ls) == 0 {
			out = append(out, listenerMissing(rt, p, gw))
			continue
		}
		admits, why, fix := admitting(ix, rt, gw, ls)
		if len(admits) == 0 {
			out = append(out, notAdmitted(rt, gw, why, fix))
			continue
		}
		if f := hostnameUnserved(rt, gw, admits); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func findGateway(ix *index, ns, name string) (kube.Gateway, bool) {
	for _, g := range ix.s.Gateways {
		if g.Metadata.Namespace == ns && g.Metadata.Name == name {
			return g, true
		}
	}
	return kube.Gateway{}, false
}

// parentMissing is a route attached to a Gateway that does not exist.
func parentMissing(ix *index, rt kube.Route, p kube.ParentRef, ns string) Finding {
	var names []string
	for _, g := range ix.s.Gateways {
		if g.Metadata.Namespace == ns {
			names = append(names, g.Metadata.Name)
		}
	}
	sort.Strings(names)
	have := fmt.Sprintf("namespace %s has no Gateway", ns)
	if len(names) > 0 {
		have = fmt.Sprintf("the Gateways of namespace %s are %s", ns, strings.Join(names, ", "))
	}
	return Finding{Rule: "KD364", Title: "Route is attached to a Gateway that does not exist", Severity: Critical, Object: rt.Ref(),
		Cause: fmt.Sprintf("%s %s attaches to Gateway %s, which does not exist in namespace %s, so no Gateway serves the route and its requests get no answer from the cluster; %s",
			rt.Kind, rt.Metadata.Name, p.Name, ns, have),
		Evidence: []Evidence{routeEvidence(rt, rt.Kind+" parentRefs", "{.spec.parentRefs}"),
			{Object: kube.Ref{Kind: "Gateway", Namespace: ns, Name: p.Name}, What: have, Command: fmt.Sprintf("kubectl get gateways -n %s", ns)}},
		Fix: fmt.Sprintf("Correct the parentRef's name in %s %s (and its namespace, for a Gateway in another namespace), or create the Gateway.", rt.Kind, rt.Metadata.Name)}
}

// gatewayClassMissing is a Gateway whose gatewayClassName names a class the cluster does not have: no controller
// takes it, so it gets no address and serves none of its routes.
func gatewayClassMissing(ix *index, gw kube.Gateway) *Finding {
	if !ix.read(gatewayClassesResource) {
		return nil
	}
	var names []string
	for _, c := range ix.s.GatewayClasses {
		if c.Metadata.Name == gw.Spec.GatewayClassName {
			return nil
		}
		names = append(names, c.Metadata.Name)
	}
	sort.Strings(names)
	have := "the cluster has no GatewayClass, so no Gateway controller is installed"
	if len(names) > 0 {
		have = "the cluster's GatewayClasses are " + strings.Join(names, ", ")
	}
	ns := gw.Metadata.Namespace
	return &Finding{Rule: "KD365", Title: "Gateway names a GatewayClass that does not exist", Severity: Critical, Object: gw.Ref(),
		Cause: fmt.Sprintf("Gateway %s names GatewayClass %s, which does not exist, so no controller takes the Gateway: it gets no address, and the routes attached to it are served by nothing; %s",
			gw.Metadata.Name, gw.Spec.GatewayClassName, have),
		Evidence: []Evidence{{Object: gw.Ref(), What: fmt.Sprintf("Gateway %s has gatewayClassName %s", gw.Metadata.Name, gw.Spec.GatewayClassName),
			Command: cmdGet("gateway", ns, gw.Metadata.Name, "{.spec.gatewayClassName}")},
			{Object: kube.Ref{Kind: "GatewayClass", Name: gw.Spec.GatewayClassName}, What: have, Command: "kubectl get gatewayclasses"}},
		Fix: "Set gatewayClassName to a class the cluster has (kubectl get gatewayclasses); a Gateway's class cannot be changed, so delete the Gateway and create it again with the right one."}
}

// listenersFor returns the listeners of a Gateway that a parentRef picks: the one its sectionName names and those on
// its port, or every listener when it names neither.
func listenersFor(gw kube.Gateway, p kube.ParentRef) []kube.Listener {
	var out []kube.Listener
	for _, l := range gw.Spec.Listeners {
		if (p.SectionName == "" || l.Name == p.SectionName) && (p.Port == nil || l.Port == *p.Port) {
			out = append(out, l)
		}
	}
	return out
}

func describeListeners(ls []kube.Listener) string {
	var parts []string
	for _, l := range ls {
		d := fmt.Sprintf("%s (port %d, %s", l.Name, l.Port, l.Protocol)
		if l.Hostname != "" {
			d += ", " + l.Hostname
		}
		parts = append(parts, d+")")
	}
	return strings.Join(parts, ", ")
}

func gatewayEvidence(gw kube.Gateway) Evidence {
	return Evidence{Object: gw.Ref(), What: fmt.Sprintf("Gateway %s has listeners %s", gw.Metadata.Name, describeListeners(gw.Spec.Listeners)),
		Command: cmdGet("gateway", gw.Metadata.Namespace, gw.Metadata.Name, "{.spec.listeners}")}
}

// listenerMissing is a route whose parentRef names a listener, by sectionName or port, that its Gateway does not have.
func listenerMissing(rt kube.Route, p kube.ParentRef, gw kube.Gateway) Finding {
	var named []string
	if p.SectionName != "" {
		named = append(named, "listener "+p.SectionName)
	}
	if p.Port != nil {
		named = append(named, fmt.Sprintf("port %d", *p.Port))
	}
	return Finding{Rule: "KD366", Title: "Route names a listener the Gateway does not have", Severity: Critical, Object: rt.Ref(),
		Cause: fmt.Sprintf("%s %s attaches to %s of Gateway %s, and the Gateway has no such listener, so the route is attached to nothing; its listeners are %s",
			rt.Kind, rt.Metadata.Name, strings.Join(named, " on "), gw.Metadata.Name, describeListeners(gw.Spec.Listeners)),
		Evidence: []Evidence{routeEvidence(rt, rt.Kind+" parentRefs", "{.spec.parentRefs}"), gatewayEvidence(gw)},
		Fix:      fmt.Sprintf("Set the parentRef's sectionName (and port) to a listener of Gateway %s, or leave them out to attach to every listener that admits the route.", gw.Metadata.Name)}
}

// routeKinds is what each listener protocol takes when its allowedRoutes names no kinds.
var routeKinds = map[string][]string{"HTTP": {"HTTPRoute", "GRPCRoute"}, "HTTPS": {"HTTPRoute", "GRPCRoute"}, "TLS": {"TLSRoute"}, "TCP": {"TCPRoute"}, "UDP": {"UDPRoute"}}

// admitting returns the listeners that admit the route, by its kind and its namespace, and for those that do not,
// why not and what would let them.
func admitting(ix *index, rt kube.Route, gw kube.Gateway, ls []kube.Listener) ([]kube.Listener, []string, string) {
	var ok []kube.Listener
	var why []string
	fix := ""
	for _, l := range ls {
		kinds := routeKinds[l.Protocol]
		from, sel := "Same", (*kube.LabelSelector)(nil)
		if a := l.AllowedRoutes; a != nil {
			if len(a.Kinds) > 0 {
				kinds = nil
				for _, k := range a.Kinds {
					if k.Group == "" || k.Group == "gateway.networking.k8s.io" {
						kinds = append(kinds, k.Kind)
					}
				}
			}
			if a.Namespaces != nil {
				if a.Namespaces.From != "" {
					from = a.Namespaces.From
				}
				sel = a.Namespaces.Selector
			}
		}
		if !slices.Contains(kinds, rt.Kind) {
			why = append(why, fmt.Sprintf("listener %s (%s) takes %s, not %ss", l.Name, l.Protocol, strings.Join(kinds, " and "), rt.Kind))
			if fix == "" {
				fix = fmt.Sprintf("Attach the route to a listener whose protocol and allowedRoutes.kinds take %ss, or add %s to listener %s's allowedRoutes.kinds.", rt.Kind, rt.Kind, l.Name)
			}
			continue
		}
		ns := rt.Metadata.Namespace
		switch from {
		case "All":
			ok = append(ok, l)
		case "Selector":
			labels, known := namespaceLabels(ix, ns)
			if !known || sel == nil || sel.Matches(labels) {
				ok = append(ok, l)
				continue
			}
			why = append(why, fmt.Sprintf("listener %s admits routes from namespaces labelled %s only (allowedRoutes.namespaces.from: Selector), and namespace %s has labels %s",
				l.Name, formatSelector(*sel), ns, kube.FormatMap(labels)))
			if fix == "" {
				fix = fmt.Sprintf("Label namespace %s so listener %s's selector matches it, or correct the selector on Gateway %s.", ns, l.Name, gw.Metadata.Name)
			}
		default:
			if ns == gw.Metadata.Namespace {
				ok = append(ok, l)
				continue
			}
			why = append(why, fmt.Sprintf("listener %s admits routes from its own namespace, %s, only (allowedRoutes.namespaces.from: Same, the default), and the route is in namespace %s",
				l.Name, gw.Metadata.Namespace, ns))
			if fix == "" {
				fix = fmt.Sprintf("Set allowedRoutes.namespaces.from to All, or to Selector with a selector namespace %s matches, on listener %s of Gateway %s.", ns, l.Name, gw.Metadata.Name)
			}
		}
	}
	return ok, why, fix
}

// namespaceLabels returns a namespace's labels, and whether the namespaces were read.
func namespaceLabels(ix *index, ns string) (map[string]string, bool) {
	for _, n := range ix.s.NamespaceObjects {
		if n.Metadata.Name == ns {
			return n.Metadata.Labels, true
		}
	}
	return nil, false
}

// notAdmitted is a route that none of the listeners it attaches to admits.
func notAdmitted(rt kube.Route, gw kube.Gateway, why []string, fix string) Finding {
	return Finding{Rule: "KD368", Title: "Gateway's listeners do not admit the route", Severity: Critical, Object: rt.Ref(),
		Cause: fmt.Sprintf("%s %s attaches to Gateway %s, and no listener it attaches to admits it, so the Gateway serves none of its requests: %s",
			rt.Kind, rt.Metadata.Name, gw.Metadata.Name, strings.Join(why, "; ")),
		Evidence: []Evidence{routeEvidence(rt, rt.Kind+" parentRefs", "{.spec.parentRefs}"),
			{Object: gw.Ref(), What: fmt.Sprintf("Gateway %s's listeners and the routes they allow", gw.Metadata.Name), Command: cmdGet("gateway", gw.Metadata.Namespace, gw.Metadata.Name, "{.spec.listeners}")}},
		Fix: fix}
}

// hostMatch reports whether a listener's hostname and a route's can meet: either is empty, they are equal, or a
// wildcard (*.example.com) of one covers the other.
func hostMatch(listener, route string) bool {
	if listener == "" || route == "" || listener == route {
		return true
	}
	covers := func(wild, host string) bool {
		suffix, ok := strings.CutPrefix(wild, "*")
		host = strings.TrimPrefix(host, "*")
		return ok && strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return covers(listener, route) || covers(route, listener) ||
		strings.HasPrefix(listener, "*.") && strings.HasPrefix(route, "*.") && (strings.HasSuffix(listener, route[1:]) || strings.HasSuffix(route, listener[1:]))
}

// hostnameUnserved is a route whose hostnames none of the listeners admitting it serve.
func hostnameUnserved(rt kube.Route, gw kube.Gateway, ls []kube.Listener) *Finding {
	if len(rt.Spec.Hostnames) == 0 {
		return nil
	}
	var served []string
	for _, l := range ls {
		for _, h := range rt.Spec.Hostnames {
			if hostMatch(l.Hostname, h) {
				return nil
			}
		}
		served = append(served, l.Hostname+" (listener "+l.Name+")")
	}
	return &Finding{Rule: "KD367", Title: "Route's hostnames are served by none of its Gateway's listeners", Severity: Critical, Object: rt.Ref(),
		Cause: fmt.Sprintf("%s %s serves %s, and the listeners of Gateway %s it attaches to serve %s: no hostname is in both, so the Gateway sends none of the route's requests to it",
			rt.Kind, rt.Metadata.Name, strings.Join(rt.Spec.Hostnames, ", "), gw.Metadata.Name, strings.Join(served, ", ")),
		Evidence: []Evidence{routeEvidence(rt, rt.Kind+" hostnames", "{.spec.hostnames}"), gatewayEvidence(gw)},
		Fix:      fmt.Sprintf("Correct the hostnames of %s %s, or add a listener to Gateway %s that serves them (a listener with no hostname serves every name).", rt.Kind, rt.Metadata.Name, gw.Metadata.Name)}
}

// listenerCertificate is a Gateway whose HTTPS or TLS listener terminates TLS with a Secret that does not exist, or
// that holds no certificate and key: the controller cannot serve that listener, and refuses its connections.
func listenerCertificate(ix *index, gw kube.Gateway) *Finding {
	if !ix.read("secrets") {
		return nil
	}
	for _, l := range gw.Spec.Listeners {
		if l.TLS == nil || l.TLS.Mode == "Passthrough" {
			continue
		}
		for _, c := range l.TLS.CertificateRefs {
			if (c.Group != "" && c.Group != "core") || (c.Kind != "" && c.Kind != "Secret") {
				continue
			}
			ns := c.Namespace
			if ns == "" {
				ns = gw.Metadata.Namespace
			}
			if !ix.nsRead(ns) {
				continue
			}
			ks, exists, known := ix.keySet("secret", ns, c.Name)
			if !known {
				continue
			}
			why := fmt.Sprintf("there is no Secret %s in namespace %s", c.Name, ns)
			if exists {
				if slices.Contains(ks.Keys, "tls.crt") && slices.Contains(ks.Keys, "tls.key") {
					continue
				}
				why = fmt.Sprintf("Secret %s has keys %s, and a certificate Secret needs tls.crt and tls.key", c.Name, strings.Join(ks.Keys, ", "))
			}
			return &Finding{Rule: "KD370", Title: "Gateway listener's certificate Secret is missing or has no certificate", Severity: Critical, Object: gw.Ref(),
				Cause: fmt.Sprintf("listener %s of Gateway %s (port %d, %s) terminates TLS with Secret %s, and %s, so the controller cannot serve the listener: HTTPS clients there get no answer, or a handshake error",
					l.Name, gw.Metadata.Name, l.Port, l.Protocol, c.Name, why),
				Evidence: []Evidence{gatewayEvidence(gw), {Object: kube.Ref{Kind: "Secret", Namespace: ns, Name: c.Name}, What: why, Command: cmdGet("secret", ns, c.Name, "{.type}")}},
				Fix:      fmt.Sprintf("Create Secret %s in namespace %s of type kubernetes.io/tls (kubectl create secret tls %s --cert=... --key=... -n %s), or have cert-manager issue it; or point the listener's certificateRefs at the Secret that holds the certificate.", c.Name, ns, c.Name, ns)}
		}
	}
	return nil
}

// backendNotGranted is a route that sends traffic to a Service in another namespace that has no ReferenceGrant
// letting routes of the route's namespace refer to it: the controller does not resolve the reference, and the rule
// answers with an error.
func backendNotGranted(ix *index, rt kube.Route) *Finding {
	if !ix.read("referencegrants.gateway.networking.k8s.io") {
		return nil
	}
	for _, b := range routeBackends(rt) {
		if b.ns == rt.Metadata.Namespace || !ix.nsRead(b.ns) || granted(ix, rt, b) {
			continue
		}
		return &Finding{Rule: "KD369", Title: "Route sends traffic to another namespace that does not grant it", Severity: Critical, Object: rt.Ref(),
			Cause: fmt.Sprintf("%s %s sends traffic to Service %s in namespace %s (from rule %d), and no ReferenceGrant in namespace %s lets %ss of namespace %s refer to its Services, so the controller does not resolve the reference and answers that rule's requests with an error",
				rt.Kind, rt.Metadata.Name, b.ref.Name, b.ns, b.rule, b.ns, rt.Kind, rt.Metadata.Namespace),
			Evidence: []Evidence{routeEvidence(rt, rt.Kind+" backendRefs", "{.spec.rules[*].backendRefs}"),
				{Object: kube.Ref{Kind: "ReferenceGrant", Namespace: b.ns, Name: "*"}, What: fmt.Sprintf("the ReferenceGrants of namespace %s", b.ns), Command: "kubectl get referencegrants -n " + b.ns + " -o yaml"}},
			Fix: fmt.Sprintf("Create a ReferenceGrant in namespace %s with from: [{group: gateway.networking.k8s.io, kind: %s, namespace: %s}] and to: [{group: \"\", kind: Service}] (name: %s to allow that Service only).",
				b.ns, rt.Kind, rt.Metadata.Namespace, b.ref.Name)}
	}
	return nil
}

// granted reports whether a ReferenceGrant in the backend's namespace lets the route refer to its Service.
func granted(ix *index, rt kube.Route, b routeBackend) bool {
	for _, g := range ix.s.ReferenceGrants {
		if g.Metadata.Namespace != b.ns {
			continue
		}
		from := false
		for _, f := range g.Spec.From {
			from = from || f.Group == "gateway.networking.k8s.io" && f.Kind == rt.Kind && f.Namespace == rt.Metadata.Namespace
		}
		for _, t := range g.Spec.To {
			if from && t.Group == "" && t.Kind == "Service" && (t.Name == "" || t.Name == b.ref.Name) {
				return true
			}
		}
	}
	return false
}

// routeClaim is one HTTPRoute rule's claim on a hostname and path of a Gateway.
type routeClaim struct {
	rt       kube.Route
	backends string
}

// precedes reports whether route a wins a tie with route b: the Gateway API gives it to the older route, and between
// routes created in the same second to the first by namespace and name.
func precedes(a, b kube.Route) bool {
	if !a.Metadata.CreationTimestamp.Equal(b.Metadata.CreationTimestamp) {
		return a.Metadata.CreationTimestamp.Before(b.Metadata.CreationTimestamp)
	}
	return a.Metadata.Namespace+"/"+a.Metadata.Name < b.Metadata.Namespace+"/"+b.Metadata.Name
}

// routeConflicts finds HTTPRoutes on one Gateway that send the same hostname and path to different Services. A match
// with headers, query parameters or a method is narrower than the path, and left out. The route that loses the tie
// gets none of those requests.
func routeConflicts(ix *index) []Finding {
	routes := []kube.Route{}
	for _, rt := range ix.s.Routes {
		if rt.Kind == "HTTPRoute" {
			routes = append(routes, rt)
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return precedes(routes[i], routes[j]) })
	claims := map[string]routeClaim{}
	lost := map[kube.Ref][]string{}
	var order []kube.Ref
	for _, rt := range routes {
		hosts := rt.Spec.Hostnames
		if len(hosts) == 0 {
			hosts = []string{"*"}
		}
		for _, p := range rt.Spec.ParentRefs {
			ns := p.Namespace
			if ns == "" {
				ns = rt.Metadata.Namespace
			}
			for _, rule := range rt.Spec.Rules {
				var names []string
				for _, b := range rule.BackendRefs {
					names = append(names, "Service "+b.Name)
				}
				sort.Strings(names)
				backends := strings.Join(names, " and ")
				matches := rule.Matches
				if len(matches) == 0 {
					matches = []kube.RouteMatch{{}}
				}
				for _, m := range matches {
					if len(m.Headers) > 0 || len(m.QueryParams) > 0 || m.Method != "" {
						continue
					}
					typ, val := "PathPrefix", "/"
					if m.Path != nil {
						if m.Path.Type != "" {
							typ = m.Path.Type
						}
						if m.Path.Value != "" {
							val = m.Path.Value
						}
					}
					for _, h := range hosts {
						key := strings.Join([]string{ns, p.Name, p.SectionName, h, typ, val}, "|")
						first, ok := claims[key]
						if !ok {
							claims[key] = routeClaim{rt, backends}
							continue
						}
						if first.rt.Ref() == rt.Ref() || first.backends == backends {
							continue
						}
						if len(lost[rt.Ref()]) == 0 {
							order = append(order, rt.Ref())
						}
						lost[rt.Ref()] = append(lost[rt.Ref()], fmt.Sprintf("%s %s %s (to %s; %s %s sends it to %s), on Gateway %s",
							h, map[string]string{"PathPrefix": "with path prefix", "Exact": "with path", "RegularExpression": "with path matching"}[typ], val,
							backends, first.rt.Kind, first.rt.Metadata.Name, first.backends, p.Name))
					}
				}
			}
		}
	}
	var out []Finding
	for _, ref := range order {
		parts := lost[ref]
		out = append(out, Finding{Rule: "KD371", Title: "HTTPRoutes send the same hostname and path to different Services", Severity: Warning, Object: ref,
			Cause: fmt.Sprintf("HTTPRoute %s claims %s: another route on the same Gateway already claims each of those, and the Gateway API gives a tie to the older route (or, created in the same second, the first by name), so %s gets none of those requests",
				ref.Name, strings.Join(parts, "; "), ref.Name),
			Evidence: []Evidence{{Object: ref, What: "the route's hostnames and matches", Command: cmdGet("httproute", ref.Namespace, ref.Name, "{.spec.hostnames}{\"\\n\"}{.spec.rules[*].matches}")},
				{Object: kube.Ref{Kind: "HTTPRoute", Namespace: ref.Namespace, Name: "*"}, What: "the namespace's HTTPRoutes, oldest first", Command: "kubectl get httproutes -n " + ref.Namespace + " --sort-by=.metadata.creationTimestamp"}},
			Fix: "Give the routes different hostnames or paths, or merge them; for a canary, send one rule to both Services with weights on its backendRefs."})
	}
	return out
}

// routeZeroWeights finds a route rule whose backends all have weight 0: the Gateway sends none of them a request
// and answers every request the rule matches with an error (500 for an HTTPRoute). It is a canary or a cutover
// left half done: the new backend added at 0, then the old one set to 0 too.
func routeZeroWeights(rt kube.Route) []Finding {
	var out []Finding
	for i, r := range rt.Spec.Rules {
		if len(r.BackendRefs) == 0 {
			continue
		}
		var names []string
		zero := true
		for _, b := range r.BackendRefs {
			zero = zero && b.Weight != nil && *b.Weight == 0
			names = append(names, b.Name)
		}
		if !zero {
			continue
		}
		answer := "an HTTP 500"
		if rt.Kind == "GRPCRoute" {
			answer = "an UNAVAILABLE error"
		}
		out = append(out, Finding{Rule: "KD374", Title: "Route rule gives every backend weight 0", Severity: Critical, Object: rt.Ref(),
			Cause: fmt.Sprintf("rule %d of %s %s sends traffic to %s, all with weight 0, so the Gateway sends none of them a request and answers each request the rule matches with %s",
				i+1, rt.Kind, rt.Metadata.Name, strings.Join(names, ", "), answer),
			Evidence: []Evidence{routeEvidence(rt, fmt.Sprintf("rule %d's backendRefs and their weights", i+1), fmt.Sprintf("{.spec.rules[%d].backendRefs}", i))},
			Fix:      fmt.Sprintf("Give at least one backend of rule %d a weight above 0 (leaving weight out means 1); to take a backend out of service, remove it from the rule.", i+1)})
	}
	return out
}
