package diagnose

import (
	"fmt"
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
	for _, rt := range ix.s.Routes {
		out = append(out, routeParentFindings(ix, rt)...)
		out = append(out, routeBackendFindings(ix, rt)...)
		out = append(out, routePortFindings(ix, rt)...)
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
		// next parent checks
		_ = gw
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
