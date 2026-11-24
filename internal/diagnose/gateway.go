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
		out = append(out, routeBackendFindings(ix, rt)...)
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
