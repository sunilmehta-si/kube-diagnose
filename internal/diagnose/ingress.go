package diagnose

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// ingressRoute is one host and path of an Ingress and the Service port it sends traffic to.
type ingressRoute struct {
	where   string // "shop.example.com/api", or "default backend"
	backend *kube.IngressServiceBackend
}

func ingressRoutes(ing kube.Ingress) []ingressRoute {
	var out []ingressRoute
	if b := ing.Spec.DefaultBackend; b != nil && b.Service != nil {
		out = append(out, ingressRoute{"default backend", b.Service})
	}
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		host := r.Host
		if host == "" {
			host = "*"
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service != nil {
				out = append(out, ingressRoute{host + p.Path, p.Backend.Service})
			}
		}
	}
	return out
}

// ingressFindings checks each Ingress's backends against the Services in its namespace.
func ingressFindings(ix *index) []Finding {
	if !ix.read("services") {
		return nil
	}
	services := map[nsName]kube.Service{}
	for _, s := range ix.s.Services {
		services[nsName{s.Metadata.Namespace, s.Metadata.Name}] = s
	}
	var out []Finding
	for _, ing := range ix.s.Ingresses {
		ns := ing.Metadata.Namespace
		missing := map[string][]string{} // Service -> routes
		var badPorts []string
		var portEv []Evidence
		for _, r := range ingressRoutes(ing) {
			svc, ok := services[nsName{ns, r.backend.Name}]
			if !ok {
				missing[r.backend.Name] = append(missing[r.backend.Name], r.where)
				continue
			}
			if want, have, ok := servicePortMatches(svc, r.backend); !ok {
				badPorts = append(badPorts, fmt.Sprintf("port %s of Service %s (for %s), which has %s", want, svc.Metadata.Name, r.where, have))
				portEv = append(portEv, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s has %s", svc.Metadata.Name, have),
					Command: cmdGet("service", ns, svc.Metadata.Name, "{.spec.ports}")})
			}
		}
		if len(badPorts) > 0 {
			out = append(out, Finding{Rule: "KD166", Title: "Ingress sends traffic to a port the Service does not have", Severity: Critical, Object: ing.Ref(),
				Cause: fmt.Sprintf("Ingress %s sends traffic to %s, so the controller has no endpoints for it and answers with an error (usually 503)",
					ing.Metadata.Name, strings.Join(badPorts, "; ")),
				Evidence: append([]Evidence{{Object: ing.Ref(), What: "Ingress backends", Command: cmdGet("ingress", ns, ing.Metadata.Name, "{.spec}")}}, portEv...),
				Fix:      "Set the Ingress backend's port to a port the Service exposes (its port number, or its port name), not the container's targetPort."})
		}
		if len(missing) == 0 {
			continue
		}
		names := sortedKeys(missing)
		var parts []string
		var ev []Evidence
		for _, n := range names {
			parts = append(parts, fmt.Sprintf("%s (for %s)", n, strings.Join(missing[n], ", ")))
			ev = append(ev, Evidence{Object: kube.Ref{Kind: "Service", Namespace: ns, Name: n},
				What: fmt.Sprintf("there is no Service %s in namespace %s", n, ns), Command: cmdGet("service", ns, n, "")})
		}
		sort.Strings(parts)
		ev = append([]Evidence{{Object: ing.Ref(), What: "Ingress backends", Command: cmdGet("ingress", ns, ing.Metadata.Name, "{.spec}")}}, ev...)
		out = append(out, Finding{Rule: "KD165", Title: "Ingress sends traffic to a Service that does not exist", Severity: Critical, Object: ing.Ref(),
			Cause:    fmt.Sprintf("Ingress %s sends traffic to Service %s, which does not exist in namespace %s, so the controller answers those requests with an error (usually 503)", ing.Metadata.Name, strings.Join(parts, " and "), ns),
			Evidence: ev, Fix: "Correct the backend Service name in the Ingress, or create the Service."})
	}
	return out
}

// servicePortMatches reports whether an Ingress backend's port is one the Service exposes, and what it asks for and
// what the Service has when it is not.
func servicePortMatches(svc kube.Service, b *kube.IngressServiceBackend) (string, string, bool) {
	var have []string
	for _, sp := range svc.Spec.Ports {
		if (b.Port.Name != "" && sp.Name == b.Port.Name) || (b.Port.Name == "" && sp.Port == b.Port.Number) {
			return "", "", true
		}
		desc := strconv.Itoa(int(sp.Port))
		if sp.Name != "" {
			desc = sp.Name + " (" + desc + ")"
		}
		have = append(have, desc)
	}
	want := strconv.Itoa(int(b.Port.Number))
	if b.Port.Name != "" {
		want = strconv.Quote(b.Port.Name)
	}
	return want, "ports " + strings.Join(have, ", "), false
}
