package diagnose

import (
	"fmt"
	"sort"
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
		for _, r := range ingressRoutes(ing) {
			if _, ok := services[nsName{ns, r.backend.Name}]; !ok {
				missing[r.backend.Name] = append(missing[r.backend.Name], r.where)
			}
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
