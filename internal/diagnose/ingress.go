package diagnose

import (
	"fmt"
	"slices"
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
	out := ingressConflicts(ix)
	for _, ing := range ix.s.Ingresses {
		if f := ingressClassMissing(ix, ing); f != nil {
			out = append(out, *f)
		}
		if f := ingressPathPattern(ing); f != nil {
			out = append(out, *f)
		}
		if f := ingressTLSSecret(ix, ing); f != nil {
			out = append(out, *f)
		} else if f := ingressHostWithoutTLS(ing); f != nil {
			out = append(out, *f)
		}
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

// ingressClassMissing finds an Ingress that no controller will serve: its ingressClassName names a class the
// cluster does not have, or it names none and no class is marked default. The legacy kubernetes.io/ingress.class
// annotation is still honoured by some controllers, so an Ingress that carries it is left alone.
func ingressClassMissing(ix *index, ing kube.Ingress) *Finding {
	if !ix.read("ingressclasses.networking.k8s.io") || ing.Metadata.Annotations["kubernetes.io/ingress.class"] != "" {
		return nil
	}
	var names []string
	def := ""
	for _, c := range ix.s.IngressClasses {
		n := c.Metadata.Name
		if c.IsDefault() {
			def = n
			n += " (default)"
		}
		names = append(names, n)
	}
	have := "the cluster has no IngressClasses"
	if len(names) > 0 {
		sort.Strings(names)
		have = "the cluster has " + strings.Join(names, ", ")
	}
	var cause string
	switch name := ing.Spec.IngressClassName; {
	case name != nil && *name != "":
		for _, c := range ix.s.IngressClasses {
			if c.Metadata.Name == *name {
				return nil
			}
		}
		cause = fmt.Sprintf("Ingress %s asks for IngressClass %s, which does not exist (%s), so no controller serves it", ing.Metadata.Name, *name, have)
	case def == "":
		cause = fmt.Sprintf("Ingress %s names no IngressClass and none is marked default (%s), so no controller serves it", ing.Metadata.Name, have)
	default:
		return nil
	}
	return &Finding{Rule: "KD167", Title: "Ingress has no controller", Severity: Critical, Object: ing.Ref(), Cause: cause,
		Evidence: []Evidence{
			{Object: ing.Ref(), What: "Ingress class", Command: cmdGet("ingress", ing.Metadata.Namespace, ing.Metadata.Name, "{.spec.ingressClassName}")},
			{Object: kube.Ref{Kind: "IngressClass", Name: "*"}, What: have, Command: "kubectl get ingressclasses"}},
		Fix: "Set ingressClassName to an installed class, or install the ingress controller the class belongs to (and mark one class default if Ingresses omit it)."}
}

// ingressTLSSecret finds an Ingress whose TLS Secret does not exist or holds no certificate and key. The controller
// then serves its own default certificate for those hosts, and clients that check certificates refuse it.
func ingressTLSSecret(ix *index, ing kube.Ingress) *Finding {
	if !ix.read("secrets") {
		return nil
	}
	ns := ing.Metadata.Namespace
	for _, t := range ing.Spec.TLS {
		if t.SecretName == "" {
			continue
		}
		hosts := "its hosts"
		if len(t.Hosts) > 0 {
			hosts = strings.Join(t.Hosts, ", ")
		}
		ref := kube.Ref{Kind: "Secret", Namespace: ns, Name: t.SecretName}
		ev := []Evidence{{Object: ing.Ref(), What: fmt.Sprintf("Ingress %s serves TLS for %s from Secret %s", ing.Metadata.Name, hosts, t.SecretName),
			Command: cmdGet("ingress", ns, ing.Metadata.Name, "{.spec.tls}")}}
		sec, ok := ix.secrets[nsName{ns, t.SecretName}]
		var cause, fix string
		switch {
		case !ok:
			ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("there is no Secret %s in namespace %s", t.SecretName, ns), Command: cmdGet("secret", ns, t.SecretName, "")})
			cause = fmt.Sprintf("Ingress %s serves TLS for %s from Secret %s, which does not exist in namespace %s, so the controller serves its default certificate and clients reject it",
				ing.Metadata.Name, hosts, t.SecretName, ns)
			fix = fmt.Sprintf("Create the TLS Secret %s in namespace %s (kubectl create secret tls, or a cert-manager Certificate), or correct secretName.", t.SecretName, ns)
		case !sec.Has("tls.crt") || !sec.Has("tls.key"):
			ev = append(ev, Evidence{Object: ref, What: fmt.Sprintf("Secret %s has type %s and keys %s", t.SecretName, sec.Type, strings.Join(sec.Keys, ", ")),
				Command: cmdGet("secret", ns, t.SecretName, "{.type}")})
			cause = fmt.Sprintf("Ingress %s serves TLS for %s from Secret %s, which has no tls.crt and tls.key, so the controller serves its default certificate and clients reject it",
				ing.Metadata.Name, hosts, t.SecretName)
			fix = fmt.Sprintf("Recreate %s with kubectl create secret tls (type kubernetes.io/tls, keys tls.crt and tls.key).", t.SecretName)
		default:
			continue
		}
		return &Finding{Rule: "KD169", Title: "Ingress TLS Secret is missing or has no certificate", Severity: Critical, Object: ing.Ref(),
			Cause: cause, Evidence: ev, Fix: fix}
	}
	return nil
}

// ingressClass is the IngressClass that serves an Ingress: its ingressClassName, the legacy annotation, or the
// cluster's default class.
// tlsCovers reports whether a TLS host entry covers a rule's host: the same name, or a wildcard (*.example.com) for
// one label in front of its domain.
func tlsCovers(tlsHost, host string) bool {
	tlsHost, host = strings.ToLower(tlsHost), strings.ToLower(host)
	if tlsHost == host {
		return true
	}
	if rest, ok := strings.CutPrefix(tlsHost, "*."); ok {
		label, domain, found := strings.Cut(host, ".")
		return found && label != "" && domain == rest
	}
	return false
}

// ingressHostWithoutTLS finds an Ingress that has TLS but a rule host no TLS entry covers, often a typo or a host
// added to the rules and not to tls: the controller serves HTTPS for that host with its default certificate, which
// clients reject.
func ingressHostWithoutTLS(ing kube.Ingress) *Finding {
	if len(ing.Spec.TLS) == 0 {
		return nil
	}
	var tlsHosts []string
	for _, t := range ing.Spec.TLS {
		tlsHosts = append(tlsHosts, t.Hosts...)
	}
	if len(tlsHosts) == 0 {
		return nil // a tls entry without hosts covers every host on most controllers
	}
	var uncovered []string
	for _, r := range ing.Spec.Rules {
		if r.Host == "" || slices.Contains(uncovered, r.Host) {
			continue
		}
		covered := false
		for _, h := range tlsHosts {
			if tlsCovers(h, r.Host) {
				covered = true
			}
		}
		if !covered {
			uncovered = append(uncovered, r.Host)
		}
	}
	if len(uncovered) == 0 {
		return nil
	}
	ns, name := ing.Metadata.Namespace, ing.Metadata.Name
	return &Finding{Rule: "KD272", Title: "Ingress serves a host that its TLS does not cover", Severity: Warning, Object: ing.Ref(),
		Cause: fmt.Sprintf("Ingress %s has TLS for %s, but its rules also serve %s, which no TLS entry covers, so HTTPS requests to %s get the controller's default certificate, which clients reject",
			name, strings.Join(tlsHosts, ", "), strings.Join(uncovered, ", "), strings.Join(uncovered, ", ")),
		Evidence: []Evidence{{Object: ing.Ref(), What: "the Ingress's rule hosts and TLS hosts",
			Command: cmdGet("ingress", ns, name, `{.spec.rules[*].host}{"\n"}{.spec.tls}`)}},
		Fix: fmt.Sprintf("Add %s to the hosts of a tls entry whose Secret's certificate covers it (or correct the rule's host if it is a typo).", strings.Join(uncovered, ", "))}
}

func ingressClass(ix *index, ing kube.Ingress) string {
	if ing.Spec.IngressClassName != nil {
		return *ing.Spec.IngressClassName
	}
	if c := ing.Metadata.Annotations["kubernetes.io/ingress.class"]; c != "" {
		return c
	}
	for _, c := range ix.s.IngressClasses {
		if c.IsDefault() {
			return c.Metadata.Name
		}
	}
	return ""
}

func backendString(b *kube.IngressServiceBackend) string {
	if b.Port.Name != "" {
		return b.Name + ":" + b.Port.Name
	}
	return b.Name + ":" + strconv.Itoa(int(b.Port.Number))
}

// ingressConflicts finds Ingresses of one class that send the same host and path to different Services. Only one
// of them gets the traffic, which one being up to the controller; ingress-nginx keeps the oldest rule. The finding
// is on the newer Ingress, the one whose route is likely ignored.
func ingressConflicts(ix *index) []Finding {
	ings := append([]kube.Ingress(nil), ix.s.Ingresses...)
	sort.SliceStable(ings, func(i, j int) bool {
		a, b := ings[i].Metadata.CreationTimestamp, ings[j].Metadata.CreationTimestamp
		if !a.Equal(b) {
			return a.Before(b)
		}
		return ings[i].Metadata.Name < ings[j].Metadata.Name
	})
	type claim struct {
		ing     kube.Ingress
		backend *kube.IngressServiceBackend
	}
	claims := map[string]claim{}
	var out []Finding
	for _, ing := range ings {
		class := ingressClass(ix, ing)
		var clashes []string
		var ev []Evidence
		for _, r := range ing.Spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Backend.Service == nil {
					continue
				}
				pathType := p.PathType
				if pathType == "" {
					pathType = "ImplementationSpecific"
				}
				host := r.Host
				if host == "" {
					host = "*"
				}
				key := strings.Join([]string{ing.Metadata.Namespace, class, host, p.Path, pathType}, "|")
				c, ok := claims[key]
				if !ok {
					claims[key] = claim{ing, p.Backend.Service}
					continue
				}
				if c.ing.Metadata.Name == ing.Metadata.Name || backendString(c.backend) == backendString(p.Backend.Service) {
					continue
				}
				earlier := ""
				if c.ing.Metadata.CreationTimestamp.Before(ing.Metadata.CreationTimestamp) {
					earlier = ", created earlier,"
				}
				clashes = append(clashes, fmt.Sprintf("%s%s to Service %s, which Ingress %s%s sends to Service %s",
					host, p.Path, backendString(p.Backend.Service), c.ing.Metadata.Name, earlier, backendString(c.backend)))
				ev = append(ev, Evidence{Object: c.ing.Ref(), What: fmt.Sprintf("Ingress %s routes %s%s to Service %s", c.ing.Metadata.Name, host, p.Path, backendString(c.backend)),
					Command: cmdGet("ingress", c.ing.Metadata.Namespace, c.ing.Metadata.Name, "{.metadata.creationTimestamp}{\" \"}{.spec.rules}")})
			}
		}
		if len(clashes) == 0 {
			continue
		}
		ns, name := ing.Metadata.Namespace, ing.Metadata.Name
		ev = append([]Evidence{{Object: ing.Ref(), What: fmt.Sprintf("Ingress %s's rules", name),
			Command: cmdGet("ingress", ns, name, "{.metadata.creationTimestamp}{\" \"}{.spec.rules}")}}, ev...)
		out = append(out, Finding{Rule: "KD263", Title: "Ingresses send the same host and path to different Services", Severity: Warning, Object: ing.Ref(),
			Cause:    fmt.Sprintf("Ingress %s sends %s; only one of them gets the traffic, which one being up to the controller (ingress-nginx keeps the oldest rule)", name, strings.Join(clashes, "; and ")),
			Evidence: ev,
			Fix:      "Give each host and path one Ingress: delete the stale rule, or change the host or path of one of them. For a canary, use the controller's canary feature rather than a second Ingress."})
	}
	return out
}

// ingressPathPattern finds an Ingress path written as a pattern, /api/* or /api/.*, with pathType Prefix or Exact,
// which every controller compares as text: only a request for that literal path matches. ImplementationSpecific is
// left alone, as a controller may read it as a regular expression (ingress-nginx does, with use-regex).
func ingressPathPattern(ing kube.Ingress) *Finding {
	for _, r := range ing.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			if p.PathType != "Prefix" && p.PathType != "Exact" || !rePathPattern.MatchString(p.Path) {
				continue
			}
			host := r.Host
			if host == "" {
				host = "any host"
			}
			fix := "Use the path's literal prefix with pathType Prefix (/api matches /api and everything under it)"
			if base := strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(p.Path, ".*"), "*"), "/"); base != "" && !rePathPattern.MatchString(base) {
				fix = fmt.Sprintf("Use path %s with pathType Prefix, which matches it and everything under it", base)
			}
			fix += ", or pathType ImplementationSpecific with your controller's regular-expression support."
			return &Finding{Rule: "KD278", Title: "Ingress path is a pattern that its pathType compares as text", Severity: Warning, Object: ing.Ref(),
				Cause: fmt.Sprintf("Ingress %s routes path %s on %s with pathType %s, which compares paths as text, not as a pattern: only a request for exactly %s matches, so the requests meant for it get a 404 or go to another path",
					ing.Metadata.Name, p.Path, host, p.PathType, p.Path),
				Evidence: []Evidence{{Object: ing.Ref(), What: "the Ingress's paths and their pathType",
					Command: cmdGet("ingress", ing.Metadata.Namespace, ing.Metadata.Name, `{range .spec.rules[*].http.paths[*]}{.path}{" "}{.pathType}{"\n"}{end}`)}},
				Fix: fix}
		}
	}
	return nil
}
