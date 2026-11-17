package diagnose

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// serviceFindings checks each Service that selects pods: that its selector matches something, that its target
// ports exist on the pods it selects, that it has ready endpoints, and that a NetworkPolicy does not shut it off.
// It returns root-cause findings, and for Services left without endpoints by a pod problem, the pods they select so
// the engine can list the Service under that problem.
func serviceFindings(ix *index) ([]Finding, map[kube.Ref][]kube.Ref) {
	var out []Finding
	blocked := map[kube.Ref][]kube.Ref{} // Service -> its pods that are not ready
	for _, svc := range ix.s.Services {
		if f := loadBalancerPending(ix, svc); f != nil {
			out = append(out, *f)
		}
		if f := externalNameIP(svc); f != nil {
			out = append(out, *f)
		}
		if len(svc.Spec.Selector) == 0 && svc.Spec.Type != "ExternalName" {
			if f := noSelectorNoEndpoints(ix, svc); f != nil {
				out = append(out, *f)
			}
		}
		if len(svc.Spec.Selector) == 0 || svc.Spec.Type == "ExternalName" {
			continue
		}
		var matching, ready []kube.Pod
		for _, p := range ix.s.Pods {
			if p.Metadata.Namespace != svc.Metadata.Namespace || p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" {
				continue
			}
			if kube.MatchesMap(svc.Spec.Selector, p.Metadata.Labels) {
				matching = append(matching, p)
				if p.Ready() {
					ready = append(ready, p)
				}
			}
		}
		if len(matching) == 0 {
			if f := selectorMatchesNothing(ix, svc); f != nil {
				out = append(out, *f)
			}
			continue
		}
		if f := missingNamedPort(ix, svc, matching, ready); f != nil {
			out = append(out, *f)
			continue
		}
		if f := undeclaredTargetPort(svc, matching); f != nil {
			out = append(out, *f)
		}
		if len(ready) == 0 {
			for _, p := range matching {
				blocked[svc.Ref()] = append(blocked[svc.Ref()], p.Ref())
			}
			continue
		}
		if f := denyAllIngress(ix, svc, ready); f != nil {
			out = append(out, *f)
		}
	}
	return out, blocked
}

func selectorMatchesNothing(ix *index, svc kube.Service) *Finding {
	ns := svc.Metadata.Namespace
	// A workload whose template matches is scaled to zero or failing to create pods: not a selector problem. Scaling
	// to zero is often deliberate (KEDA does it); it is worth saying only when an Ingress still sends traffic here.
	var zero []kube.Workload
	for _, w := range ix.s.Workloads {
		if w.Metadata.Namespace == ns && w.Kind != "ReplicaSet" && kube.MatchesMap(svc.Spec.Selector, w.Spec.Template.Metadata.Labels) {
			if w.Kind == "DaemonSet" || w.Desired() != 0 {
				return nil
			}
			zero = append(zero, w)
		}
	}
	if len(zero) > 0 {
		return scaledToZero(ix, svc, zero[0])
	}
	sel := kube.FormatMap(svc.Spec.Selector)
	ev := []Evidence{{Object: svc.Ref(), What: "Service selects pods with " + sel,
		Command: cmdGet("service", ns, svc.Metadata.Name, "{.spec.selector}")}}
	cause := fmt.Sprintf("Service %s selects pods with %s, and no pod in namespace %s has those labels", svc.Metadata.Name, sel, ns)
	fix := "Change the Service's selector to the labels its pods carry, or the pods' labels to match the selector."
	if near := nearestLabels(ix, ns, svc.Spec.Selector); near != "" {
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "Pod", Namespace: ns, Name: "*"},
			What: "the closest labels on pods in the namespace are " + near, Command: "kubectl get pods -n " + ns + " --show-labels"})
		cause += fmt.Sprintf(" (the closest are %s)", near)
		fix = fmt.Sprintf("Change the Service's selector from %s to match the pods (%s), or relabel the pods.", sel, near)
	}
	return &Finding{Rule: "KD160", Title: "Service selects no pods", Severity: Critical, Object: svc.Ref(), Cause: cause,
		Evidence: ev, Fix: fix}
}

// lbPendingAfter is how long a LoadBalancer Service may wait for its address before it is reported.
const lbPendingAfter = 2 * time.Minute

// loadBalancerPending finds a LoadBalancer Service that has no external address minutes after it was created: no
// load balancer controller serves it, or the one there fails.
func loadBalancerPending(ix *index, svc kube.Service) *Finding {
	if svc.Spec.Type != "LoadBalancer" || len(svc.Status.LoadBalancer.Ingress) > 0 || svc.Metadata.CreationTimestamp.IsZero() {
		return nil
	}
	age := ix.s.CollectedAt.Sub(svc.Metadata.CreationTimestamp)
	if age < lbPendingAfter {
		return nil
	}
	ns, name := svc.Metadata.Namespace, svc.Metadata.Name
	ev := []Evidence{{Object: svc.Ref(), What: fmt.Sprintf("Service %s has type LoadBalancer and no external address after %s", name, age.Round(time.Minute)),
		Command: cmdGet("service", ns, name, "{.spec.type}{\" \"}{.status.loadBalancer}")}}
	cause := fmt.Sprintf("LoadBalancer Service %s has had no external address for %s: nothing in the cluster provisions load balancers (a cloud controller manager, MetalLB, cloud-provider-kind), or the one there ignores this Service", name, age.Round(time.Minute))
	fix := "Install a load balancer implementation for this cluster, or expose the Service another way (an Ingress or Gateway, or type NodePort)."
	for _, e := range ix.eventsFor(svc.Ref(), "SyncLoadBalancerFailed") {
		ev = append(ev, eventEvidence(svc.Ref(), e))
		cause = fmt.Sprintf("LoadBalancer Service %s has had no external address for %s: the load balancer controller fails to create one: %s", name, age.Round(time.Minute), clip(e.Message, 200))
		fix = "Fix what the load balancer controller reports (quota, subnet, annotations, permissions); it retries on its own."
		break
	}
	return &Finding{Rule: "KD168", Title: "LoadBalancer Service has no external address", Severity: Warning, Object: svc.Ref(),
		Cause: cause, Evidence: ev, Fix: fix}
}

// scaledToZero reports a Service whose workload is scaled to zero while an Ingress still sends it traffic.
func scaledToZero(ix *index, svc kube.Service, w kube.Workload) *Finding {
	ns := svc.Metadata.Namespace
	for _, ing := range ix.s.Ingresses {
		if ing.Metadata.Namespace != ns || !routesTo(ing, svc.Metadata.Name) {
			continue
		}
		return &Finding{Rule: "KD160", Title: "Service selects no pods", Severity: Warning, Object: svc.Ref(),
			Cause: fmt.Sprintf("Ingress %s sends traffic to Service %s, which has no pods because %s %s is scaled to 0 replicas", ing.Metadata.Name, svc.Metadata.Name, w.Kind, w.Metadata.Name),
			Evidence: []Evidence{{Object: w.Ref(), What: fmt.Sprintf("%s %s has replicas 0", w.Kind, w.Metadata.Name),
				Command: cmdGet(strings.ToLower(w.Kind), ns, w.Metadata.Name, "{.spec.replicas}")},
				{Object: ing.Ref(), What: fmt.Sprintf("Ingress %s routes to Service %s", ing.Metadata.Name, svc.Metadata.Name), Command: cmdGet("ingress", ns, ing.Metadata.Name, "{.spec}")}},
			Fix:     fmt.Sprintf("Scale %s %s up (kubectl scale --replicas), or check what scaled it down (an HPA, KEDA or a deploy pipeline); if it is retired, remove the Ingress route.", w.Kind, w.Metadata.Name),
			Affects: []kube.Ref{ing.Ref()}}
	}
	return nil
}

func routesTo(ing kube.Ingress, svc string) bool {
	for _, r := range ingressRoutes(ing) {
		if r.backend.Name == svc {
			return true
		}
	}
	return false
}

// nearestLabels finds the pod label set that shares the most selector keys with the selector, printed as the
// selector's keys with the pod's values.
func nearestLabels(ix *index, ns string, sel map[string]string) string {
	best, bestScore := "", 0
	seen := map[string]bool{}
	for _, p := range ix.s.Pods {
		if p.Metadata.Namespace != ns {
			continue
		}
		score := 0
		vals := map[string]string{}
		for k := range sel {
			if v, ok := p.Metadata.Labels[k]; ok {
				score++
				vals[k] = v
			}
		}
		s := kube.FormatMap(vals)
		if score > bestScore && !seen[s] {
			best, bestScore = s, score
		}
		seen[s] = true
	}
	return best
}

// missingNamedPort finds a Service whose targetPort names a port no selected container declares. The endpoint
// controller leaves such pods out, so the Service has no endpoints although its pods are ready.
func missingNamedPort(ix *index, svc kube.Service, matching, ready []kube.Pod) *Finding {
	for _, sp := range svc.Spec.Ports {
		if !sp.TargetPort.IsName {
			continue
		}
		declared := map[string]bool{}
		found := false
		for _, p := range matching {
			for _, c := range p.Spec.Containers {
				for _, cp := range c.Ports {
					if cp.Name != "" {
						declared[fmt.Sprintf("%s (%d)", cp.Name, cp.ContainerPort)] = true
					}
					if cp.Name == sp.TargetPort.Str {
						found = true
					}
				}
			}
		}
		if found {
			continue
		}
		names := sortedKeys(declared)
		have := "no named ports"
		if len(names) > 0 {
			have = "named ports " + strings.Join(names, ", ")
		}
		ns := svc.Metadata.Namespace
		ev := []Evidence{
			{Object: svc.Ref(), What: fmt.Sprintf("Service port %d targets the named port %q", sp.Port, sp.TargetPort.Str),
				Command: cmdGet("service", ns, svc.Metadata.Name, "{.spec.ports}")},
			{Object: matching[0].Ref(), What: fmt.Sprintf("the selected pods declare %s", have),
				Command: cmdGet("pod", ns, matching[0].Metadata.Name, "{.spec.containers[*].ports}")},
		}
		if ix.read("endpointslices.discovery.k8s.io") {
			ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service has %d ready endpoints although %d of its pods are ready",
				readyEndpoints(ix, svc), len(ready)), Command: "kubectl get endpointslices -n " + ns + " -l kubernetes.io/service-name=" + svc.Metadata.Name})
		}
		return &Finding{Rule: "KD161", Title: "Service targets a port the pods do not have", Severity: Critical, Object: svc.Ref(),
			Cause: fmt.Sprintf("Service %s sends traffic to the named port %q, which no selected pod declares (they have %s), so it has no endpoints",
				svc.Metadata.Name, sp.TargetPort.Str, have),
			Evidence: ev, Fix: fmt.Sprintf("Set the Service's targetPort to a port the pods declare, or name the container port %q.", sp.TargetPort.Str)}
	}
	return nil
}

// undeclaredTargetPort finds a numeric targetPort that none of the selected containers declares while they declare
// others. Declaring ports is optional, so this can be intended, but it is how a wrong targetPort looks: the Service
// has endpoints and every connection fails.
func undeclaredTargetPort(svc kube.Service, matching []kube.Pod) *Finding {
	for _, sp := range svc.Spec.Ports {
		if sp.TargetPort.IsName {
			continue
		}
		target := sp.TargetPort.Int
		if target == 0 {
			target = sp.Port
		}
		declared := map[int32]bool{}
		for _, p := range matching {
			for _, c := range p.Spec.Containers {
				for _, cp := range c.Ports {
					declared[cp.ContainerPort] = true
				}
			}
		}
		if len(declared) == 0 || declared[target] {
			continue
		}
		var ports []string
		for p := range declared {
			ports = append(ports, strconv.Itoa(int(p)))
		}
		sort.Strings(ports)
		ns := svc.Metadata.Namespace
		return &Finding{Rule: "KD164", Title: "Service targets a port the pods do not declare", Severity: Warning, Object: svc.Ref(),
			Cause: fmt.Sprintf("Service %s sends port %d to port %d on its pods, but they declare only port %s; if nothing listens on %d, every connection fails",
				svc.Metadata.Name, sp.Port, target, strings.Join(ports, ", "), target),
			Evidence: []Evidence{
				{Object: svc.Ref(), What: fmt.Sprintf("Service port %d has targetPort %d", sp.Port, target), Command: cmdGet("service", ns, svc.Metadata.Name, "{.spec.ports}")},
				{Object: matching[0].Ref(), What: "the selected pods declare port " + strings.Join(ports, ", "),
					Command: cmdGet("pod", ns, matching[0].Metadata.Name, "{.spec.containers[*].ports}")},
			},
			Fix: fmt.Sprintf("Set targetPort to the port the app listens on (the pods declare %s), or declare the port in the pod spec if %d is right.",
				strings.Join(ports, ", "), target)}
	}
	return nil
}

func readyEndpoints(ix *index, svc kube.Service) int {
	n := 0
	for _, sl := range ix.slices[nsName{svc.Metadata.Namespace, svc.Metadata.Name}] {
		for _, e := range sl.Endpoints {
			if e.Conditions.Ready == nil || *e.Conditions.Ready {
				n += len(e.Addresses)
			}
		}
	}
	return n
}

// denyAllIngress finds a Service whose every ready pod is selected by ingress NetworkPolicies that allow nothing.
func denyAllIngress(ix *index, svc kube.Service, ready []kube.Pod) *Finding {
	ns := svc.Metadata.Namespace
	var policy *kube.NetworkPolicy
	for _, p := range ready {
		selected, allows := false, false
		for i, np := range ix.s.NetworkPolicies {
			if np.Metadata.Namespace != ns || !np.AppliesToIngress() || !np.Spec.PodSelector.Matches(p.Metadata.Labels) {
				continue
			}
			selected = true
			if len(np.Spec.Ingress) > 0 {
				allows = true
			} else if policy == nil {
				policy = &ix.s.NetworkPolicies[i]
			}
		}
		if !selected || allows {
			return nil
		}
	}
	if policy == nil {
		return nil
	}
	ref := kube.Ref{Kind: "NetworkPolicy", Namespace: ns, Name: policy.Metadata.Name}
	return &Finding{Rule: "KD163", Title: "NetworkPolicy blocks all traffic to a Service", Severity: Warning, Object: ref,
		Cause: fmt.Sprintf("NetworkPolicy %s selects every pod behind Service %s and allows no ingress, so nothing can connect to it",
			policy.Metadata.Name, svc.Metadata.Name),
		Evidence: []Evidence{
			{Object: ref, What: fmt.Sprintf("NetworkPolicy selects pods with %s and has no ingress rules", selectorString(policy.Spec.PodSelector)),
				Command: cmdGet("networkpolicy", ns, policy.Metadata.Name, "{.spec}")},
			{Object: svc.Ref(), What: fmt.Sprintf("Service %s has %d ready pods, all selected by ingress policies with no rules", svc.Metadata.Name, len(ready)),
				Command: "kubectl get networkpolicies -n " + ns},
		},
		Fix:     fmt.Sprintf("Add an ingress rule that allows the Service's clients (by namespace or pod labels and port) to a NetworkPolicy that selects these pods, if %s is not meant to be closed.", svc.Metadata.Name),
		Affects: []kube.Ref{svc.Ref()}}
}

func selectorString(s kube.LabelSelector) string {
	if len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 {
		return "any labels (every pod in the namespace)"
	}
	out := kube.FormatMap(s.MatchLabels)
	for _, e := range s.MatchExpressions {
		if out != "" {
			out += ","
		}
		out += fmt.Sprintf("%s %s (%s)", e.Key, e.Operator, strings.Join(e.Values, ","))
	}
	return out
}

// externalNameIP finds an ExternalName Service whose externalName is an IP address. Cluster DNS answers a lookup of
// such a Service with a CNAME to the address written as a name, which resolves to nothing.
func externalNameIP(svc kube.Service) *Finding {
	if svc.Spec.Type != "ExternalName" || net.ParseIP(svc.Spec.ExternalName) == nil {
		return nil
	}
	ns, name, ip := svc.Metadata.Namespace, svc.Metadata.Name, svc.Spec.ExternalName
	return &Finding{Rule: "KD260", Title: "ExternalName Service names an IP address", Severity: Warning, Object: svc.Ref(),
		Cause: fmt.Sprintf("Service %s is of type ExternalName with externalName %s, an IP address: cluster DNS answers %s.%s.svc with a CNAME to the name %q, which does not resolve, so clients of the Service get no address", name, ip, name, ns, ip),
		Evidence: []Evidence{{Object: svc.Ref(), What: fmt.Sprintf("Service %s has type ExternalName and externalName %s", name, ip),
			Command: cmdGet("service", ns, name, `{.spec.type}{" "}{.spec.externalName}`)}},
		Fix: fmt.Sprintf("ExternalName takes a DNS name. To send Service %s to the address %s, make it a Service without a selector and give it an EndpointSlice with that address.", name, ip)}
}

// noSelectorNoEndpoints finds a Service without a selector and without a ready address in any EndpointSlice: no
// controller fills in endpoints for such a Service, so whoever made it was meant to, and connections to it fail.
func noSelectorNoEndpoints(ix *index, svc kube.Service) *Finding {
	if !ix.read("endpointslices.discovery.k8s.io") || readyEndpoints(ix, svc) > 0 {
		return nil
	}
	ns, name := svc.Metadata.Namespace, svc.Metadata.Name
	slices := ix.slices[nsName{ns, name}]
	have := "no EndpointSlice"
	if len(slices) > 0 {
		have = fmt.Sprintf("%s with no ready address", plural(len(slices), "EndpointSlice"))
	}
	return &Finding{Rule: "KD264", Title: "Service has no selector and no endpoints", Severity: Warning, Object: svc.Ref(),
		Cause: fmt.Sprintf("Service %s has no selector, so Kubernetes keeps no endpoints for it, and it has %s: connections to it fail", name, have),
		Evidence: []Evidence{{Object: svc.Ref(), What: fmt.Sprintf("Service %s has no selector", name), Command: cmdGet("service", ns, name, "{.spec.selector}")},
			{Object: svc.Ref(), What: fmt.Sprintf("Service %s has %s", name, have), Command: "kubectl get endpointslices -n " + ns + " -l kubernetes.io/service-name=" + name}},
		Fix: fmt.Sprintf("Give Service %s a selector that matches the pods it fronts, or create an EndpointSlice labelled kubernetes.io/service-name: %s with the addresses it should send to.", name, name)}
}
