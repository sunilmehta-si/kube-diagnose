package diagnose

import (
	"fmt"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// statefulSetFindings reports StatefulSets whose governing Service does not exist or is not headless. The pods run,
// but their stable DNS names (web-0.web.shop.svc) do not resolve, so peers that find each other by name, as
// databases and queues do, cannot.
func statefulSetFindings(ix *index) []Finding {
	var out []Finding
	for _, w := range ix.s.Workloads {
		if w.Kind != "StatefulSet" || w.Spec.ServiceName == "" {
			continue
		}
		ns, name, svcName := w.Metadata.Namespace, w.Metadata.Name, w.Spec.ServiceName
		ev := []Evidence{{Object: w.Ref(), What: fmt.Sprintf("StatefulSet %s names Service %s as its governing Service", name, svcName),
			Command: cmdGet("statefulset", ns, name, "{.spec.serviceName}")}}
		svcRef := kube.Ref{Kind: "Service", Namespace: ns, Name: svcName}
		exists, known := ix.serviceExists(ns, svcName)
		if !known {
			continue
		}
		pod := name + "-0." + svcName + "." + ns + ".svc"
		var cause, fix string
		if !exists {
			ev = append(ev, Evidence{Object: svcRef, What: fmt.Sprintf("there is no Service %s in namespace %s", svcName, ns), Command: cmdGet("service", ns, svcName, "")})
			cause = fmt.Sprintf("StatefulSet %s's governing Service %s does not exist, so its pods have no DNS names (%s does not resolve)", name, svcName, pod)
			fix = fmt.Sprintf("Create a headless Service %s (clusterIP: None) that selects the StatefulSet's pods, or set serviceName to the one that exists.", svcName)
		} else {
			svc := serviceByName(ix, ns, svcName)
			if svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == "" {
				if f := headlessSelectsOthers(w, svc, pod, ev); f != nil {
					out = append(out, *f)
				}
				continue
			}
			ev = append(ev, Evidence{Object: svcRef, What: fmt.Sprintf("Service %s has clusterIP %s", svcName, svc.Spec.ClusterIP), Command: cmdGet("service", ns, svcName, "{.spec.clusterIP}")})
			cause = fmt.Sprintf("StatefulSet %s's governing Service %s is not headless (it has clusterIP %s), so its pods get no DNS names of their own (%s does not resolve)", name, svcName, svc.Spec.ClusterIP, pod)
			fix = fmt.Sprintf("Make %s headless: clusterIP cannot be changed in place, so recreate it with clusterIP: None (and keep a separate Service for clients if they need one IP).", svcName)
		}
		out = append(out, Finding{Rule: "KD182", Title: "StatefulSet's governing Service is missing or not headless", Severity: Warning, Object: w.Ref(),
			Cause: cause, Evidence: ev, Fix: fix})
	}
	return out
}

// headlessSelectsOthers finds a StatefulSet whose governing Service is headless but selects other pods than the
// StatefulSet's: the DNS records of a headless Service come from the pods it selects, so web-0.web.shop.svc exists
// only for a pod the selector matches, and the StatefulSet's pods get none.
func headlessSelectsOthers(w kube.Workload, svc kube.Service, pod string, ev []Evidence) *Finding {
	labels := w.Spec.Template.Metadata.Labels
	if len(svc.Spec.Selector) == 0 || len(labels) == 0 || kube.MatchesMap(svc.Spec.Selector, labels) {
		return nil
	}
	ns, name, sel, have := w.Metadata.Namespace, w.Metadata.Name, kube.FormatMap(svc.Spec.Selector), kube.FormatMap(labels)
	ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s is headless and selects pods with %s", svc.Metadata.Name, sel),
		Command: cmdGet("service", ns, svc.Metadata.Name, `{.spec.clusterIP}{" "}{.spec.selector}`)},
		Evidence{Object: w.Ref(), What: fmt.Sprintf("StatefulSet %s's pods carry %s", name, have),
			Command: cmdGet("statefulset", ns, name, "{.spec.template.metadata.labels}")})
	return &Finding{Rule: "KD182", Title: "StatefulSet's governing Service is missing or not headless", Severity: Warning, Object: w.Ref(),
		Cause:    fmt.Sprintf("StatefulSet %s's governing Service %s is headless, but it selects pods with %s and the StatefulSet's pods carry %s; a headless Service's DNS records come from the pods it selects, so the StatefulSet's pods have no DNS names (%s does not resolve)", name, svc.Metadata.Name, sel, have, pod),
		Evidence: ev,
		Fix:      fmt.Sprintf("Change Service %s's selector to the StatefulSet's pod labels (%s), or give it its own headless Service.", svc.Metadata.Name, have)}
}

func serviceByName(ix *index, ns, name string) kube.Service {
	for _, s := range ix.s.Services {
		if s.Metadata.Namespace == ns && s.Metadata.Name == name {
			return s
		}
	}
	return kube.Service{}
}
