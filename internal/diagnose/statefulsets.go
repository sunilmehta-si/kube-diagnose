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

func serviceByName(ix *index, ns, name string) kube.Service {
	for _, s := range ix.s.Services {
		if s.Metadata.Namespace == ns && s.Metadata.Name == name {
			return s
		}
	}
	return kube.Service{}
}
