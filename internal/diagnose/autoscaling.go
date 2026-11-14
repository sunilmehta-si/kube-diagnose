package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var reMissingRequest = regexp.MustCompile(`missing request for (\S+) in container (\S+) of Pod (\S+)`)

// hpaFindings reports HorizontalPodAutoscalers that cannot do their job. A workload under such an HPA looks
// healthy; the failure is only in the HPA's conditions.
func hpaFindings(ix *index) []Finding {
	var out []Finding
	for _, h := range ix.s.HPAs {
		if f := hpaTarget(ix, h); f != nil {
			out = append(out, *f)
		} else if f := hpaMetrics(h); f != nil {
			out = append(out, *f)
		} else if f := hpaAtMax(h); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func hpaCondition(h kube.HorizontalPodAutoscaler, typ string) Evidence {
	return Evidence{Object: h.Ref(), What: typ + " condition",
		Command: cmdGet("hpa", h.Metadata.Namespace, h.Metadata.Name, fmt.Sprintf(`{.status.conditions[?(@.type=="%s")]}`, typ))}
}

// hpaMetrics finds an HPA whose ScalingActive condition is False because it cannot read the metrics it scales on.
func hpaMetrics(h kube.HorizontalPodAutoscaler) *Finding {
	c, ok := kube.FindCondition(h.Status.Conditions, "ScalingActive")
	if !ok || c.Status != "False" || !strings.HasPrefix(c.Reason, "FailedGet") {
		return nil
	}
	ev := hpaCondition(h, "ScalingActive")
	ev.What, ev.Detail = "ScalingActive is False, reason "+c.Reason, c.Message
	target := h.Spec.ScaleTargetRef.Kind + " " + h.Spec.ScaleTargetRef.Name
	f := &Finding{Rule: "KD176", Title: "HPA cannot read its metrics", Severity: Warning, Object: h.Ref(), Evidence: []Evidence{ev},
		Affects: []kube.Ref{{Kind: h.Spec.ScaleTargetRef.Kind, Namespace: h.Metadata.Namespace, Name: h.Spec.ScaleTargetRef.Name}}}
	switch m := reMissingRequest.FindStringSubmatch(c.Message); {
	case m != nil:
		f.Cause = fmt.Sprintf("HPA %s scales %s on %s utilization, but container %s sets no %s request, so utilization cannot be computed and the HPA does not scale",
			h.Metadata.Name, target, m[1], m[2], m[1])
		f.Fix = fmt.Sprintf("Set a %s request on container %s (utilization is usage divided by the request), or scale on an absolute target (AverageValue).", m[1], m[2])
	case strings.Contains(c.Message, "metrics.k8s.io") && (strings.Contains(c.Message, "could not find the requested resource") ||
		strings.Contains(c.Message, "no metrics returned") || strings.Contains(c.Message, "unable to fetch metrics")):
		f.Cause = fmt.Sprintf("HPA %s cannot read resource metrics for %s, because the metrics API (metrics-server) is not answering, so the HPA does not scale", h.Metadata.Name, target)
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "APIService", Name: "v1beta1.metrics.k8s.io"},
			What: "the resource metrics API", Command: "kubectl get apiservices v1beta1.metrics.k8s.io"})
		f.Fix = "Install metrics-server (or the cluster's metrics adapter) and check that the v1beta1.metrics.k8s.io APIService is Available."
	default:
		f.Cause = fmt.Sprintf("HPA %s cannot read the metrics it scales %s on, so it does not scale: %s", h.Metadata.Name, target, clip(c.Message, 220))
		f.Fix = "Check that the metric the HPA names exists and that its adapter (metrics-server, prometheus-adapter, KEDA) serves it."
	}
	return f
}

// hpaAtMax finds an HPA that computes more replicas than maxReplicas allows, so the workload runs short.
func hpaAtMax(h kube.HorizontalPodAutoscaler) *Finding {
	c, ok := kube.FindCondition(h.Status.Conditions, "ScalingLimited")
	if !ok || c.Status != "True" || c.Reason != "TooManyReplicas" {
		return nil
	}
	ev := hpaCondition(h, "ScalingLimited")
	ev.What, ev.Detail = "ScalingLimited is True, reason TooManyReplicas", c.Message
	target := h.Spec.ScaleTargetRef.Kind + " " + h.Spec.ScaleTargetRef.Name
	return &Finding{Rule: "KD177", Title: "HPA is held at its maximum", Severity: Warning, Object: h.Ref(),
		Cause: fmt.Sprintf("HPA %s wants more replicas of %s than its maxReplicas of %d, so the workload runs at %d replicas under more load than its target",
			h.Metadata.Name, target, h.Spec.MaxReplicas, h.Status.CurrentReplicas),
		Evidence: []Evidence{ev}, Fix: "Raise maxReplicas if the cluster has room, or lower the per-replica load (a higher target, faster replicas).",
		Affects: []kube.Ref{{Kind: h.Spec.ScaleTargetRef.Kind, Namespace: h.Metadata.Namespace, Name: h.Spec.ScaleTargetRef.Name}}}
}

// hpaTarget finds an HPA whose scaleTargetRef names a workload that does not exist.
func hpaTarget(ix *index, h kube.HorizontalPodAutoscaler) *Finding {
	c, ok := kube.FindCondition(h.Status.Conditions, "AbleToScale")
	if !ok || c.Status != "False" || c.Reason != "FailedGetScale" || !strings.Contains(c.Message, "not found") {
		return nil
	}
	ref := h.Spec.ScaleTargetRef
	ev := hpaCondition(h, "AbleToScale")
	ev.What, ev.Detail = "AbleToScale is False, reason FailedGetScale", c.Message
	evs := []Evidence{ev}
	if ix.read("deployments.apps") {
		evs = append(evs, Evidence{Object: kube.Ref{Kind: ref.Kind, Namespace: h.Metadata.Namespace, Name: ref.Name},
			What:    fmt.Sprintf("there is no %s %s in namespace %s", ref.Kind, ref.Name, h.Metadata.Namespace),
			Command: cmdGet(ref.Kind, h.Metadata.Namespace, ref.Name, "")})
	}
	return &Finding{Rule: "KD178", Title: "HPA targets a workload that does not exist", Severity: Warning, Object: h.Ref(),
		Cause:    fmt.Sprintf("HPA %s scales %s %s, which does not exist in namespace %s, so it scales nothing", h.Metadata.Name, ref.Kind, ref.Name, h.Metadata.Namespace),
		Evidence: evs, Fix: "Correct scaleTargetRef to the workload's kind and name, or delete the HPA if the workload is gone."}
}
