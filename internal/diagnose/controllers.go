package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	reQuota         = regexp.MustCompile(`exceeded quota: ([^,]+), requested: ([^,]+(?:,[^,:]+)*), used: ([^,]+(?:,[^,:]+)*), limited: (.+)$`)
	reQuotaM        = regexp.MustCompile(`must specify ([^ ]+)`)
	reLimitRange    = regexp.MustCompile(`(?:maximum|minimum) (?:cpu|memory|ephemeral-storage|storage) usage per (?:Container|Pod) is [^,\]]+, but (?:limit|request) is [^,\]]+|(?:cpu|memory|ephemeral-storage) max limit to request ratio per Container is [^,\]]+, but provided ratio is [^,\]]+`)
	rePriorityClass = regexp.MustCompile(`no PriorityClass with name (\S+) was found`)
	reRuntimeClass  = regexp.MustCompile(`RuntimeClass "([^"]+)" not found`)
	reSA            = regexp.MustCompile(`serviceaccount "([^"]+)" not found`)
	reWebhk         = regexp.MustCompile(`admission webhook "([^"]+)" denied the request`)
	rePSA           = regexp.MustCompile(`violates PodSecurity "([^"]+)"`)
)

// controllerFindings reads why a controller cannot create its pods, from its FailedCreate events: quota,
// a missing ServiceAccount, PodSecurity or an admission webhook. Pods that are never created leave no pod to
// diagnose, so these are visible only on the controller.
func controllerFindings(ix *index) []Finding {
	var out []Finding
	seen := map[kube.Ref]bool{}
	check := func(ref kube.Ref, owner kube.Ref, short bool) {
		if !short || seen[owner] {
			return
		}
		evs := ix.eventsFor(ref, "FailedCreate")
		if len(evs) == 0 {
			return
		}
		seen[owner] = true
		out = append(out, failedCreate(ix, ref, owner, evs[0]))
	}
	for _, w := range ix.s.Workloads {
		owner := w.Ref()
		if w.Kind == "ReplicaSet" {
			if d, ok := w.Metadata.Controller(); ok && d.Kind == "Deployment" {
				owner = kube.Ref{Kind: "Deployment", Namespace: w.Metadata.Namespace, Name: d.Name}
			}
			if w.Desired() == 0 {
				continue // an old ReplicaSet scaled down
			}
		}
		if w.Kind == "Deployment" {
			continue // a Deployment's FailedCreate events are on its ReplicaSet
		}
		check(w.Ref(), owner, w.Status.Replicas < w.Desired() || w.Kind == "DaemonSet" && w.Status.DesiredNumberScheduled > w.Status.NumberReady)
	}
	for _, j := range ix.s.Jobs {
		failed, _ := kube.FindCondition(j.Status.Conditions, "Failed")
		check(j.Ref(), j.Ref(), failed.Status != "True" || j.Status.Active == 0)
	}
	return out
}

func failedCreate(ix *index, src, owner kube.Ref, e kube.Event) Finding {
	ev := []Evidence{eventEvidence(src, e)}
	msg := e.Message
	ns := owner.Namespace
	f := Finding{Object: owner, Severity: Critical, Evidence: ev}
	switch {
	case reQuota.MatchString(msg):
		m := reQuota.FindStringSubmatch(msg)
		f.Rule, f.Title = "KD170", "ResourceQuota is exhausted"
		f.Cause = fmt.Sprintf("%s cannot create pods: ResourceQuota %s is used up (requested %s, used %s, limit %s)", owner, m[1], m[2], m[3], m[4])
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "ResourceQuota", Namespace: ns, Name: m[1]},
			What: "quota usage", Command: cmdGet("resourcequota", ns, m[1], "{.status}")})
		f.Fix = fmt.Sprintf("Raise ResourceQuota %s, lower what %s asks for, or remove workloads that hold the quota.", m[1], owner)
	case strings.Contains(msg, "forbidden: failed quota") || reQuotaM.MatchString(msg) && strings.Contains(msg, "quota"):
		f.Rule, f.Title = "KD170", "ResourceQuota is exhausted"
		f.Cause = fmt.Sprintf("%s cannot create pods: a ResourceQuota in %s rejects them (%s)", owner, ns, clip(msg, 200))
		f.Fix = "A quota on cpu or memory requires every container to set that request or limit: set them, or add a LimitRange with defaults."
	case reLimitRange.MatchString(msg):
		m := reLimitRange.FindAllString(msg, -1)
		f.Rule, f.Title = "KD174", "LimitRange rejects the pods"
		f.Cause = fmt.Sprintf("%s cannot create pods: a LimitRange in %s rejects them (%s)", owner, ns, strings.Join(m, "; "))
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "LimitRange", Namespace: ns, Name: "*"},
			What: "the namespace's LimitRanges", Command: "kubectl get limitranges -n " + ns + " -o yaml"})
		f.Fix = "Set the containers' requests and limits inside the LimitRange's minimum and maximum, or change the LimitRange."
	case rePriorityClass.MatchString(msg):
		pc := rePriorityClass.FindStringSubmatch(msg)[1]
		f.Rule, f.Title = "KD175", "PriorityClass does not exist"
		f.Cause = fmt.Sprintf("%s cannot create pods: they name PriorityClass %s, which does not exist", owner, pc)
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "PriorityClass", Name: pc},
			What: "the cluster's PriorityClasses", Command: "kubectl get priorityclasses"})
		f.Fix = fmt.Sprintf("Create PriorityClass %s, or set priorityClassName to one that exists (or remove it).", pc)
	case reRuntimeClass.MatchString(msg):
		rc := reRuntimeClass.FindStringSubmatch(msg)[1]
		f.Rule, f.Title = "KD183", "RuntimeClass does not exist"
		f.Cause = fmt.Sprintf("%s cannot create pods: they name RuntimeClass %s, which does not exist", owner, rc)
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "RuntimeClass", Name: rc},
			What: "the cluster's RuntimeClasses", Command: "kubectl get runtimeclasses"})
		f.Fix = fmt.Sprintf("Create RuntimeClass %s for a handler the nodes' container runtime has (such as gVisor's runsc or Kata), or remove runtimeClassName to use the default runtime.", rc)
	case reSA.MatchString(msg):
		sa := reSA.FindStringSubmatch(msg)[1]
		f.Rule, f.Title = "KD171", "ServiceAccount does not exist"
		f.Cause = fmt.Sprintf("%s cannot create pods: its pods run as ServiceAccount %s, which does not exist in namespace %s", owner, sa, ns)
		if ix.read("serviceaccounts") && !ix.sas[nsName{ns, sa}] {
			f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "ServiceAccount", Namespace: ns, Name: sa},
				What: "there is no ServiceAccount " + sa, Command: cmdGet("serviceaccount", ns, sa, "")})
		}
		f.Fix = fmt.Sprintf("Create ServiceAccount %s in namespace %s, or set serviceAccountName to one that exists.", sa, ns)
	case rePSA.MatchString(msg):
		f.Rule, f.Title = "KD172", "Pod Security admission rejects the pods"
		level := rePSA.FindStringSubmatch(msg)[1]
		f.Cause = fmt.Sprintf("%s cannot create pods: they violate the namespace's PodSecurity level %s (%s)", owner, level, clip(msg[strings.Index(msg, "violates"):], 220))
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "Namespace", Name: ns}, What: "namespace PodSecurity labels",
			Command: "kubectl get namespace " + ns + " --show-labels"})
		f.Fix = "Change the pod spec to meet the level (the message lists each violation), or relax the namespace's pod-security.kubernetes.io/enforce label if that is intended."
	case reWebhk.MatchString(msg):
		wh := reWebhk.FindStringSubmatch(msg)[1]
		f.Rule, f.Title = "KD173", "Admission webhook rejects the pods"
		f.Cause = fmt.Sprintf("%s cannot create pods: admission webhook %s denies them (%s)", owner, wh, clip(msg, 220))
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "ValidatingWebhookConfiguration", Name: "*"},
			What: "admission webhooks", Command: "kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations"})
		f.Fix = "Change the pod spec to satisfy the webhook's policy, or have its owner exempt this workload."
	default:
		f.Rule, f.Title = "KD179", "Controller cannot create pods"
		f.Cause = fmt.Sprintf("%s cannot create pods: %s", owner, clip(msg, 240))
		f.Fix = "Read the error in the evidence; the API server rejected the pod the controller tried to create."
	}
	return f
}

// rolloutFindings reports controllers that failed without a pod-level cause: a Job that hit its backoff limit or
// deadline after its pods were cleaned up, a Deployment whose rollout passed its progress deadline.
func rolloutFindings(ix *index, explained map[kube.Ref]bool) []Finding {
	var out []Finding
	for _, j := range ix.s.Jobs {
		c, ok := kube.FindCondition(j.Status.Conditions, "Failed")
		if !ok || c.Status != "True" || explained[j.Ref()] {
			continue
		}
		out = append(out, Finding{Rule: "KD180", Title: "Job failed", Severity: Critical, Object: j.Ref(),
			Cause: fmt.Sprintf("Job %s failed: %s (%s)", j.Metadata.Name, c.Reason, c.Message),
			Evidence: []Evidence{{Object: j.Ref(), What: "Job condition Failed: " + c.Reason, Detail: c.Message,
				Command: cmdGet("job", j.Metadata.Namespace, j.Metadata.Name, `{.status.conditions[?(@.type=="Failed")]}`)}},
			Fix: "Read the failed pods' logs if they still exist (kubectl logs job/" + j.Metadata.Name + "); raise backoffLimit or activeDeadlineSeconds only if the work is slow, not broken."})
	}
	for _, w := range ix.s.Workloads {
		if w.Kind != "Deployment" || explained[w.Ref()] {
			continue
		}
		c, ok := kube.FindCondition(w.Status.Conditions, "Progressing")
		if !ok || c.Reason != "ProgressDeadlineExceeded" {
			continue
		}
		out = append(out, Finding{Rule: "KD181", Title: "Deployment rollout stalled", Severity: Warning, Object: w.Ref(),
			Cause: fmt.Sprintf("Deployment %s did not finish its rollout in time: %s", w.Metadata.Name, c.Message),
			Evidence: []Evidence{{Object: w.Ref(), What: "Progressing condition: ProgressDeadlineExceeded", Detail: c.Message,
				Command: cmdGet("deployment", w.Metadata.Namespace, w.Metadata.Name, `{.status.conditions[?(@.type=="Progressing")]}`)}},
			Fix: "Find why the new pods do not become ready (kubectl rollout status, and their events), then fix or roll back (kubectl rollout undo)."})
	}
	return out
}
