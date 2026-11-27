package diagnose

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	reQuota         = regexp.MustCompile(`exceeded quota: ([^,]+), requested: ([^,]+(?:,[^,:]+)*), used: ([^,]+(?:,[^,:]+)*), limited: (.+)$`)
	reQuotaM        = regexp.MustCompile(`must specify ([^ ]+)`)
	reQuotaMust     = regexp.MustCompile(`failed quota: ([^:]+): must specify (.+)$`)
	reReqAboveLimit = regexp.MustCompile(`spec\.(initContainers|containers)\[(\d+)\]\.resources\.requests: Invalid value: "([^"]+)": must be less than or equal to (\S+) limit of (\S+)`)
	reCreateClaim   = regexp.MustCompile(`^[Cc]reate Claim (\S+) for Pod \S+ in StatefulSet \S+ failed`)
	reLimitRange    = regexp.MustCompile(`(?:maximum|minimum) (?:cpu|memory|ephemeral-storage|storage) usage per (?:Container|Pod|PersistentVolumeClaim) is [^,\]]+, but (?:limit|request) is [^,\]]+|(?:cpu|memory|ephemeral-storage) max limit to request ratio per Container is [^,\]]+, but provided ratio is [^,\]]+`)
	rePriorityClass = regexp.MustCompile(`no PriorityClass with name (\S+) was found`)
	reRuntimeClass  = regexp.MustCompile(`RuntimeClass "([^"]+)" not found`)
	reSA            = regexp.MustCompile(`serviceaccount "([^"]+)" not found`)
	reWebhk         = regexp.MustCompile(`admission webhook "([^"]+)" denied the request`)
	reWebhkCall     = regexp.MustCompile(`failed calling webhook "([^"]+)": (?:failed to call webhook: )?(.*)$`)
	reWebhkService  = regexp.MustCompile(`"https://([a-z0-9-]+)\.([a-z0-9-]+)\.svc(?::\d+)?[^"]*"`)
	rePSA           = regexp.MustCompile(`violates PodSecurity "([^"]+)"`)
	// The API server's own CEL admission: "ValidatingAdmissionPolicy 'p' with binding 'b' denied request: <message>".
	// System-critical priority is limited to namespaces with a ResourceQuota that names it (kube-system's, by default).
	reCriticalPriority = regexp.MustCompile(`insufficient quota to match these scopes: \[\{PriorityClass In \[([^\]]+)\]\}\]`)
	reVAP              = regexp.MustCompile(`ValidatingAdmissionPolicy '([^']+)' with binding '([^']+)' denied request: (.*)$`)
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
	// A StatefulSet creates each pod's claims from its volumeClaimTemplates first; when that fails, the pod waits.
	claim := ""
	if m := reCreateClaim.FindStringSubmatch(msg); m != nil {
		claim = m[1]
	}
	switch {
	case reCriticalPriority.MatchString(msg):
		classes := reCriticalPriority.FindStringSubmatch(msg)[1]
		pc := ""
		if w := ix.workloads[src]; w != nil {
			pc = w.Spec.Template.Spec.PriorityClassName
		} else if j := ix.jobs[src]; j != nil {
			pc = j.Spec.Template.Spec.PriorityClassName
		}
		if pc == "" {
			pc = strings.Fields(classes)[0]
		}
		f.Rule, f.Title = "KD380", "System-critical priority is not allowed in the namespace"
		f.Cause = fmt.Sprintf("%s cannot create pods: they use PriorityClass %s, and the API server admits a pod with a system-critical priority (%s) only in a namespace with a ResourceQuota that names that class, as kube-system has; %s has none", owner, pc, classes, ns)
		f.Evidence = append(f.Evidence, Evidence{Object: owner, What: fmt.Sprintf("the pod template's priorityClassName is %s", pc),
			Command: cmdGet(strings.ToLower(owner.Kind), ns, owner.Name, `{.spec.template.spec.priorityClassName}`)})
		f.Fix = fmt.Sprintf("Remove priorityClassName %s (it is for cluster add-ons that must not be evicted, often copied from a kube-system manifest) or use a PriorityClass of your own. If the workload truly is critical, add a ResourceQuota in %s whose scopeSelector names PriorityClass %s.", pc, ns, pc)
	case reQuota.MatchString(msg):
		m := reQuota.FindStringSubmatch(msg)
		f.Rule, f.Title = "KD170", "ResourceQuota is exhausted"
		f.Cause = fmt.Sprintf("%s cannot create pods: ResourceQuota %s is used up (requested %s, used %s, limit %s)", owner, m[1], m[2], m[3], m[4])
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "ResourceQuota", Namespace: ns, Name: m[1]},
			What: "quota usage", Command: cmdGet("resourcequota", ns, m[1], "{.status}")})
		f.Fix = fmt.Sprintf("Raise ResourceQuota %s, lower what %s asks for, or remove workloads that hold the quota.", m[1], owner)
		if claim != "" {
			f.Cause = fmt.Sprintf("%s cannot create PersistentVolumeClaim %s from its volumeClaimTemplates, so the pod that mounts it is never created: ResourceQuota %s is used up (requested %s, used %s, limit %s)", owner, claim, m[1], m[2], m[3], m[4])
			f.Fix = fmt.Sprintf("Raise ResourceQuota %s, lower the storage the volumeClaimTemplates ask for, or delete claims that hold the quota (a StatefulSet keeps its claims after its pods are gone).", m[1])
		}
	case reQuotaMust.MatchString(msg):
		quotaRequires(&f, owner, reQuotaMust.FindStringSubmatch(msg))
	case strings.Contains(msg, "forbidden: failed quota") || reQuotaM.MatchString(msg) && strings.Contains(msg, "quota"):
		f.Rule, f.Title = "KD170", "ResourceQuota is exhausted"
		f.Cause = fmt.Sprintf("%s cannot create pods: a ResourceQuota in %s rejects them (%s)", owner, ns, clip(msg, 200))
		f.Fix = "A quota on cpu or memory requires every container to set that request or limit: set them, or add a LimitRange with defaults."
	case reReqAboveLimit.MatchString(msg):
		defaultBelowRequest(ix, &f, src, owner, reReqAboveLimit.FindStringSubmatch(msg))
	case reLimitRange.MatchString(msg):
		m := reLimitRange.FindAllString(msg, -1)
		f.Rule, f.Title = "KD174", "LimitRange rejects the pods"
		f.Cause = fmt.Sprintf("%s cannot create pods: a LimitRange in %s rejects them (%s)", owner, ns, strings.Join(m, "; "))
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "LimitRange", Namespace: ns, Name: "*"},
			What: "the namespace's LimitRanges", Command: "kubectl get limitranges -n " + ns + " -o yaml"})
		f.Fix = "Set the containers' requests and limits inside the LimitRange's minimum and maximum, or change the LimitRange."
		if claim != "" {
			f.Cause = fmt.Sprintf("%s cannot create PersistentVolumeClaim %s from its volumeClaimTemplates, so the pod that mounts it is never created: a LimitRange in %s rejects the claim (%s)", owner, claim, ns, strings.Join(m, "; "))
			f.Fix = "Ask for storage within the LimitRange's PersistentVolumeClaim minimum and maximum in the volumeClaimTemplates (they cannot be edited in place: delete the StatefulSet with --cascade=orphan, which keeps its pods, and apply it again), or change the LimitRange."
		}
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
	case reVAP.MatchString(msg):
		m := reVAP.FindStringSubmatch(msg)
		policy, binding, why := m[1], m[2], strings.TrimSpace(m[3])
		f.Rule, f.Title = "KD279", "ValidatingAdmissionPolicy rejects the pods"
		f.Cause = fmt.Sprintf("%s cannot create pods: ValidatingAdmissionPolicy %s, through binding %s, denies them: %s", owner, policy, binding, clip(why, 200))
		f.Evidence = append(f.Evidence,
			Evidence{Object: kube.Ref{Kind: "ValidatingAdmissionPolicy", Name: policy}, What: fmt.Sprintf("policy %s's validations", policy),
				Command: cmdGet("validatingadmissionpolicy", "", policy, `{.spec.validations}`)},
			Evidence{Object: kube.Ref{Kind: "ValidatingAdmissionPolicyBinding", Name: binding}, What: fmt.Sprintf("binding %s: what it applies the policy to, and how", binding),
				Command: cmdGet("validatingadmissionpolicybinding", "", binding, `{.spec.matchResources}{"\n"}{.spec.validationActions}`)})
		f.Fix = fmt.Sprintf("Change the pod template to pass the policy (its message says what it checks), or, if %s should not apply here, narrow binding %s's matchResources; validationActions Warn or Audit report without denying.", owner, binding)
	case reWebhkCall.MatchString(msg):
		webhookUnreachable(&f, owner, reWebhkCall.FindStringSubmatch(msg))
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
		jf := Finding{Rule: "KD180", Title: "Job failed", Severity: Critical, Object: j.Ref(),
			Cause: fmt.Sprintf("Job %s failed: %s (%s)", j.Metadata.Name, c.Reason, c.Message),
			Evidence: []Evidence{{Object: j.Ref(), What: "Job condition Failed: " + c.Reason, Detail: c.Message,
				Command: cmdGet("job", j.Metadata.Namespace, j.Metadata.Name, `{.status.conditions[?(@.type=="Failed")]}`)}},
			Fix: "Read the failed pods' logs if they still exist (kubectl logs job/" + j.Metadata.Name + "); raise backoffLimit or activeDeadlineSeconds only if the work is slow, not broken."}
		if c.Reason == "DeadlineExceeded" && j.Spec.ActiveDeadlineSeconds != nil {
			pastDeadline(&jf, j)
		}
		out = append(out, jf)
	}
	for _, j := range ix.s.Jobs {
		if f := suspendedJob(ix, j); f != nil && !explained[j.Ref()] {
			out = append(out, *f)
		} else if f := noParallelism(ix, j); f != nil && !explained[j.Ref()] {
			out = append(out, *f)
		} else if f := managedElsewhere(ix, j); f != nil && !explained[j.Ref()] {
			out = append(out, *f)
		}
	}
	for _, w := range ix.s.Workloads {
		if f := daemonSetNoNodes(ix, w); f != nil && !explained[w.Ref()] {
			out = append(out, *f)
		} else if f := sharedRWOClaim(ix, w); f != nil && !explained[w.Ref()] {
			out = append(out, *f)
		} else if f := onDeleteWaits(w); f != nil && !explained[w.Ref()] {
			out = append(out, *f)
		} else if f := partitionHolds(w); f != nil && !explained[w.Ref()] {
			out = append(out, *f)
		} else if f := deadlineTooShort(w); f != nil && !explained[w.Ref()] {
			out = append(out, *f)
		} else if f := minReadyHolds(w); f != nil && !explained[w.Ref()] {
			out = append(out, *f)
		}
	}
	for _, w := range ix.s.Workloads {
		if w.Kind != "Deployment" || explained[w.Ref()] {
			continue
		}
		if f := paused(w); f != nil {
			out = append(out, *f)
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

// paused finds a Deployment left paused while its replicas are not all on the current template and ready. A paused
// Deployment creates no new ReplicaSet and never reaches its progress deadline, so nothing else reports it; one
// created paused never creates a pod at all.
func paused(w kube.Workload) *Finding {
	desired := w.Desired()
	if !w.Spec.Paused || desired == 0 || (w.Status.UpdatedReplicas >= desired && w.Status.ReadyReplicas >= desired) {
		return nil
	}
	ns, name := w.Metadata.Namespace, w.Metadata.Name
	sev := Warning
	if w.Status.ReadyReplicas == 0 {
		sev = Critical
	}
	ev := []Evidence{{Object: w.Ref(), What: fmt.Sprintf("Deployment has spec.paused: true, %d of %d replicas updated, %d ready", w.Status.UpdatedReplicas, desired, w.Status.ReadyReplicas),
		Command: cmdGet("deployment", ns, name, `{.spec.paused}{" "}{.status}`)}}
	if c, ok := kube.FindCondition(w.Status.Conditions, "Progressing"); ok && c.Reason == "DeploymentPaused" {
		ev[0].Detail = c.Message
	}
	return &Finding{Rule: "KD184", Title: "Deployment rollout is paused", Severity: sev, Object: w.Ref(),
		Cause:    fmt.Sprintf("Deployment %s is paused, so it does not roll out: %d of its %d replicas run the current pod template and %d are ready", name, w.Status.UpdatedReplicas, desired, w.Status.ReadyReplicas),
		Evidence: ev,
		Fix:      fmt.Sprintf("Resume it when the change is ready: kubectl rollout resume deployment/%s -n %s.", name, ns)}
}

// suspendedAfter is how long a Job may stay suspended before it is reported: Kueue admits a Job with quota free at
// once, and a Job suspended by hand is usually resumed soon after.
const suspendedAfter = 2 * time.Minute

// suspendedJob finds a Job that has been suspended for a while, so it runs no pods. Under Kueue that means the Job
// waits for admission; otherwise someone suspended it, which is noted as information.
func suspendedJob(ix *index, j kube.Job) *Finding {
	if j.Spec.Suspend == nil || !*j.Spec.Suspend {
		return nil
	}
	since := j.Metadata.CreationTimestamp
	if c, ok := kube.FindCondition(j.Status.Conditions, "Suspended"); ok && c.Status == "True" && !c.LastTransitionTime.IsZero() {
		since = c.LastTransitionTime
	}
	if since.IsZero() || ix.s.CollectedAt.Sub(since) < suspendedAfter {
		return nil
	}
	ns, name := j.Metadata.Namespace, j.Metadata.Name
	held := ix.s.CollectedAt.Sub(since).Round(time.Minute)
	ev := []Evidence{{Object: j.Ref(), What: "Job has spec.suspend: true", Command: cmdGet("job", ns, name, `{.spec.suspend}{" "}{.status.conditions}`)}}
	f := &Finding{Rule: "KD187", Title: "Job is suspended", Severity: Info, Object: j.Ref(), Evidence: ev,
		Cause: fmt.Sprintf("Job %s has been suspended for %s, so it runs no pods until spec.suspend is set to false", name, held),
		Fix:   fmt.Sprintf("Resume it if it should run: kubectl patch job %s -n %s --type=merge -p '{\"spec\":{\"suspend\":false}}'.", name, ns)}
	if q := j.Metadata.Labels["kueue.x-k8s.io/queue-name"]; q != "" {
		f.Severity = Warning
		f.Cause = fmt.Sprintf("Job %s has waited %s for Kueue to admit it from LocalQueue %s; Kueue keeps it suspended until the queue's ClusterQueue has quota for it", name, held, q)
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "Workload", Namespace: ns, Name: "*"}, What: "Kueue's Workloads in the namespace, with their admission status",
			Command: "kubectl get workloads.kueue.x-k8s.io -n " + ns})
		f.Fix = fmt.Sprintf("Read the Job's Workload (its QuotaReserved and Admitted conditions say why it waits): the ClusterQueue behind LocalQueue %s has no quota left for its flavor, or the LocalQueue does not exist. Do not unsuspend it by hand: Kueue would suspend it again.", q)
	}
	return f
}

// managedElsewhere finds a Job whose spec.managedBy hands it to another controller than Kubernetes' Job controller,
// and that has not started: the Job controller creates no pods for it and writes no status, and the controller it
// names has done nothing either (it is not installed, or does not take this Job). MultiKueue is the common case: it
// runs the Job on a worker cluster and copies the status back.
func managedElsewhere(ix *index, j kube.Job) *Finding {
	by := j.Spec.ManagedBy
	if by == "" || by == "kubernetes.io/job-controller" || j.Status.StartTime != nil || j.Status.Active+j.Status.Succeeded+j.Status.Failed > 0 ||
		len(j.Status.Conditions) > 0 || ix.s.CollectedAt.Sub(j.Metadata.CreationTimestamp) < suspendedAfter {
		return nil
	}
	ns, name := j.Metadata.Namespace, j.Metadata.Name
	age := ix.s.CollectedAt.Sub(j.Metadata.CreationTimestamp).Round(time.Minute)
	cause := fmt.Sprintf("Job %s has spec.managedBy %s, so Kubernetes' Job controller leaves it alone and creates no pods; in %s that controller has not started it either (the Job has no status), so it is not running here or does not take this Job", name, by, age)
	fix := fmt.Sprintf("Run the controller that %s names, or create the Job without spec.managedBy so Kubernetes' Job controller runs it (the field cannot be changed on an existing Job: delete and recreate it).", by)
	if by == "kueue.x-k8s.io/multikueue" {
		cause = fmt.Sprintf("Job %s has spec.managedBy kueue.x-k8s.io/multikueue, so Kubernetes' Job controller leaves it to MultiKueue, which runs it on a worker cluster and copies the status back; in %s it has not started (the Job has no status): MultiKueue has not dispatched it, or no worker cluster has admitted it", name, age)
		fix = "Read the Job's Workload and the MultiKueueCluster objects on this (manager) cluster: a worker that cannot be reached, or no quota on any worker, keeps the Job here. Remove spec.managedBy only to run the Job on this cluster."
	}
	return &Finding{Rule: "KD298", Title: "Job is left to another controller, which has not run it", Severity: Warning, Object: j.Ref(), Cause: cause,
		Evidence: []Evidence{{Object: j.Ref(), What: fmt.Sprintf("Job %s has spec.managedBy %s and no status after %s", name, by, age),
			Command: cmdGet("job", ns, name, `{.spec.managedBy}{" "}{.status}`)}},
		Fix: fix}
}

// noParallelism finds a Job with parallelism 0 that has not finished: it starts no pods, so it never completes, and
// nothing reports an error. Setting parallelism to 0 is a way to pause a Job; left there, it looks like a hung Job.
func noParallelism(ix *index, j kube.Job) *Finding {
	if j.Spec.Parallelism == nil || *j.Spec.Parallelism != 0 || j.Status.Active > 0 || ix.s.CollectedAt.Sub(j.Metadata.CreationTimestamp) < suspendedAfter {
		return nil
	}
	for _, t := range []string{"Complete", "Failed"} {
		if c, ok := kube.FindCondition(j.Status.Conditions, t); ok && c.Status == "True" {
			return nil
		}
	}
	ns, name := j.Metadata.Namespace, j.Metadata.Name
	age := ix.s.CollectedAt.Sub(j.Metadata.CreationTimestamp).Round(time.Minute)
	return &Finding{Rule: "KD283", Title: "Job runs no pods: parallelism is 0", Severity: Warning, Object: j.Ref(),
		Cause: fmt.Sprintf("Job %s has parallelism 0, so it starts no pods: it has run none in %s and will never complete (%d succeeded, %d failed)", name, age, j.Status.Succeeded, j.Status.Failed),
		Evidence: []Evidence{{Object: j.Ref(), What: fmt.Sprintf("Job %s has spec.parallelism 0 and no active pods", name),
			Command: cmdGet("job", ns, name, `{.spec.parallelism}{" "}{.status}`)}},
		Fix: fmt.Sprintf("Set parallelism to the number of pods to run at once: kubectl patch job %s -n %s --type=merge -p '{\"spec\":{\"parallelism\":1}}'; to pause a Job, spec.suspend says so plainly.", name, ns)}
}

// minReadyHolds finds a Deployment whose pods are all ready and still not counted available, because its
// minReadySeconds is long: a pod is available only after it has stayed ready that long, so the Deployment reports
// unavailable replicas and each step of a rollout waits that long, with nothing failing.
func minReadyHolds(w kube.Workload) *Finding {
	wait := w.Spec.MinReadySeconds
	if w.Kind != "Deployment" || wait < 60 || w.Spec.Replicas == nil || *w.Spec.Replicas == 0 {
		return nil
	}
	ready, avail := w.Status.ReadyReplicas, w.Status.AvailableReplicas
	if ready == 0 || avail >= ready {
		return nil
	}
	ns, name := w.Metadata.Namespace, w.Metadata.Name
	d := time.Duration(wait) * time.Second
	return &Finding{Rule: "KD288", Title: "Ready pods are held unavailable by minReadySeconds", Severity: Warning, Object: w.Ref(),
		Cause: fmt.Sprintf("Deployment %s has %d of %d pods ready but only %d available: its minReadySeconds is %d, so a pod counts as available only after it has stayed ready for %s, and a rollout waits that long at every step",
			name, ready, *w.Spec.Replicas, avail, wait, d),
		Evidence: []Evidence{{Object: w.Ref(), What: fmt.Sprintf("Deployment %s has minReadySeconds %d, %d ready and %d available", name, wait, ready, avail),
			Command: cmdGet("deployment", ns, name, `{.spec.minReadySeconds}{" "}{.status.readyReplicas}{" "}{.status.availableReplicas}`)}},
		Fix: "Lower minReadySeconds to the few seconds a new pod needs to prove itself (it is not a timeout), and let the readiness probe say when the pod can serve."}
}

// sharedRWOClaim finds a Deployment or ReplicaSet with more than one replica whose pod template mounts a
// PersistentVolumeClaim that is ReadWriteOnce only: every replica mounts the same claim, and a ReadWriteOnce volume
// attaches to one node at a time, so replicas the scheduler puts on another node never start (Multi-Attach error),
// and a rolling update can stall the same way. On one node, or while they share a node, it happens to work.
func sharedRWOClaim(ix *index, w kube.Workload) *Finding {
	if (w.Kind != "Deployment" && w.Kind != "ReplicaSet") || w.Spec.Replicas == nil || *w.Spec.Replicas < 2 {
		return nil
	}
	if w.Kind == "ReplicaSet" {
		if o, ok := w.Metadata.Controller(); ok && o.Kind == "Deployment" {
			return nil // reported on the Deployment
		}
	}
	ns := w.Metadata.Namespace
	for _, v := range w.Spec.Template.Spec.Volumes {
		if v.PersistentVolumeClaim == nil {
			continue
		}
		claim := v.PersistentVolumeClaim.ClaimName
		pvc, ok := ix.pvcs[nsName{ns, claim}]
		if !ok || !onlyRWO(pvc.Spec.AccessModes) {
			continue
		}
		return &Finding{Rule: "KD287", Title: "Replicas share a ReadWriteOnce claim", Severity: Warning, Object: w.Ref(),
			Cause: fmt.Sprintf("%s %s runs %d replicas that all mount PersistentVolumeClaim %s, which is ReadWriteOnce: its volume attaches to one node at a time, so replicas scheduled on another node cannot start (Multi-Attach error), and rolling updates can stall the same way; it works only while they share a node",
				w.Kind, w.Metadata.Name, *w.Spec.Replicas, claim),
			Evidence: []Evidence{
				{Object: w.Ref(), What: fmt.Sprintf("%s %s has %d replicas and mounts claim %s", w.Kind, w.Metadata.Name, *w.Spec.Replicas, claim),
					Command: cmdGet(strings.ToLower(w.Kind), ns, w.Metadata.Name, `{.spec.replicas}{" "}{.spec.template.spec.volumes}`)},
				{Object: kube.Ref{Kind: "PersistentVolumeClaim", Namespace: ns, Name: claim}, What: fmt.Sprintf("claim %s has access modes %s", claim, strings.Join(pvc.Spec.AccessModes, ", ")),
					Command: cmdGet("persistentvolumeclaim", ns, claim, "{.spec.accessModes}")},
			},
			Fix: "Give each replica its own volume (a StatefulSet with volumeClaimTemplates), use a ReadWriteMany volume if they must share files, or run one replica with strategy Recreate."}
	}
	return nil
}

func onlyRWO(modes []string) bool {
	return len(modes) > 0 && !slices.ContainsFunc(modes, func(m string) bool { return m != "ReadWriteOnce" })
}

// daemonSetNoNodes finds a DaemonSet that should run on no node: its nodeSelector matches none, or every node has a
// taint its pods do not tolerate. It creates no pods, so nothing fails and nothing says why.
func daemonSetNoNodes(ix *index, w kube.Workload) *Finding {
	if w.Kind != "DaemonSet" || w.Status.DesiredNumberScheduled != 0 || len(ix.s.Nodes) == 0 || !ix.read("nodes") ||
		ix.s.CollectedAt.Sub(w.Metadata.CreationTimestamp) < suspendedAfter {
		return nil
	}
	ns, name, spec := w.Metadata.Namespace, w.Metadata.Name, w.Spec.Template.Spec
	if sel := spec.NodeSelector; len(sel) > 0 {
		for _, n := range ix.s.Nodes {
			if kube.MatchesMap(sel, n.Metadata.Labels) {
				return nil // a node matches: the reason is elsewhere (affinity, taints)
			}
		}
		s := kube.FormatMap(sel)
		return &Finding{Rule: "KD282", Title: "DaemonSet matches no node", Severity: Warning, Object: w.Ref(),
			Cause: fmt.Sprintf("DaemonSet %s's nodeSelector requires the labels %s, and none of the cluster's %s has them, so it runs no pods and nothing reports an error", name, s, plural(len(ix.s.Nodes), "node")),
			Evidence: []Evidence{{Object: w.Ref(), What: fmt.Sprintf("DaemonSet %s should run on 0 nodes; its pods require node labels %s", name, s),
				Command: cmdGet("daemonset", ns, name, `{.spec.template.spec.nodeSelector}{" "}{.status.desiredNumberScheduled}`)},
				{Object: kube.Ref{Kind: "Node", Name: "*"}, What: fmt.Sprintf("none of the %d nodes has %s", len(ix.s.Nodes), s), Command: "kubectl get nodes -l " + s}},
			Fix: "Label the nodes it should run on (kubectl label node NODE " + strings.ReplaceAll(s, ",", " ") + "), or correct the nodeSelector."}
	}
	for _, n := range ix.s.Nodes {
		if tolerated(spec.Tolerations, n.Spec.Taints) {
			return nil
		}
	}
	return &Finding{Rule: "KD282", Title: "DaemonSet matches no node", Severity: Warning, Object: w.Ref(),
		Cause: fmt.Sprintf("every node has a taint DaemonSet %s's pods do not tolerate, so it runs no pods and nothing reports an error", name),
		Evidence: []Evidence{{Object: w.Ref(), What: fmt.Sprintf("DaemonSet %s should run on 0 nodes", name), Command: cmdGet("daemonset", ns, name, `{.spec.template.spec.tolerations}{" "}{.status.desiredNumberScheduled}`)},
			{Object: kube.Ref{Kind: "Node", Name: "*"}, What: "node taints", Command: `kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints`}},
		Fix: "Add tolerations for the nodes' taints to the DaemonSet's pod template if it belongs on them, or remove the taints."}
}

// tolerated reports whether the tolerations let a pod onto a node with these taints (NoSchedule and NoExecute;
// PreferNoSchedule does not keep a pod off).
func tolerated(tols []kube.Toleration, taints []kube.Taint) bool {
	for _, t := range taints {
		if t.Effect == "PreferNoSchedule" {
			continue
		}
		ok := false
		for _, tol := range tols {
			if (tol.Effect == "" || tol.Effect == t.Effect) &&
				((tol.Operator == "Exists" && (tol.Key == "" || tol.Key == t.Key)) || (tol.Key == t.Key && tol.Value == t.Value)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// quotaRequires explains pods rejected because a ResourceQuota limits a compute resource that their containers do
// not set: a quota on limits.memory, say, can only be counted when every container has a memory limit, so the API
// server refuses pods without one. The quota is not used up; m is reQuotaMust's match.
func quotaRequires(f *Finding, owner kube.Ref, m []string) {
	quota, ns := m[1], owner.Namespace
	field := func(res string) string {
		switch {
		case strings.HasPrefix(res, "limits."), strings.HasPrefix(res, "requests."):
			return "resources." + res
		default:
			return "resources.requests." + res // a quota on plain cpu or memory counts requests
		}
	}
	var missing, set, names []string
	for _, item := range strings.Split(m[2], "; ") {
		res, containers, _ := strings.Cut(item, " for: ")
		res = strings.TrimSpace(res)
		who := "its containers set"
		if cs := strings.Split(containers, ","); containers != "" && len(cs) == 1 {
			who = "container " + cs[0] + " sets"
		} else if containers != "" {
			who = "containers " + strings.Join(cs, ", ") + " set"
		}
		missing = append(missing, fmt.Sprintf("%s no %s", who, field(res)))
		names = append(names, res)
		set = append(set, field(res))
	}
	f.Rule, f.Title = "KD275", "ResourceQuota requires a request or limit the pods do not set"
	f.Cause = fmt.Sprintf("%s cannot create pods: ResourceQuota %s puts a quota on %s, which the API server can only count when every container sets it, and %s. The quota is not used up: the pods are refused for leaving the field out",
		owner, quota, strings.Join(names, " and "), strings.Join(missing, "; "))
	f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "ResourceQuota", Namespace: ns, Name: quota},
		What: fmt.Sprintf("ResourceQuota %s's limits", quota), Command: cmdGet("resourcequota", ns, quota, "{.status.hard}")},
		Evidence{Object: owner, What: "the containers' requests and limits",
			Command: cmdGet(strings.ToLower(owner.Kind), ns, owner.Name, `{range .spec.template.spec.containers[*]}{.name}{" "}{.resources}{"\n"}{end}`)})
	f.Fix = fmt.Sprintf("Set %s on the containers named, or add a LimitRange to the namespace with a default for it, so that containers which set none are given one.", strings.Join(set, " and "))
}

// pastDeadline explains a Job that its own activeDeadlineSeconds stopped. The deadline counts from the Job's start
// and covers every retry; when it passes, the Job controller ends the pods that are still running and fails the
// Job, so nothing has crashed and there is no failed pod to read: the work was cut off.
func pastDeadline(f *Finding, j kube.Job) {
	limit := *j.Spec.ActiveDeadlineSeconds
	done := fmt.Sprintf("%d of its pods had succeeded", j.Status.Succeeded)
	if j.Spec.Completions != nil {
		done = fmt.Sprintf("%d of %d completions had succeeded", j.Status.Succeeded, *j.Spec.Completions)
	}
	f.Cause = fmt.Sprintf("Job %s was stopped by its own activeDeadlineSeconds (%d): it was still running %ds after it started, so the Job controller ended its pods and failed the Job (%s). Nothing crashed: the work was cut off, and its pods are gone",
		j.Metadata.Name, limit, limit, done)
	f.Evidence = append(f.Evidence, Evidence{Object: j.Ref(), What: fmt.Sprintf("the Job's activeDeadlineSeconds is %d", limit),
		Command: cmdGet("job", j.Metadata.Namespace, j.Metadata.Name, `{.spec.activeDeadlineSeconds}{" "}{.status.startTime}{" "}{.status.succeeded}`)})
	f.Fix = fmt.Sprintf("If the work needs longer than %ds, recreate the Job with a higher activeDeadlineSeconds, or none: the deadline covers the whole Job from its start, every retry included. If the work hangs, read its log while it runs (kubectl logs -f job/%s): once the deadline passes the pods are deleted.", limit, j.Metadata.Name)
}

// defaultBelowRequest explains pods the API server calls invalid because a container's request is above its limit,
// when the pod template sets that request and no limit. The limit is the namespace's LimitRange default: the
// LimitRanger admission plugin fills it in, and it is below what the container asks for. The error names neither the
// LimitRange nor where the limit came from. m is reReqAboveLimit's match.
func defaultBelowRequest(ix *index, f *Finding, src, owner kube.Ref, m []string) {
	ns, request, res, limit := owner.Namespace, m[3], m[4], m[5]
	idx, _ := strconv.Atoi(m[2])
	container := fmt.Sprintf("container %d", idx)
	ownLimit := ""
	for _, ref := range []kube.Ref{owner, src} {
		w, ok := ix.workloads[ref]
		if !ok {
			continue
		}
		cs := w.Spec.Template.Spec.Containers
		if m[1] == "initContainers" {
			cs = w.Spec.Template.Spec.InitContainers
		}
		if idx < len(cs) {
			container, ownLimit = "container "+cs[idx].Name, cs[idx].Resources.Limits[res]
		}
		break
	}
	f.Rule, f.Title = "KD276", "LimitRange's default limit is below the container's request"
	f.Cause = fmt.Sprintf("%s cannot create pods: %s requests %s of %s and sets no %s limit, so the namespace's LimitRange gave it its default limit, %s, and a request above the limit makes the pod invalid", owner, container, request, res, res, limit)
	if ownLimit != "" {
		f.Cause = fmt.Sprintf("%s cannot create pods: %s requests %s of %s, above its %s limit of %s, which makes the pod invalid", owner, container, request, res, res, limit)
	}
	f.Evidence = append(f.Evidence, Evidence{Object: owner, What: "the pod template's requests and limits",
		Command: cmdGet(strings.ToLower(owner.Kind), ns, owner.Name, `{range .spec.template.spec.containers[*]}{.name}{" "}{.resources}{"\n"}{end}`)},
		Evidence{Object: kube.Ref{Kind: "LimitRange", Namespace: ns, Name: "*"}, What: "the namespace's LimitRanges and their defaults", Command: "kubectl get limitranges -n " + ns + " -o yaml"})
	f.Fix = fmt.Sprintf("Set the %s limit of %s in the pod template, at or above its request of %s, so that the LimitRange's default is not used; or lower the request to %s or less; or raise the default in the LimitRange.", res, container, request, limit)
}

// webhookUnreachable explains pods refused because the API server could not call an admission webhook: its Service
// is gone or has no pods, the connection fails or times out, or its certificate is not trusted. The webhook did not
// reject anything; with failurePolicy Fail, not reaching it refuses every request it covers, here every new pod.
// m is reWebhkCall's match.
func webhookUnreachable(f *Finding, owner kube.Ref, m []string) {
	hook, detail := m[1], m[2]
	svc, svcNS := "", ""
	if s := reWebhkService.FindStringSubmatch(detail); s != nil {
		svc, svcNS = s[1], s[2]
	}
	where := "its endpoint"
	if svc != "" {
		where = fmt.Sprintf("Service %s in namespace %s", svc, svcNS)
	}
	// What went wrong follows the URL, which itself ends in "?timeout=...".
	reason := detail
	if i := strings.LastIndex(detail, `": `); i >= 0 {
		reason = detail[i+3:]
	}
	var why string
	switch {
	case strings.Contains(reason, "x509"):
		why = "the API server does not accept the certificate of " + where + " (the caBundle in the webhook's configuration does not match it, or it has expired)"
	case strings.Contains(reason, "not found"):
		why = where + " does not exist"
	case strings.Contains(reason, "no endpoints available"):
		why = where + " has no ready pods"
	case strings.Contains(reason, "connection refused"):
		why = where + " refuses the connection"
	case strings.Contains(reason, "deadline exceeded") || strings.Contains(reason, "timeout") || strings.Contains(reason, "timed out"):
		why = where + " does not answer in time"
	default:
		why = clip(detail, 200)
	}
	f.Rule, f.Title = "KD277", "Admission webhook cannot be reached"
	f.Cause = fmt.Sprintf("%s cannot create pods: the API server must ask admission webhook %s before it admits a pod, and cannot: %s. The webhook rejected nothing; its failurePolicy is Fail, so every pod is refused for as long as it cannot be asked", owner, hook, why)
	f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "ValidatingWebhookConfiguration", Name: "*"},
		What: fmt.Sprintf("the configuration that lists webhook %s", hook), Command: "kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations"})
	fix := "Bring the webhook back"
	if svc != "" {
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "Service", Namespace: svcNS, Name: svc}, What: "the webhook's Service and the pods behind it",
			Command: "kubectl get service,endpointslices,pods -n " + svcNS})
		fix = fmt.Sprintf("Bring the webhook back: Service %s in namespace %s and the pods behind it", svc, svcNS)
	}
	f.Fix = fmt.Sprintf("%s. If the webhook is gone for good, delete the ValidatingWebhookConfiguration or MutatingWebhookConfiguration that lists %s. A webhook that should not stop the cluster when it is down can set failurePolicy: Ignore, or leave this namespace out with a namespaceSelector.", fix, hook)
}

// onDeleteWaits finds a StatefulSet or DaemonSet with updateStrategy OnDelete whose template has changed and whose
// pods still run the old one. OnDelete replaces a pod only when someone deletes it, so a new image or setting
// reaches nothing, and nothing says so: no event, no condition, every pod ready.
func onDeleteWaits(w kube.Workload) *Finding {
	if w.Spec.UpdateStrategy.Type != "OnDelete" {
		return nil
	}
	ns, name := w.Metadata.Namespace, w.Metadata.Name
	var old, all int32
	var ev Evidence
	switch w.Kind {
	case "StatefulSet":
		if w.Status.UpdateRevision == "" || w.Status.UpdateRevision == w.Status.CurrentRevision {
			return nil
		}
		all = w.Status.Replicas
		old = all - w.Status.UpdatedReplicas
		ev = Evidence{Object: w.Ref(), What: fmt.Sprintf("StatefulSet %s: current revision %s, update revision %s, %d of %d pods updated", name, w.Status.CurrentRevision, w.Status.UpdateRevision, w.Status.UpdatedReplicas, all),
			Command: cmdGet("statefulset", ns, name, `{.spec.updateStrategy.type}{" "}{.status.currentRevision}{" "}{.status.updateRevision}{" "}{.status.updatedReplicas}/{.status.replicas}`)}
	case "DaemonSet":
		all = w.Status.DesiredNumberScheduled
		old = all - w.Status.UpdatedNumberScheduled
		ev = Evidence{Object: w.Ref(), What: fmt.Sprintf("DaemonSet %s: %d of %d pods run its current template", name, w.Status.UpdatedNumberScheduled, all),
			Command: cmdGet("daemonset", ns, name, `{.spec.updateStrategy.type}{" "}{.status.updatedNumberScheduled}/{.status.desiredNumberScheduled}`)}
	default:
		return nil
	}
	if old <= 0 || all <= 0 {
		return nil
	}
	kind := strings.ToLower(w.Kind)
	return &Finding{Rule: "KD294", Title: "Template change waits for pods to be deleted (OnDelete)", Severity: Warning, Object: w.Ref(),
		Cause: fmt.Sprintf("%s %s's pod template has changed, and %d of its %d pods still run the old one: its updateStrategy is OnDelete, which replaces a pod only when the pod is deleted, so the change reaches none of them until someone does",
			w.Kind, name, old, all),
		Evidence: []Evidence{ev},
		Fix:      fmt.Sprintf("Delete the old pods one at a time (each comes back with the new template), or set updateStrategy type RollingUpdate on %s %s to have the controller do it: kubectl rollout status %s/%s then follows it.", w.Kind, name, kind, name)}
}

// partitionHolds finds a StatefulSet whose rolling update stops at its partition: only pods with an ordinal at or
// above it get the new template, and pods below keep the old one for as long as the partition stays. A partition is
// how a canary is staged; one left behind holds every later change back from those pods, and one at or above the
// replica count lets the change reach none.
func partitionHolds(w kube.Workload) *Finding {
	ru := w.Spec.UpdateStrategy.RollingUpdate
	if w.Kind != "StatefulSet" || w.Spec.UpdateStrategy.Type == "OnDelete" || ru == nil || ru.Partition == nil || *ru.Partition <= 0 {
		return nil
	}
	if w.Status.UpdateRevision == "" || w.Status.UpdateRevision == w.Status.CurrentRevision {
		return nil
	}
	part, all := *ru.Partition, w.Desired()
	old := all - w.Status.UpdatedReplicas
	if old <= 0 {
		return nil
	}
	ns, name := w.Metadata.Namespace, w.Metadata.Name
	held := fmt.Sprintf("pods %s-0 to %s-%d", name, name, min(part, all)-1)
	if min(part, all) == 1 {
		held = fmt.Sprintf("pod %s-0", name)
	}
	cause := fmt.Sprintf("StatefulSet %s's pod template has changed, and %d of its %d pods still run the old one: its rolling update has partition %d, so only pods with an ordinal of %d or more get the new template, and %s keep the old one", name, old, all, part, part, held)
	if part >= all {
		cause = fmt.Sprintf("StatefulSet %s's pod template has changed, and none of its %d pods runs it: its rolling update has partition %d, at or above its replica count, so the update reaches no pod", name, all, part)
	}
	return &Finding{Rule: "KD296", Title: "StatefulSet update stops at its partition", Severity: Warning, Object: w.Ref(),
		Cause: cause,
		Evidence: []Evidence{{Object: w.Ref(), What: fmt.Sprintf("StatefulSet %s: partition %d, current revision %s, update revision %s, %d of %d pods updated", name, part, w.Status.CurrentRevision, w.Status.UpdateRevision, w.Status.UpdatedReplicas, all),
			Command: cmdGet("statefulset", ns, name, `{.spec.updateStrategy}{" "}{.status.currentRevision}{" "}{.status.updateRevision}{" "}{.status.updatedReplicas}/{.status.replicas}`)}},
		Fix: fmt.Sprintf("Lower the partition to roll the change out further (0 updates every pod), once the pods above it look healthy; kubectl rollout status statefulset/%s follows it.", name)}
}

// deadlineTooShort finds a Deployment whose progressDeadlineSeconds is shorter than its new pods can take to count as
// available: the readiness probe's initialDelaySeconds (or the startup probe's, which runs first) plus
// minReadySeconds. Every rollout then makes no progress for longer than the deadline and is reported as failed
// (ProgressDeadlineExceeded, and kubectl rollout status fails a pipeline), though the pods come up fine.
func deadlineTooShort(w kube.Workload) *Finding {
	d := w.Spec.ProgressDeadlineSeconds
	if w.Kind != "Deployment" || d == nil {
		return nil
	}
	need, why := int32(0), ""
	for _, c := range w.Spec.Template.Spec.Containers {
		delay, kind := int32(0), ""
		if c.StartupProbe != nil {
			delay, kind = c.StartupProbe.InitialDelaySeconds, "startup"
		}
		if c.ReadinessProbe != nil && c.ReadinessProbe.InitialDelaySeconds > delay {
			delay, kind = c.ReadinessProbe.InitialDelaySeconds, "readiness"
		}
		if delay > need {
			need, why = delay, fmt.Sprintf("container %s's %s probe waits initialDelaySeconds %d", c.Name, kind, delay)
		}
	}
	if m := w.Spec.MinReadySeconds; m > 0 {
		need += m
		if why != "" {
			why += fmt.Sprintf(", then minReadySeconds %d", m)
		} else {
			why = fmt.Sprintf("minReadySeconds is %d", m)
		}
	}
	if need == 0 || *d >= need {
		return nil
	}
	ns, name := w.Metadata.Namespace, w.Metadata.Name
	return &Finding{Rule: "KD295", Title: "Rollout deadline is shorter than a pod takes to become available", Severity: Warning, Object: w.Ref(),
		Cause: fmt.Sprintf("Deployment %s's progressDeadlineSeconds is %d, and a new pod cannot count as available in under %ds (%s), so every rollout goes %ds without progress and is reported as failed (ProgressDeadlineExceeded), and kubectl rollout status fails, though the pods come up fine",
			name, *d, need, why, *d),
		Evidence: []Evidence{{Object: w.Ref(), What: fmt.Sprintf("Deployment %s: progressDeadlineSeconds %d, minReadySeconds %d, and its probes' initial delays", name, *d, w.Spec.MinReadySeconds),
			Command: cmdGet("deployment", ns, name, `{.spec.progressDeadlineSeconds}{" "}{.spec.minReadySeconds}{"\n"}{range .spec.template.spec.containers[*]}{.name}{" "}{.readinessProbe.initialDelaySeconds}{" "}{.startupProbe.initialDelaySeconds}{"\n"}{end}`)}},
		Fix: fmt.Sprintf("Raise progressDeadlineSeconds well above %ds (the default is 600), or shorten the probe's initialDelaySeconds: a startup probe lets a slow start finish without a long fixed delay.", need)}
}
