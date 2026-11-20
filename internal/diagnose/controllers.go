package diagnose

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	reQuota         = regexp.MustCompile(`exceeded quota: ([^,]+), requested: ([^,]+(?:,[^,:]+)*), used: ([^,]+(?:,[^,:]+)*), limited: (.+)$`)
	reQuotaM        = regexp.MustCompile(`must specify ([^ ]+)`)
	reCreateClaim   = regexp.MustCompile(`^create Claim (\S+) for Pod \S+ in StatefulSet \S+ failed`)
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
	// A StatefulSet creates each pod's claims from its volumeClaimTemplates first; when that fails, the pod waits.
	claim := ""
	if m := reCreateClaim.FindStringSubmatch(msg); m != nil {
		claim = m[1]
	}
	switch {
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
	for _, j := range ix.s.Jobs {
		if f := suspendedJob(ix, j); f != nil && !explained[j.Ref()] {
			out = append(out, *f)
		} else if f := noParallelism(ix, j); f != nil && !explained[j.Ref()] {
			out = append(out, *f)
		}
	}
	for _, w := range ix.s.Workloads {
		if f := daemonSetNoNodes(ix, w); f != nil && !explained[w.Ref()] {
			out = append(out, *f)
		} else if f := sharedRWOClaim(ix, w); f != nil && !explained[w.Ref()] {
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
