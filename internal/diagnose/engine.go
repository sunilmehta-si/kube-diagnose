package diagnose

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// Diagnose finds the root causes in a snapshot.
func Diagnose(s *snapshot.Snapshot) Report {
	ix := newIndex(s)
	r := Report{Context: s.Context, ServerVersion: s.ServerVersion, Namespaces: s.Namespaces,
		CollectedAt: s.CollectedAt.UTC().Format("2006-01-02 15:04 MST"), Gaps: s.Gaps,
		Checked: Checked{Pods: len(s.Pods), Services: len(s.Services), PVCs: len(s.PVCs), Nodes: len(s.Nodes)}}

	// Pods: one problem each, grouped by owner and cause.
	type group struct {
		owner kube.Ref
		probs []*problem
	}
	groups := map[string]*group{}
	var order []string
	links := map[kube.Ref][]kube.Ref{} // PVC -> pods waiting for it
	pods := append([]kube.Pod(nil), s.Pods...)
	sort.Slice(pods, func(i, j int) bool { return pods[i].Ref().String() < pods[j].Ref().String() })
	for _, p := range pods {
		pr := podProblem(ix, p)
		if pr == nil {
			continue
		}
		if pr.linkTo != nil {
			links[*pr.linkTo] = append(links[*pr.linkTo], p.Ref())
			continue
		}
		owner := ix.owner(p)
		k := owner.String() + "|" + pr.key
		if groups[k] == nil {
			groups[k] = &group{owner: owner}
			order = append(order, k)
		}
		groups[k].probs = append(groups[k].probs, pr)
	}
	explained := map[kube.Ref]bool{}
	podsTo := map[kube.Ref]int{} // pod -> index of the finding that explains it
	for _, k := range order {
		g := groups[k]
		f := fromProblems(ix, g.owner, g.probs)
		for _, pr := range g.probs {
			podsTo[pr.pod.Ref()] = len(r.Findings)
		}
		explained[g.owner] = true
		r.Findings = append(r.Findings, f)
	}

	// Storage: a pending claim is the root cause for the pods that wait for it.
	for _, f := range storageFindings(ix) {
		f.Affects = append(f.Affects, links[f.Object]...)
		delete(links, f.Object)
		r.Findings = append(r.Findings, f)
	}
	for claim, ps := range links { // a claim that is pending with nothing we can explain
		r.Findings = append(r.Findings, Finding{Rule: "KD143", Title: "Pod waits for a PersistentVolumeClaim", Severity: Critical,
			Object: claim, Cause: fmt.Sprintf("pods wait for PersistentVolumeClaim %s, which is not bound", claim.Name),
			Evidence: []Evidence{{Object: claim, What: "PersistentVolumeClaim is not bound", Command: cmdGet("pvc", claim.Namespace, claim.Name, "{.status}")},
				{Object: claim, What: "events", Command: cmdEvents(claim)}},
			Fix: "Read the claim's events: its StorageClass's provisioner reports why it has not created a volume.", Affects: ps})
	}

	for _, f := range controllerFindings(ix) {
		explained[f.Object] = true
		r.Findings = append(r.Findings, f)
	}

	// Services: root causes of their own, and Services left without endpoints by a pod problem.
	svcFindings, blocked := serviceFindings(ix)
	r.Findings = append(r.Findings, svcFindings...)
	for _, svc := range sortedRefs(blocked) {
		attached := false
		for _, pod := range blocked[svc] {
			if i, ok := podsTo[pod]; ok {
				addAffect(&r.Findings[i], svc)
				attached = true
			}
		}
		if !attached {
			r.Findings = append(r.Findings, noReadyEndpoints(ix, svc, blocked[svc]))
		}
	}

	r.Findings = append(r.Findings, rolloutFindings(ix, explained)...)
	r.Findings = append(r.Findings, nodeFindings(ix)...)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Object.String() < b.Object.String()
	})
	if r.Findings == nil {
		r.Findings = []Finding{}
	}
	return r
}

// fromProblems turns the problems of one owner's pods, which share a cause, into one finding on the owner.
func fromProblems(ix *index, owner kube.Ref, probs []*problem) Finding {
	first := probs[0]
	f := Finding{Rule: first.rule, Title: first.title, Severity: first.severity, Object: owner, Cause: first.cause,
		Evidence: first.evidence, Fix: first.fix}
	for _, pr := range probs {
		f.Affects = append(f.Affects, pr.pod.Ref())
	}
	if owner.Kind == "Pod" {
		f.Affects = nil
	}
	if w, ok := ix.workloads[owner]; ok {
		desired, ready := w.Desired(), w.Ready()
		if ready > 0 && f.Severity == Critical {
			f.Severity = Warning
		}
		if owner.Kind != "Pod" {
			f.Cause += fmt.Sprintf("; %s %s has %d of %d replicas ready", owner.Kind, owner.Name, ready, desired)
		}
	}
	return f
}

func addAffect(f *Finding, r kube.Ref) {
	for _, x := range f.Affects {
		if x == r {
			return
		}
	}
	f.Affects = append(f.Affects, r)
}

func noReadyEndpoints(ix *index, svc kube.Ref, pods []kube.Ref) Finding {
	names := make([]string, 0, len(pods))
	for _, p := range pods {
		names = append(names, p.Name)
	}
	return Finding{Rule: "KD162", Title: "Service has no ready pods", Severity: Critical, Object: svc,
		Cause: fmt.Sprintf("Service %s selects %d pods and none of them is ready (%s)", svc.Name, len(pods), strings.Join(names, ", ")),
		Evidence: []Evidence{{Object: svc, What: "selected pods are not ready",
			Command: fmt.Sprintf("kubectl get pods -n %s -o wide", svc.Namespace)}},
		Fix:     "Find why the selected pods are not ready (kubectl describe pod) and fix that; the Service recovers on its own.",
		Affects: pods}
}

func sortedRefs[V any](m map[kube.Ref]V) []kube.Ref {
	out := make([]kube.Ref, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
