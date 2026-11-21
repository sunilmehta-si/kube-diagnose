package diagnose

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// pdbFindings reports PodDisruptionBudgets that allow no voluntary disruption while every pod they cover is
// healthy: the budget itself forbids evictions, so draining a node or upgrading the cluster waits on it forever.
// A budget at zero because pods are unhealthy is left to the findings about those pods.
func pdbFindings(ix *index) []Finding {
	out := pdbOverlap(ix)
	for _, b := range ix.s.PDBs {
		if f := pdbSelectsNothing(ix, b); f != nil {
			out = append(out, *f)
			continue
		}
		st := b.Status
		if st.ExpectedPods == 0 || st.DisruptionsAllowed > 0 || st.CurrentHealthy < st.DesiredHealthy || st.CurrentHealthy < st.ExpectedPods {
			continue
		}
		bound := "its bounds"
		switch {
		case b.Spec.MaxUnavailable != nil:
			bound = "maxUnavailable " + b.Spec.MaxUnavailable.String()
		case b.Spec.MinAvailable != nil:
			bound = "minAvailable " + b.Spec.MinAvailable.String()
		}
		out = append(out, Finding{Rule: "KD185", Title: "PodDisruptionBudget allows no disruptions", Severity: Warning, Object: b.Ref(),
			Cause: fmt.Sprintf("PodDisruptionBudget %s allows 0 disruptions with all %d of its pods healthy (%s), so evicting any of them, as a node drain or cluster upgrade does, waits forever",
				b.Metadata.Name, st.ExpectedPods, bound),
			Evidence: []Evidence{{Object: b.Ref(),
				What:    fmt.Sprintf("disruptionsAllowed 0, currentHealthy %d, desiredHealthy %d, expectedPods %d", st.CurrentHealthy, st.DesiredHealthy, st.ExpectedPods),
				Command: cmdGet("pdb", b.Metadata.Namespace, b.Metadata.Name, "{.spec}{\"\\n\"}{.status}")}},
			Fix: "Allow at least one disruption: lower minAvailable below the replica count, set maxUnavailable to 1 or more, or run more replicas."})
	}
	return out
}

// pdbSelectsNothing reports a PodDisruptionBudget whose selector matches no pod and no workload's pod template: it
// protects nothing, usually because its labels do not match the pods it was written for. A nil selector selects no
// pods in policy/v1.
func pdbSelectsNothing(ix *index, b kube.PodDisruptionBudget) *Finding {
	if b.Status.ExpectedPods != 0 {
		return nil
	}
	ns := b.Metadata.Namespace
	if b.Spec.Selector != nil {
		for _, p := range ix.s.Pods {
			if p.Metadata.Namespace == ns && b.Spec.Selector.Matches(p.Metadata.Labels) {
				return nil
			}
		}
		for _, w := range ix.s.Workloads {
			if w.Metadata.Namespace == ns && b.Spec.Selector.Matches(w.Spec.Template.Metadata.Labels) {
				return nil
			}
		}
	}
	sel := "no selector"
	cause := fmt.Sprintf("PodDisruptionBudget %s has no selector, so it covers no pods and protects nothing from evictions", b.Metadata.Name)
	fix := "Give the budget a selector that matches the pods it should protect."
	if b.Spec.Selector != nil {
		sel = "selector " + selectorString(*b.Spec.Selector)
		cause = fmt.Sprintf("PodDisruptionBudget %s selects pods with %s, and no pod or workload in namespace %s has those labels, so it protects nothing from evictions",
			b.Metadata.Name, selectorString(*b.Spec.Selector), ns)
		if near := nearestLabels(ix, ns, b.Spec.Selector.MatchLabels); near != "" {
			cause += fmt.Sprintf(" (the closest pod labels are %s)", near)
			fix = fmt.Sprintf("Change the budget's selector to match the pods it should protect (%s).", near)
		}
	}
	return &Finding{Rule: "KD186", Title: "PodDisruptionBudget selects no pods", Severity: Warning, Object: b.Ref(), Cause: cause,
		Evidence: []Evidence{{Object: b.Ref(), What: fmt.Sprintf("the budget has %s and expects 0 pods", sel),
			Command: cmdGet("pdb", ns, b.Metadata.Name, "{.spec.selector}{\"\\n\"}{.status.expectedPods}")},
			{Object: kube.Ref{Kind: "Pod", Namespace: ns, Name: "*"}, What: "pod labels in the namespace", Command: "kubectl get pods -n " + ns + " --show-labels"}},
		Fix: fix}
}

// pdbOverlap reports pods that more than one PodDisruptionBudget covers. The eviction API refuses such a pod
// outright ("This pod has more than one PodDisruptionBudget, which the eviction subresource does not support"), so
// a node drain fails on it however many disruptions each budget allows. Nothing shows it until a drain.
func pdbOverlap(ix *index) []Finding {
	type group struct {
		budgets []kube.PodDisruptionBudget
		pods    []kube.Pod
	}
	groups := map[string]*group{}
	for _, p := range ix.s.Pods {
		if p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" || p.Metadata.DeletionTimestamp != nil {
			continue
		}
		var covering []kube.PodDisruptionBudget
		for _, b := range ix.s.PDBs {
			if b.Metadata.Namespace == p.Metadata.Namespace && b.Spec.Selector != nil && b.Spec.Selector.Matches(p.Metadata.Labels) {
				covering = append(covering, b)
			}
		}
		if len(covering) < 2 {
			continue
		}
		sort.Slice(covering, func(i, j int) bool { return covering[i].Metadata.Name < covering[j].Metadata.Name })
		key := p.Metadata.Namespace
		for _, b := range covering {
			key += "/" + b.Metadata.Name
		}
		if groups[key] == nil {
			groups[key] = &group{budgets: covering}
		}
		groups[key].pods = append(groups[key].pods, p)
	}
	var out []Finding
	for _, key := range sortedKeys(groups) {
		g := groups[key]
		first, ns := g.budgets[0], g.budgets[0].Metadata.Namespace
		var names []string
		ev := []Evidence{}
		for _, b := range g.budgets {
			names = append(names, b.Metadata.Name)
			ev = append(ev, Evidence{Object: b.Ref(), What: fmt.Sprintf("budget %s selects pods with %s", b.Metadata.Name, selectorString(*b.Spec.Selector)),
				Command: cmdGet("pdb", ns, b.Metadata.Name, "{.spec.selector}")})
		}
		sample := g.pods[0]
		ev = append(ev, Evidence{Object: sample.Ref(), What: fmt.Sprintf("pod %s has labels %s, which every one of those selectors matches", sample.Metadata.Name, kube.FormatMap(sample.Metadata.Labels)),
			Command: cmdGet("pod", ns, sample.Metadata.Name, "{.metadata.labels}")})
		f := Finding{Rule: "KD289", Title: "Pods are covered by more than one PodDisruptionBudget", Severity: Warning, Object: first.Ref(),
			Cause: fmt.Sprintf("PodDisruptionBudgets %s all select %s (%s for one): the eviction API refuses a pod that more than one budget covers, so a node drain or cluster upgrade fails on these pods whatever the budgets allow",
				strings.Join(names, " and "), plural(len(g.pods), "pod"), sample.Metadata.Name),
			Evidence: ev,
			Fix:      "Leave each pod under one budget: delete the extra PodDisruptionBudget, or narrow the selectors so they no longer match the same pods."}
		for _, p := range g.pods {
			if o := ix.owner(p); o.Kind != "Pod" && !containsRef(f.Affects, o) {
				f.Affects = append(f.Affects, o)
			}
		}
		out = append(out, f)
	}
	return out
}

func containsRef(rs []kube.Ref, r kube.Ref) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}
