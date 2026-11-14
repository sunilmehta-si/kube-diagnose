package diagnose

import "fmt"

// pdbFindings reports PodDisruptionBudgets that allow no voluntary disruption while every pod they cover is
// healthy: the budget itself forbids evictions, so draining a node or upgrading the cluster waits on it forever.
// A budget at zero because pods are unhealthy is left to the findings about those pods.
func pdbFindings(ix *index) []Finding {
	var out []Finding
	for _, b := range ix.s.PDBs {
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
