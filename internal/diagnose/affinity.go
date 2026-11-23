package diagnose

import (
	"fmt"
	"sort"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// nodesWith counts the nodes that carry a label, and returns the values they give it.
func nodesWith(ix *index, key string) (n int, values []string) {
	seen := map[string]bool{}
	for _, node := range ix.s.Nodes {
		if v, ok := node.Metadata.Labels[key]; ok {
			n++
			if !seen[v] {
				seen[v] = true
				values = append(values, v)
			}
		}
	}
	sort.Strings(values)
	return n, values
}

// spreadKeyMissing finds a pod the scheduler places nowhere because a topology spread constraint that must hold
// (DoNotSchedule) spreads over a node label no node has: the scheduler then rejects every node. Cloud nodes get
// topology.kubernetes.io/zone from their provider; kind, bare-metal and many on-premises nodes do not.
func spreadKeyMissing(ix *index, p kube.Pod) *problem {
	if !ix.read("nodes") || len(ix.s.Nodes) == 0 {
		return nil
	}
	for _, c := range p.Spec.TopologySpreadConstraints {
		if c.WhenUnsatisfiable == "ScheduleAnyway" || c.TopologyKey == "" {
			continue
		}
		if n, _ := nodesWith(ix, c.TopologyKey); n > 0 {
			continue
		}
		cause := fmt.Sprintf("its topologySpreadConstraints spread it over %s (whenUnsatisfiable: DoNotSchedule), and none of the %s has that label, so the scheduler rejects them all",
			c.TopologyKey, plural(len(ix.s.Nodes), "node"))
		fix := fmt.Sprintf("Label the nodes with %s (cloud providers set the zone labels; kind and bare-metal nodes have none), spread over a label the nodes have, such as kubernetes.io/hostname, or set whenUnsatisfiable: ScheduleAnyway.", c.TopologyKey)
		return newProblem(p, "", "KD245", "Spread constraint's topology key is on no node", Critical, cause, "spreadkey|"+c.TopologyKey, fix,
			Evidence{Object: p.Ref(), What: fmt.Sprintf("topologySpreadConstraints: topologyKey %s, maxSkew %d", c.TopologyKey, c.MaxSkew),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.topologySpreadConstraints}")},
			Evidence{Object: kube.Ref{Kind: "Node", Name: "*"}, What: fmt.Sprintf("none of the %s has the label %s", plural(len(ix.s.Nodes), "node"), c.TopologyKey),
				Command: "kubectl get nodes -L " + c.TopologyKey})
	}
	return nil
}
