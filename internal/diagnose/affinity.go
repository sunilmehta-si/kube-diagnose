package diagnose

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

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

// affinity is the part of a pod's affinity the rules read: the required terms.
type affinity struct {
	NodeAffinity *struct {
		Required *struct {
			Terms []struct {
				MatchExpressions []kube.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
			} `json:"nodeSelectorTerms"`
		} `json:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
	} `json:"nodeAffinity,omitempty"`
	PodAffinity *struct {
		Required []podAffinityTerm `json:"requiredDuringSchedulingIgnoredDuringExecution,omitempty"`
	} `json:"podAffinity,omitempty"`
}

type podAffinityTerm struct {
	LabelSelector     *kube.LabelSelector `json:"labelSelector,omitempty"`
	Namespaces        []string            `json:"namespaces,omitempty"`
	NamespaceSelector *kube.LabelSelector `json:"namespaceSelector,omitempty"`
	TopologyKey       string              `json:"topologyKey"`
}

func affinityOf(p kube.Pod) affinity {
	var a affinity
	if len(p.Spec.Affinity) > 0 {
		_ = json.Unmarshal(p.Spec.Affinity, &a)
	}
	return a
}

// formatSelector writes a label selector as kubectl -l takes it.
func formatSelector(s kube.LabelSelector) string {
	var parts []string
	if len(s.MatchLabels) > 0 {
		parts = append(parts, kube.FormatMap(s.MatchLabels))
	}
	for _, e := range s.MatchExpressions {
		switch e.Operator {
		case "Exists":
			parts = append(parts, e.Key)
		case "DoesNotExist":
			parts = append(parts, "!"+e.Key)
		default:
			parts = append(parts, fmt.Sprintf("%s %s (%s)", e.Key, strings.ToLower(e.Operator), strings.Join(e.Values, ",")))
		}
	}
	return strings.Join(parts, ",")
}

// affinityPodsMissing finds a pod the scheduler places nowhere because a required podAffinity term asks for pods
// that no namespace it looks in has. The scheduler lets the first pod of a group start when it matches its own
// term; a pod that does not wait for pods that never come. Terms with a namespaceSelector, or in namespaces not
// read, are left alone.
func affinityPodsMissing(ix *index, p kube.Pod) *problem {
	a := affinityOf(p)
	if a.PodAffinity == nil {
		return nil
	}
	for _, t := range a.PodAffinity.Required {
		if t.LabelSelector == nil || t.NamespaceSelector != nil {
			continue
		}
		nss := t.Namespaces
		if len(nss) == 0 {
			nss = []string{p.Metadata.Namespace}
		}
		read := true
		for _, ns := range nss {
			read = read && ix.nsRead(ns)
		}
		if !read || t.LabelSelector.Matches(p.Metadata.Labels) {
			continue
		}
		found := false
		for _, q := range ix.s.Pods {
			if slices.Contains(nss, q.Metadata.Namespace) && t.LabelSelector.Matches(q.Metadata.Labels) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		sel := formatSelector(*t.LabelSelector)
		where := "namespace " + strings.Join(nss, ", ")
		cause := fmt.Sprintf("its required podAffinity places it only beside pods labelled %s (topologyKey %s), and %s has no such pod, so no node qualifies", sel, t.TopologyKey, where)
		if near := otherPodsLabels(ix, p, nss, t.LabelSelector.MatchLabels); near != "" {
			cause += " (the other pods there have " + near + ")"
		}
		fix := "Correct the podAffinity selector to the labels the pods it should run beside carry, start those pods first, or make the rule preferredDuringSchedulingIgnoredDuringExecution so the pod can run without them."
		return newProblem(p, "", "KD246", "Pod affinity requires pods that do not exist", Critical, cause, "affinitypods|"+sel, fix,
			Evidence{Object: p.Ref(), What: fmt.Sprintf("required podAffinity: pods labelled %s, topologyKey %s", sel, t.TopologyKey),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, "{.spec.affinity.podAffinity}")},
			Evidence{Object: kube.Ref{Kind: "Pod", Namespace: nss[0], Name: "*"}, What: fmt.Sprintf("no pod in %s is labelled %s", where, sel),
				Command: fmt.Sprintf("kubectl get pods -n %s -l '%s' --show-labels", nss[0], sel)})
	}
	return nil
}

// nodeAffinityUnmet describes the expressions of a pod's required node affinity that no node meets, with the values
// the nodes do give those labels: "kubernetes.io/arch in (arm64), and the nodes have amd64". Each term is an
// alternative, so every term is described. Empty when nodes were not read, a term uses Gt or Lt, or some node meets
// every expression of a term (the pod is then held by something else).
func nodeAffinityUnmet(ix *index, p kube.Pod) string {
	a := affinityOf(p)
	if a.NodeAffinity == nil || a.NodeAffinity.Required == nil || !ix.read("nodes") || len(ix.s.Nodes) == 0 {
		return ""
	}
	var terms []string
	for _, t := range a.NodeAffinity.Required.Terms {
		var unmet []string
		for _, e := range t.MatchExpressions {
			if e.Operator == "Gt" || e.Operator == "Lt" {
				return ""
			}
			sel := kube.LabelSelector{MatchExpressions: []kube.LabelSelectorRequirement{e}}
			met := false
			for _, n := range ix.s.Nodes {
				met = met || sel.Matches(n.Metadata.Labels)
			}
			if met {
				continue
			}
			desc := formatSelector(sel)
			switch _, values := nodesWith(ix, e.Key); {
			case len(values) == 0:
				desc += ", a label no node has"
			case len(values) <= 4:
				desc += ", and the nodes have " + strings.Join(values, ", ")
			}
			unmet = append(unmet, desc)
		}
		if len(unmet) == 0 {
			return "" // a node meets this term on its own; the expressions together, or something else, rule it out
		}
		terms = append(terms, strings.Join(unmet, "; "))
	}
	return strings.Join(terms, "; or ")
}

// otherPodsLabels lists the values that the pods of the namespaces, other than the pod's own workload, give the
// selector's keys: what a mistyped selector was most likely meant to say. Only the selector's keys are shown, so
// labels the controllers add (pod-template-hash) stay out.
func otherPodsLabels(ix *index, p kube.Pod, nss []string, sel map[string]string) string {
	if len(sel) == 0 {
		return ""
	}
	own := ix.owner(p)
	seen := map[string]bool{}
	var out []string
	for _, q := range ix.s.Pods {
		if !slices.Contains(nss, q.Metadata.Namespace) || ix.owner(q) == own {
			continue
		}
		vals := map[string]string{}
		for k := range sel {
			if v, ok := q.Metadata.Labels[k]; ok {
				vals[k] = v
			}
		}
		if s := kube.FormatMap(vals); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) > 4 {
		out = out[:4]
	}
	return strings.Join(out, "; ")
}
