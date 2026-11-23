package diagnose

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// denial is the API server's refusal as a client prints it: who was refused what, and where. ns is empty for a
// request at the cluster scope.
type denial struct {
	line                            string
	saNS, sa, verb, resource, group string
	ns                              string
}

func (d denial) res() string {
	if d.group == "" {
		return d.resource
	}
	return d.resource + "." + d.group
}

func (d denial) scope() string {
	if d.ns == "" {
		return "across the cluster"
	}
	return "in namespace " + d.ns
}

// lastDenial returns the newest log line with the API server's RBAC refusal.
func lastDenial(lines []string) (denial, bool) {
	for i := len(lines) - 1; i >= 0; i-- {
		if m := reForbidden.FindStringSubmatch(lines[i]); m != nil {
			return denial{line: lines[i], saNS: m[1], sa: m[2], verb: m[3], resource: m[4], group: m[5], ns: m[6]}, true
		}
	}
	return denial{}, false
}

// grant is one rule of a Role, and the binding that gives it to a ServiceAccount. A binding grants only in its own
// namespace.
type grant struct {
	binding kube.RoleBinding
	role    kube.Role
	rule    kube.PolicyRule
}

func (g grant) ns() string { return g.binding.Metadata.Namespace }

// namesAccount reports whether a binding names ServiceAccount saNS/sa; a subject with no namespace is in the
// binding's own.
func namesAccount(b kube.RoleBinding, saNS, sa string) bool {
	for _, s := range b.Subjects {
		ns := s.Namespace
		if ns == "" {
			ns = b.Metadata.Namespace
		}
		if s.Kind == "ServiceAccount" && s.Name == sa && ns == saNS {
			return true
		}
	}
	return false
}

// grantsOf returns the rules of every Role bound to ServiceAccount saNS/sa, in the namespaces read. ClusterRoles are
// read by name only, so their rules are not among them.
func grantsOf(ix *index, saNS, sa string) []grant {
	var out []grant
	for _, b := range ix.s.RoleBindings {
		if b.RoleRef.Kind != "Role" || !namesAccount(b, saNS, sa) {
			continue
		}
		for _, r := range ix.s.Roles {
			if r.Metadata.Namespace != b.Metadata.Namespace || r.Metadata.Name != b.RoleRef.Name {
				continue
			}
			for _, rule := range r.Rules {
				out = append(out, grant{binding: b, role: r, rule: rule})
			}
		}
	}
	return out
}

// allows reports whether a rule's list holds the value or the wildcard.
func allows(list []string, v string) bool {
	for _, x := range list {
		if x == v || x == "*" {
			return true
		}
	}
	return false
}

func quoted(list []string) string {
	q := make([]string, len(list))
	for i, x := range list {
		q[i] = fmt.Sprintf("%q", x)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func roleEvidence(g grant) Evidence {
	return Evidence{Object: kube.Ref{Kind: "Role", Namespace: g.ns(), Name: g.role.Metadata.Name},
		What:    fmt.Sprintf("Role %s, bound by RoleBinding %s: apiGroups %s, resources %s, verbs %s", g.role.Metadata.Name, g.binding.Metadata.Name, quoted(g.rule.APIGroups), quoted(g.rule.Resources), quoted(g.rule.Verbs)),
		Command: cmdGet("role", g.ns(), g.role.Metadata.Name, "{.rules}")}
}

// groupName says which API group a resource is in, as people write it.
func groupName(g string) string {
	if g == "" {
		return `the core group ""`
	}
	return fmt.Sprintf("API group %q", g)
}

// grantNearMiss finds a container that the API server refuses while a Role bound to its ServiceAccount nearly grants
// the request: the rule names the resource in another API group. Nil when a Role grants the request in full (the
// refusal is then something else) or nothing comes near it (KD126 names what to grant).
func grantNearMiss(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	d, ok := lastDenial(lines)
	if !ok || !ix.read(rolesResource) || !ix.read(bindingsResource) {
		return nil
	}
	gs := grantsOf(ix, d.saNS, d.sa)
	var here []grant
	for _, g := range gs {
		if g.ns() != d.ns {
			continue
		}
		r := g.rule
		if allows(r.APIGroups, d.group) && allows(r.Resources, d.resource) && allows(r.Verbs, d.verb) && len(r.ResourceNames) == 0 {
			return nil
		}
		here = append(here, g)
	}
	sort.SliceStable(here, func(i, j int) bool { return here[i].role.Metadata.Name < here[j].role.Metadata.Name })
	prefix := fmt.Sprintf("container %s exits because the API server refuses its ServiceAccount %s: it may not %s %s %s", cs.Name, d.sa, d.verb, d.res(), d.scope())
	for _, g := range here {
		r := g.rule
		if allows(r.Resources, d.resource) && allows(r.Verbs, d.verb) && !allows(r.APIGroups, d.group) {
			cause := fmt.Sprintf("%s. Role %s grants %s on %s, but in apiGroups %s, and %s are in %s, so the rule never matches; its log says: %q",
				prefix, g.role.Metadata.Name, strings.Join(r.Verbs, ", "), d.resource, quoted(r.APIGroups), d.resource, groupName(d.group), clip(d.line, 200))
			fix := fmt.Sprintf("Set apiGroups to [%q] in the rule of Role %s that names %s (kubectl api-resources shows each resource's group).", d.group, g.role.Metadata.Name, d.resource)
			return newProblem(p, cs.Name, "KD300", "Role grants the resource in another API group", Critical, cause,
				"rbacgroup|"+g.role.Metadata.Name+"|"+d.res(), fix, append(ev, roleEvidence(g), bindingEvidence(g.binding))...)
		}
	}
	return nil
}
