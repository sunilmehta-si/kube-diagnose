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
// the request: the rule leaves out the verb, names the resource in another API group, or names it with a slip
// (configmap for configmaps). Nil when a Role grants the request in full (the
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
		if allows(r.APIGroups, d.group) && allows(r.Resources, d.resource) && !allows(r.Verbs, d.verb) {
			cause := fmt.Sprintf("%s. Role %s grants %s on %s, and not %s%s; its log says: %q",
				prefix, g.role.Metadata.Name, strings.Join(r.Verbs, ", "), d.resource, d.verb, verbNote(d.verb, r.Verbs), clip(d.line, 200))
			fix := fmt.Sprintf("Add %q to the verbs of the rule of Role %s that names %s.", d.verb, g.role.Metadata.Name, d.resource)
			return newProblem(p, cs.Name, "KD302", "Role grants the resource but not the verb", Critical, cause,
				"rbacverb|"+g.role.Metadata.Name+"|"+d.res()+"|"+d.verb, fix, append(ev, roleEvidence(g), bindingEvidence(g.binding))...)
		}
	}
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
	for _, g := range here {
		r := g.rule
		if !allows(r.APIGroups, d.group) || !allows(r.Verbs, d.verb) {
			continue
		}
		for _, name := range r.Resources {
			if !resourceLike(name, d.resource) {
				continue
			}
			cause := fmt.Sprintf("%s. Role %s grants %s on resource %q, and the API has no resource by that name: it is %q (resource names are lower case and plural), so the rule never matches; its log says: %q",
				prefix, g.role.Metadata.Name, strings.Join(r.Verbs, ", "), name, d.resource, clip(d.line, 200))
			fix := fmt.Sprintf("Write %q for %q in the resources of Role %s (kubectl api-resources lists the names).", d.resource, name, g.role.Metadata.Name)
			return newProblem(p, cs.Name, "KD301", "Role names a resource that does not exist", Critical, cause,
				"rbacname|"+g.role.Metadata.Name+"|"+name, fix, append(ev, roleEvidence(g), bindingEvidence(g.binding))...)
		}
	}
	return nil
}

// verbNote explains a verb that is easy to leave out.
func verbNote(verb string, have []string) string {
	switch {
	case verb == "list" && allows(have, "get"):
		return " (get reads one object by name; reading them all is list)"
	case verb == "watch":
		return " (a client that follows changes, as an informer or kubectl get --watch does, lists and then watches)"
	}
	return ""
}

// resourceLike reports whether a Role's resource name is a slip for the one the API uses: another case, the singular,
// the kind ("ConfigMap"), one letter off, or two letters swapped.
func resourceLike(have, want string) bool {
	if have == want || have == "*" {
		return false
	}
	lw, lh := strings.ToLower(want), strings.ToLower(have)
	if lh == lw || lh+"s" == lw || lh+"es" == lw || strings.TrimSuffix(lw, "ies")+"y" == lh {
		return true
	}
	return len(want) >= 5 && (editDistance(lh, lw) == 1 || swapped(lh, lw))
}

// swapped reports whether b is a with two neighbouring letters exchanged.
func swapped(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i+1 < len(a); i++ {
		if a[i] != b[i] {
			return a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
		}
	}
	return false
}

// editDistance counts the letters to insert, delete or change to turn a into b.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
