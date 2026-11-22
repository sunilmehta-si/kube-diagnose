package diagnose

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

const (
	rolesResource    = "roles.rbac.authorization.k8s.io"
	bindingsResource = "rolebindings.rbac.authorization.k8s.io"
)

// reHTTPForbidden matches a client that reports the status and not the API server's sentence, as wget and curl do.
var reHTTPForbidden = regexp.MustCompile(`(?i)\b403\b.*forbidden|forbidden.*\b403\b`)

// apiDenied returns the log line in which the API server refuses the container's request: its own sentence (User
// "system:serviceaccount:..." cannot ...), or a bare 403 Forbidden from a container that talks to the API server.
func apiDenied(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string) (string, bool) {
	for i := len(lines) - 1; i >= 0; i-- {
		if reForbidden.MatchString(lines[i]) {
			return lines[i], true
		}
	}
	c, _ := containerSpec(p, cs.Name)
	cmd := strings.Join(append(append([]string{}, c.Command...), c.Args...), " ")
	api := strings.Contains(cmd, "kubernetes.default") || strings.Contains(cmd, "KUBERNETES_SERVICE_HOST")
	for _, l := range lines {
		if m := reConnecting.FindStringSubmatch(l); m != nil {
			port, _ := strconv.Atoi(m[3])
			api = api || apiServerHost(ix, m[1], int32(port)) || apiServerHost(ix, m[2], int32(port))
		}
	}
	if !api {
		return "", false
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if reHTTPForbidden.MatchString(lines[i]) {
			return lines[i], true
		}
	}
	return "", false
}

// roleMissing reports whether the Role or ClusterRole a binding grants does not exist, and what does: the Roles of
// the namespace. A binding to a role that does not exist is accepted by the API and grants nothing.
func roleMissing(ix *index, b kube.RoleBinding) (missing bool, have []string) {
	switch b.RoleRef.Kind {
	case "Role":
		if !ix.read(rolesResource) {
			return false, nil
		}
		for _, r := range ix.s.Roles {
			if r.Metadata.Namespace != b.Metadata.Namespace {
				continue
			}
			if r.Metadata.Name == b.RoleRef.Name {
				return false, nil
			}
			have = append(have, r.Metadata.Name)
		}
		sort.Strings(have)
		return true, have
	case "ClusterRole":
		if len(ix.s.ClusterRoles) == 0 {
			return false, nil // not read
		}
		for _, n := range ix.s.ClusterRoles {
			if n == b.RoleRef.Name {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

// grantsTo reports whether a binding names the ServiceAccount.
func grantsTo(b kube.RoleBinding, ns, sa string) bool {
	for _, s := range b.Subjects {
		if s.Kind == "ServiceAccount" && s.Name == sa && (s.Namespace == ns || s.Namespace == "") {
			return true
		}
	}
	return false
}

// missingSubject returns the first ServiceAccount of the binding's own namespace that a binding names and that does
// not exist.
func missingSubject(ix *index, b kube.RoleBinding) (string, bool) {
	if !ix.read("serviceaccounts") {
		return "", false
	}
	ns := b.Metadata.Namespace
	for _, s := range b.Subjects {
		if s.Kind == "ServiceAccount" && (s.Namespace == ns || s.Namespace == "") && s.Name != "default" && !ix.sas[nsName{ns, s.Name}] {
			return s.Name, true
		}
	}
	return "", false
}

func subjectNames(b kube.RoleBinding) string {
	var out []string
	for _, s := range b.Subjects {
		out = append(out, s.Kind+" "+s.Name)
	}
	if len(out) == 0 {
		return "no subjects"
	}
	return strings.Join(out, ", ")
}

func roleMissingText(b kube.RoleBinding, have []string) (cause, fix string) {
	ns, role := b.Metadata.Namespace, b.RoleRef.Name
	where := "in namespace " + ns
	exist := "the namespace has no Roles"
	if len(have) > 0 {
		exist = "the namespace's Roles are " + strings.Join(have, ", ")
	}
	if b.RoleRef.Kind == "ClusterRole" {
		where, exist = "in the cluster", ""
	}
	cause = fmt.Sprintf("RoleBinding %s grants %s %s to %s, and there is no %s %s %s, so the binding grants nothing", b.Metadata.Name, b.RoleRef.Kind, role, subjectNames(b), b.RoleRef.Kind, role, where)
	if exist != "" {
		cause += " (" + exist + ")"
	}
	fix = fmt.Sprintf("Create %s %s, or bind the %s that was meant: a binding's roleRef cannot be changed, so delete RoleBinding %s and create it again with the right name.", b.RoleRef.Kind, role, b.RoleRef.Kind, b.Metadata.Name)
	return cause, fix
}

func bindingEvidence(b kube.RoleBinding) Evidence {
	return Evidence{Object: b.Ref(), What: fmt.Sprintf("RoleBinding %s grants %s %s to %s", b.Metadata.Name, b.RoleRef.Kind, b.RoleRef.Name, subjectNames(b)),
		Command: cmdGet("rolebinding", b.Metadata.Namespace, b.Metadata.Name, `{.roleRef.kind}{"/"}{.roleRef.name}{" "}{.subjects}`)}
}

// rbacFindings reports RoleBindings that cannot grant anything: one that grants a Role or ClusterRole which does
// not exist, and one whose subject is a ServiceAccount which does not exist. The API accepts both.
func rbacFindings(ix *index) []Finding {
	var out []Finding
	for _, b := range ix.s.RoleBindings {
		ns := b.Metadata.Namespace
		if missing, have := roleMissing(ix, b); missing {
			cause, fix := roleMissingText(b, have)
			kind := strings.ToLower(b.RoleRef.Kind) + "s"
			out = append(out, Finding{Rule: "KD227", Title: "RoleBinding grants a Role that does not exist", Severity: Warning, Object: b.Ref(), Cause: cause, Fix: fix,
				Evidence: []Evidence{bindingEvidence(b), {Object: kube.Ref{Kind: b.RoleRef.Kind, Namespace: ns, Name: b.RoleRef.Name},
					What: fmt.Sprintf("there is no %s %s", b.RoleRef.Kind, b.RoleRef.Name), Command: "kubectl get " + kind + nsFlagFor(b)}}})
			continue
		}
		if sa, ok := missingSubject(ix, b); ok {
			out = append(out, Finding{Rule: "KD228", Title: "RoleBinding names a ServiceAccount that does not exist", Severity: Warning, Object: b.Ref(),
				Cause: fmt.Sprintf("RoleBinding %s grants %s %s to ServiceAccount %s, and there is no ServiceAccount %s in namespace %s, so nothing receives the permission%s",
					b.Metadata.Name, b.RoleRef.Kind, b.RoleRef.Name, sa, sa, ns, unboundAccounts(ix, ns)),
				Fix: fmt.Sprintf("Set the subject of RoleBinding %s to the ServiceAccount the pods run as (a binding's subjects can be edited), or create ServiceAccount %s and run the pods as it.", b.Metadata.Name, sa),
				Evidence: []Evidence{bindingEvidence(b), {Object: kube.Ref{Kind: "ServiceAccount", Namespace: ns, Name: sa},
					What: "there is no ServiceAccount " + sa, Command: "kubectl get serviceaccounts -n " + ns}}})
		}
	}
	return out
}

func nsFlagFor(b kube.RoleBinding) string {
	if b.RoleRef.Kind == "ClusterRole" {
		return ""
	}
	return " -n " + b.Metadata.Namespace
}

// unboundAccounts names the ServiceAccounts that pods of the namespace run as and that no RoleBinding of the
// namespace names: where a binding with a mistyped subject was most likely meant to go.
func unboundAccounts(ix *index, ns string) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ix.s.Pods {
		sa := p.Spec.ServiceAccountName
		if p.Metadata.Namespace != ns || sa == "" || sa == "default" || seen[sa] {
			continue
		}
		seen[sa] = true
		bound := false
		for _, b := range ix.s.RoleBindings {
			bound = bound || b.Metadata.Namespace == ns && grantsTo(b, ns, sa)
		}
		if !bound {
			out = append(out, sa)
		}
	}
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	return fmt.Sprintf("; pods here run as ServiceAccount %s, which no RoleBinding of the namespace names", strings.Join(out, ", "))
}

// rbacBroken finds a container that the API server refuses while a RoleBinding meant for its ServiceAccount cannot
// grant anything: the binding names a Role that does not exist, or, when no binding names the pod's ServiceAccount,
// one names a ServiceAccount that does not exist. The binding is the cause, and the fix goes there.
func rbacBroken(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	if len(ix.s.RoleBindings) == 0 {
		return nil
	}
	line, ok := apiDenied(ix, p, cs, lines)
	if !ok {
		return nil
	}
	ns := p.Metadata.Namespace
	sa := p.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	named := false
	for _, b := range ix.s.RoleBindings {
		if b.Metadata.Namespace != ns || !grantsTo(b, ns, sa) {
			continue
		}
		named = true
		if missing, have := roleMissing(ix, b); missing {
			cause, fix := roleMissingText(b, have)
			return newProblem(p, cs.Name, "KD227", "RoleBinding grants a Role that does not exist", Critical,
				fmt.Sprintf("container %s exits because the API server refuses its ServiceAccount %s: %s; its log says: %q", cs.Name, sa, cause, clip(line, 200)),
				"rbacrole|"+b.Metadata.Name, fix, append(ev, bindingEvidence(b))...)
		}
	}
	if named {
		return nil
	}
	for _, b := range ix.s.RoleBindings {
		if b.Metadata.Namespace != ns {
			continue
		}
		if ghost, ok := missingSubject(ix, b); ok {
			return newProblem(p, cs.Name, "KD228", "RoleBinding names a ServiceAccount that does not exist", Critical,
				fmt.Sprintf("container %s exits because the API server refuses its ServiceAccount %s, which no RoleBinding of namespace %s names: RoleBinding %s grants %s %s to ServiceAccount %s, and there is no ServiceAccount %s, so nothing receives the permission; its log says: %q",
					cs.Name, sa, ns, b.Metadata.Name, b.RoleRef.Kind, b.RoleRef.Name, ghost, ghost, clip(line, 200)),
				"rbacsubject|"+b.Metadata.Name,
				fmt.Sprintf("Set the subject of RoleBinding %s to ServiceAccount %s (a binding's subjects can be edited), if that is who it was meant for; or run the pods as ServiceAccount %s after creating it.", b.Metadata.Name, sa, ghost),
				append(ev, bindingEvidence(b), Evidence{Object: p.Ref(), What: "the pod runs as ServiceAccount " + sa, Command: cmdGet("pod", ns, p.Metadata.Name, "{.spec.serviceAccountName}")})...)
		}
	}
	return nil
}
