package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// reVarRef is a $(NAME) reference in a container's command or args; $$(NAME) is an escaped one, left alone.
var reVarRef = regexp.MustCompile(`(^|[^$])\$\(([A-Za-z_][A-Za-z0-9_]*)\)`)

// undefinedVar finds a container that fails because its command or args refer to $(NAME) and the container defines
// no variable NAME. The kubelet expands $(NAME) only from the container's env and envFrom, not from the image's ENV,
// and leaves an unknown reference as the literal text, so the app receives "$(NAME)" itself. The log shows it: the
// literal text, or, under sh -c, the shell running NAME as a command ("NAME: not found").
func undefinedVar(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, ok := containerSpec(p, cs.Name)
	if !ok {
		return nil
	}
	defined, known := containerEnv(ix, p.Metadata.Namespace, c)
	if !known {
		return nil // an envFrom source the snapshot cannot list: the variable may come from it
	}
	for _, part := range []struct {
		field string
		words []string
	}{{"command", c.Command}, {"args", c.Args}} {
		for _, w := range part.words {
			for _, m := range reVarRef.FindAllStringSubmatch(w, -1) {
				name := m[2]
				if defined[name] || serviceLinkVar(ix, p.Metadata.Namespace, name) {
					continue
				}
				line := ""
				for i := len(lines) - 1; i >= 0 && line == ""; i-- {
					if strings.Contains(lines[i], "$("+name+")") || strings.Contains(lines[i], name+": not found") {
						line = lines[i]
					}
				}
				if line == "" {
					continue
				}
				ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's %s refers to $(%s), and its env and envFrom define no %s", cs.Name, part.field, name, name),
					Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].%s}{"\n"}{.spec.containers[?(@.name=="%s")].env[*].name}`, cs.Name, part.field, cs.Name))})
				return newProblem(p, cs.Name, "KD205", "Command refers to a variable the container does not define", Critical,
					fmt.Sprintf("container %s's %s uses $(%s), but the container's env and envFrom define no %s, so the kubelet passes the text $(%s) on unexpanded (it does not read the image's ENV) and the process fails on it; its log says: %q",
						cs.Name, part.field, name, name, name, clip(line, 200)),
					"undefvar|"+name,
					fmt.Sprintf("Define %s in the container's env (or a ConfigMap in envFrom), or correct the name in the %s. To pass a literal $(%s), write $$(%s).", name, part.field, name, name), ev...)
			}
		}
	}
	return nil
}

// serviceLinkVar reports whether name is one of the variables the kubelet sets for a Service of the namespace
// (FOO_SERVICE_HOST, FOO_SERVICE_PORT, FOO_PORT, FOO_PORT_80_TCP and so on for Service foo), which it expands too.
// When the Services were not read, any name of that form counts.
func serviceLinkVar(ix *index, ns, name string) bool {
	if !ix.read("services") {
		return strings.Contains(name, "_SERVICE_") || strings.HasSuffix(name, "_PORT") || strings.Contains(name, "_PORT_")
	}
	for _, svc := range ix.s.Services {
		if svc.Metadata.Namespace != ns {
			continue
		}
		prefix := strings.ToUpper(strings.ReplaceAll(svc.Metadata.Name, "-", "_"))
		if strings.HasPrefix(name, prefix+"_SERVICE_") || name == prefix+"_PORT" || strings.HasPrefix(name, prefix+"_PORT_") {
			return true
		}
	}
	return false
}

// containerEnv returns the variable names a container defines through env and envFrom, and whether every envFrom
// source could be listed.
func containerEnv(ix *index, ns string, c kube.Container) (map[string]bool, bool) {
	out := map[string]bool{}
	for _, e := range c.Env {
		out[e.Name] = true
	}
	for _, src := range c.EnvFrom {
		var ks kube.KeySet
		var ok bool
		switch {
		case src.ConfigMapRef != nil:
			ks, ok = ix.configMaps[nsName{ns, src.ConfigMapRef.Name}]
		case src.SecretRef != nil:
			ks, ok = ix.secrets[nsName{ns, src.SecretRef.Name}]
		}
		if !ok {
			return out, false
		}
		for _, k := range ks.Keys {
			out[src.Prefix+k] = true
		}
	}
	return out, true
}
