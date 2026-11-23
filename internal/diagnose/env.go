package diagnose

import (
	"fmt"
	"regexp"
	"slices"
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

// reShellVar is a shell-style reference, $NAME or ${NAME}, in a command or args; $(NAME) is Kubernetes' own form.
var reShellVar = regexp.MustCompile(`\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`)

// runsShell reports whether the container's command hands a script to a shell (sh -c ...), which expands $NAME itself.
func runsShell(c kube.Container) bool {
	words := append(append([]string{}, c.Command...), c.Args...)
	for i, w := range words {
		switch w[strings.LastIndex(w, "/")+1:] {
		case "sh", "bash", "ash", "dash", "zsh":
			for _, next := range words[i+1:] {
				if strings.HasPrefix(next, "-") && strings.Contains(next, "c") {
					return true
				}
			}
		}
	}
	return false
}

// shellVar finds a container that fails because its command or args use the shell's $NAME or ${NAME} with no shell
// to expand it: Kubernetes passes each word to the process as written and expands only $(NAME), so the app receives
// the text "$NAME". The log shows that text.
func shellVar(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, ok := containerSpec(p, cs.Name)
	if !ok || runsShell(c) {
		return nil
	}
	defined, _ := containerEnv(ix, p.Metadata.Namespace, c)
	for _, part := range []struct {
		field string
		words []string
	}{{"command", c.Command}, {"args", c.Args}} {
		for _, w := range part.words {
			for _, m := range reShellVar.FindAllStringSubmatch(w, -1) {
				ref, name := m[0], strings.Trim(m[1], "{}")
				line := ""
				for i := len(lines) - 1; i >= 0 && line == ""; i-- {
					if strings.Contains(lines[i], ref) {
						line = lines[i]
					}
				}
				if line == "" {
					continue
				}
				how := fmt.Sprintf("Write it as $(%s), which Kubernetes expands from the container's env", name)
				if !defined[name] {
					how = fmt.Sprintf("Define %s in the container's env and write it as $(%s)", name, name)
				}
				ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's %s has %s and runs no shell", cs.Name, part.field, ref),
					Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].%s}`, cs.Name, part.field))})
				return newProblem(p, cs.Name, "KD213", "Command uses a shell variable with no shell", Critical,
					fmt.Sprintf("container %s's %s uses %s, the shell's syntax, but the command runs without a shell, so nothing expands it: the process receives the text %s and fails on it (Kubernetes expands only $(%s)); its log says: %q",
						cs.Name, part.field, ref, ref, name, clip(line, 200)),
					"shellvar|"+name,
					fmt.Sprintf("%s, or run the command through a shell: [\"sh\", \"-c\", \"...\"].", how), ev...)
			}
		}
	}
	return nil
}

// envOrder finds a container that fails because one of its env values refers to $(NAME) where NAME is defined later
// in the env list, or not at all. The kubelet expands a reference only from the variables defined before it (envFrom,
// the Service variables and the env entries above), and leaves any other as the literal text; the log shows that text.
func envOrder(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, ok := containerSpec(p, cs.Name)
	if !ok {
		return nil
	}
	fromSources := map[string]bool{}
	all, known := containerEnv(ix, p.Metadata.Namespace, c)
	position := map[string]int{}
	for i, e := range c.Env {
		position[e.Name] = i
	}
	for name := range all {
		if _, inEnv := position[name]; !inEnv {
			fromSources[name] = true
		}
	}
	for i, e := range c.Env {
		for _, m := range reVarRef.FindAllStringSubmatch(e.Value, -1) {
			name := m[2]
			at, inEnv := position[name]
			if fromSources[name] || (inEnv && at < i) || serviceLinkVar(ix, p.Metadata.Namespace, name) {
				continue
			}
			if !inEnv && !known {
				continue // an envFrom source the snapshot cannot list may define it
			}
			line := ""
			for j := len(lines) - 1; j >= 0 && line == ""; j-- {
				if strings.Contains(lines[j], "$("+name+")") {
					line = lines[j]
				}
			}
			if line == "" {
				continue
			}
			why := "which the container's env and envFrom do not define"
			fix := fmt.Sprintf("Define %s in the container's env above %s (or in a ConfigMap in envFrom), or correct the name.", name, e.Name)
			if inEnv && at == i {
				why = "which is the variable itself"
				fix = fmt.Sprintf("Give %s its value directly: a variable cannot refer to itself.", e.Name)
			} else if inEnv {
				why = fmt.Sprintf("which is defined after %s in the env list", e.Name)
				fix = fmt.Sprintf("Move %s above %s in the container's env list: a value can refer only to variables defined before it.", name, e.Name)
			}
			ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's env, in order: %s is entry %d and refers to $(%s)", cs.Name, e.Name, i+1, name),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{range .spec.containers[?(@.name=="%s")].env[*]}{.name}={.value}{"\n"}{end}`, cs.Name))})
			return newProblem(p, cs.Name, "KD216", "Env value refers to a variable not defined before it", Critical,
				fmt.Sprintf("container %s's env %s refers to $(%s), %s: the kubelet expands a reference only from variables defined before it, so %s holds the text $(%s) unexpanded and the process fails on it; its log says: %q",
					cs.Name, e.Name, name, why, e.Name, name, clip(line, 200)),
				"envorder|"+e.Name+"|"+name, fix, ev...)
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

// serviceLinkOverride finds a container that exits after reading, as a setting of its own, a variable the kubelet
// set for a Service. For Service redis the kubelet gives every container of the namespace REDIS_PORT=tcp://IP:PORT
// (and REDIS_SERVICE_HOST, REDIS_PORT_6379_TCP and more), unless the pod sets enableServiceLinks: false. An app or
// image that keeps its own port in REDIS_PORT then gets a URL where it expects a number, and its log shows the
// value.
func serviceLinkOverride(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	if p.Spec.EnableServiceLinks != nil && !*p.Spec.EnableServiceLinks {
		return nil
	}
	c, ok := containerSpec(p, cs.Name)
	if !ok {
		return nil
	}
	ns := p.Metadata.Namespace
	defined, _ := containerEnv(ix, ns, c)
	for _, svc := range ix.s.Services {
		ip := svc.Spec.ClusterIP
		if svc.Metadata.Namespace != ns || ip == "" || ip == "None" || len(svc.Spec.Ports) == 0 {
			continue
		}
		if !svc.Metadata.CreationTimestamp.IsZero() && !p.Metadata.CreationTimestamp.IsZero() && svc.Metadata.CreationTimestamp.After(p.Metadata.CreationTimestamp) {
			continue // created after the pod: its containers did not get the variables
		}
		name := strings.ToUpper(strings.ReplaceAll(svc.Metadata.Name, "-", "_")) + "_PORT"
		if defined[name] {
			continue // the container's own value wins
		}
		proto := strings.ToLower(svc.Spec.Ports[0].Protocol)
		if proto == "" {
			proto = "tcp"
		}
		value := fmt.Sprintf("%s://%s:%d", proto, ip, svc.Spec.Ports[0].Port)
		for i := len(lines) - 1; i >= 0; i-- {
			if !strings.Contains(lines[i], value) {
				continue
			}
			ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s has cluster IP %s and port %d, so the kubelet sets %s=%s in the namespace's containers", svc.Metadata.Name, ip, svc.Spec.Ports[0].Port, name, value),
				Command: cmdGet("service", ns, svc.Metadata.Name, `{.spec.clusterIP}{" "}{.spec.ports[0].port}`)},
				Evidence{Object: p.Ref(), What: fmt.Sprintf("the pod does not set enableServiceLinks: false, and container %s defines no %s of its own", cs.Name, name),
					Command: cmdGet("pod", ns, p.Metadata.Name, fmt.Sprintf(`{.spec.enableServiceLinks}{" "}{.spec.containers[?(@.name=="%s")].env[*].name}`, cs.Name))})
			return newProblem(p, cs.Name, "KD223", "Service link variable replaces the app's own setting", Critical,
				fmt.Sprintf("container %s exits after reading %s as a setting of its own, and Kubernetes set it: for every Service of the namespace the kubelet gives each container variables named after the Service (service links), and for Service %s that includes %s=%s, an address where the app expects a port number; its log says: %q",
					cs.Name, name, svc.Metadata.Name, name, value, clip(lines[i], 200)),
				"servicelink|"+name,
				fmt.Sprintf("Set enableServiceLinks: false in the pod spec, so the kubelet adds no such variables (the Service's DNS name still works), or define %s in the container's env, which wins over the service link, or rename the app's variable or the Service.", name),
				ev...)
		}
	}
	return nil
}

// reVarUnset matches a log line that says a variable has no value.
var reVarUnset = regexp.MustCompile(`(?i)not set|missing|required|is empty|undefined|unset|no value`)

// optionalEnvMissing finds a container that exits because a variable it needs is unset, where the variable comes
// from a ConfigMap or Secret key marked optional and that key, or the whole object, does not exist. For an optional
// reference the kubelet leaves the variable out rather than refuse to start the container, so the mistake shows only
// as the app's own complaint.
func optionalEnvMissing(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, _ := containerSpec(p, cs.Name)
	ns := p.Metadata.Namespace
	for _, e := range c.Env {
		if e.ValueFrom == nil {
			continue
		}
		kind, ref := "configmap", e.ValueFrom.ConfigMapKeyRef
		if ref == nil {
			kind, ref = "secret", e.ValueFrom.SecretKeyRef
		}
		if ref == nil || ref.Optional == nil || !*ref.Optional {
			continue
		}
		ks, exists, known := ix.keySet(kind, ns, ref.Name)
		if !known || exists && slices.Contains(ks.Keys, ref.Key) {
			continue
		}
		line := ""
		for i := len(lines) - 1; i >= 0 && line == ""; i-- {
			if wordIn(lines[i], e.Name) && reVarUnset.MatchString(lines[i]) {
				line = lines[i]
			}
		}
		if line == "" {
			continue
		}
		kindName := map[string]string{"configmap": "ConfigMap", "secret": "Secret"}[kind]
		why := fmt.Sprintf("there is no %s %s in namespace %s", kindName, ref.Name, ns)
		if exists {
			have := "no keys"
			if len(ks.Keys) > 0 {
				have = strings.Join(ks.Keys, ", ")
			}
			why = fmt.Sprintf("%s %s has no key %s (it has %s)", kindName, ref.Name, ref.Key, have)
		}
		cause := fmt.Sprintf("container %s exits because %s is unset: it comes from key %s of %s %s, marked optional, and %s, so the kubelet left the variable out instead of refusing to start the container; its log says: %q",
			cs.Name, e.Name, ref.Key, kindName, ref.Name, why, clip(line, 200))
		fix := fmt.Sprintf("Add key %s to %s %s, or point %s at the key it has; and drop optional: true if the app cannot run without it, so that a missing key stops the container with a clear error instead.", ref.Key, kindName, ref.Name, e.Name)
		return newProblem(p, cs.Name, "KD235", "Optional key is missing, so a variable the app needs is unset", Critical, cause,
			"optenv|"+e.Name, fix, append(ev, Evidence{Object: kube.Ref{Kind: kindName, Namespace: ns, Name: ref.Name}, What: why,
				Command: cmdGet(kind, ns, ref.Name, "{.data}")},
				Evidence{Object: p.Ref(), What: fmt.Sprintf("%s comes from %s %s key %s, optional", e.Name, kindName, ref.Name, ref.Key),
					Command: cmdGet("pod", ns, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].env}`, cs.Name))})...)
	}
	return nil
}

// wordIn reports whether name occurs in line as a whole word.
func wordIn(line, name string) bool {
	for i := strings.Index(line, name); i >= 0; {
		end := i + len(name)
		before := i == 0 || !isIdent(line[i-1])
		after := end == len(line) || !isIdent(line[end])
		if before && after {
			return true
		}
		j := strings.Index(line[i+1:], name)
		if j < 0 {
			break
		}
		i += 1 + j
	}
	return false
}

func isIdent(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
