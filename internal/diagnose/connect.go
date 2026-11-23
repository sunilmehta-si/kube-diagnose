package diagnose

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// Failed connections as clients print them, with the host or IP and the port: Go, curl, Node, libpq and redis-py.
var reConnectFailed = []struct {
	re  *regexp.Regexp
	how string
}{
	{regexp.MustCompile(`dial tcp \[?([0-9a-fA-F.:]+?)\]?:(\d+): connect: connection refused`), "refused"},
	{regexp.MustCompile(`(?i)failed to connect to ([A-Za-z0-9.-]+) port (\d+).*(?:Connection refused|Couldn't connect to server)`), "refused"},
	{regexp.MustCompile(`ECONNREFUSED ([0-9a-fA-F.:]+?):(\d+)\b`), "refused"},
	{regexp.MustCompile(`connection to server at "([A-Za-z0-9.-]+)"[^,]*, port (\d+) failed: Connection refused`), "refused"},
	{regexp.MustCompile(`(?i)connecting to ([A-Za-z0-9.-]+):(\d+)\. Connection refused`), "refused"},
	{regexp.MustCompile(`dial tcp ([0-9.]+):(\d+): connect: (?:no route to host|network is unreachable)`), "unreachable"},
}

// busybox wget and nc name the address but not the port; the "Connecting to" line before it has both.
var reConnectBare = regexp.MustCompile(`can't connect to remote host \(([0-9a-fA-F.:]+)\): (Connection refused|No route to host|Host is unreachable|Network is unreachable)`)

// connectFailure returns the newest failed connection in a log: the host (a name when the log has one, else the
// address), the port, how it failed ("refused", "timed out" or "unreachable") and the line that says so.
func connectFailure(lines []string) (host string, port int32, how, line string) {
	for i := len(lines) - 1; i >= 0; i-- {
		for _, p := range reConnectFailed {
			if m := p.re.FindStringSubmatch(lines[i]); m != nil {
				n, _ := strconv.Atoi(m[2])
				return m[1], int32(n), p.how, lines[i]
			}
		}
		if m := reConnectBare.FindStringSubmatch(lines[i]); m != nil {
			how := "unreachable"
			if m[2] == "Connection refused" {
				how = "refused"
			}
			for j := i - 1; j >= 0; j-- {
				if c := reConnecting.FindStringSubmatch(lines[j]); c != nil && c[2] == m[1] {
					n, _ := strconv.Atoi(c[3])
					return c[1], int32(n), how, lines[i]
				}
			}
			return m[1], 0, how, lines[i]
		}
	}
	if h, n, l := timedOutHost(lines); h != "" {
		return h, n, "timed out", l
	}
	return "", 0, "", ""
}

// localhostForService finds a container that exits because it connects to localhost for something that runs in
// another pod. In a pod, 127.0.0.1 is the pod itself: a connection there reaches only the pod's own containers, and
// is refused when none of them listens on the port. A Service of the namespace that serves that port is what the
// address should have been.
func localhostForService(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, port, how, line := connectFailure(lines)
	if how != "refused" || port == 0 || !loopback(host) {
		return nil
	}
	for _, c := range p.Spec.Containers {
		for _, cp := range c.Ports {
			if cp.ContainerPort == port {
				return nil // a container of this pod is meant to serve it: its own finding says why it does not
			}
		}
	}
	ns := p.Metadata.Namespace
	var svc kube.Service
	var sp kube.ServicePort
	found := false
	for _, s := range ix.s.Services {
		if s.Metadata.Namespace != ns || len(s.Spec.Selector) == 0 || kube.MatchesMap(s.Spec.Selector, p.Metadata.Labels) {
			continue
		}
		for _, q := range s.Spec.Ports {
			if q.Port == port || (!q.TargetPort.IsName && q.TargetPort.Int == port && !found) {
				exact := q.Port == port
				if !found || exact {
					svc, sp, found = s, q, true
				}
				if exact {
					break
				}
			}
		}
	}
	if !found {
		return nil
	}
	addr := fmt.Sprintf("%s:%d", svc.Metadata.Name, sp.Port)
	where := "the container's configuration"
	c, _ := containerSpec(p, cs.Name)
	for _, e := range c.Env {
		if strings.Contains(e.Value, "127.0.0.1") || strings.Contains(e.Value, "localhost") || strings.Contains(e.Value, "::1") {
			where = fmt.Sprintf("env %s (now %s)", e.Name, clip(e.Value, 80))
			break
		}
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("no container of pod %s declares port %d", p.Metadata.Name, port),
		Command: cmdGet("pod", ns, p.Metadata.Name, `{range .spec.containers[*]}{.name}{" "}{.ports[*].containerPort}{"\n"}{end}`)},
		Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s serves port %d from other pods (selector %s)", svc.Metadata.Name, sp.Port, kube.FormatMap(svc.Spec.Selector)),
			Command: cmdGet("service", ns, svc.Metadata.Name, `{.spec.selector}{" "}{.spec.ports}`)})
	return newProblem(p, cs.Name, "KD217", "Container connects to localhost for a Service in another pod", Critical,
		fmt.Sprintf("container %s exits because its connection to %s:%d is refused: in a pod, localhost is the pod itself, and none of its containers listens on %d. What serves that port here is Service %s, in other pods; its log says: %q",
			cs.Name, host, port, port, svc.Metadata.Name, clip(line, 200)),
		"localhost|"+strconv.Itoa(int(port)),
		fmt.Sprintf("Connect to %s instead of %s:%d: set it in %s.", addr, host, port, where), ev...)
}

// servicePortNotExposed finds a container that exits because it connects to a Service of its namespace on a port
// the Service does not expose: most often the pods' own port (the targetPort) where the Service's port was meant. A
// cluster IP answers only on the Service's ports, so the connection is refused or times out though the pods are up.
func servicePortNotExposed(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, port, how, line := connectFailure(lines)
	if port == 0 || loopback(host) {
		return nil
	}
	ns := p.Metadata.Namespace
	svc, ok := serviceByHost(ix, ns, host)
	if !ok || svc.Spec.ClusterIP == "None" || svc.Spec.Type == "ExternalName" || len(svc.Spec.Ports) == 0 {
		return nil // a headless Service resolves to the pods themselves, where the pods' port is the right one
	}
	var exposed []string
	var forwards *kube.ServicePort
	for i, sp := range svc.Spec.Ports {
		if sp.Port == port {
			return nil
		}
		exposed = append(exposed, strconv.Itoa(int(sp.Port)))
		if !sp.TargetPort.IsName && sp.TargetPort.Int == port {
			forwards = &svc.Spec.Ports[i]
		}
	}
	name := svc.Metadata.Name
	result := map[string]string{"refused": "is refused", "timed out": "times out", "unreachable": "finds no route"}[how]
	listens := fmt.Sprintf("it listens on %s", strings.Join(exposed, ", "))
	fix := fmt.Sprintf("Connect to one of Service %s's ports (%s), or add port %d to the Service.", name, strings.Join(exposed, ", "), port)
	if forwards != nil {
		listens = fmt.Sprintf("it listens on %d and forwards to the pods' port %d", forwards.Port, port)
		fix = fmt.Sprintf("Connect to %s:%d: %d is the pods' port (the Service's targetPort), and a client of a Service uses the Service's own port. Or change the Service's port to %d.",
			name, forwards.Port, port, port)
	}
	ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s exposes port %s, not %d", name, strings.Join(exposed, ", "), port),
		Command: cmdGet("service", ns, name, `{range .spec.ports[*]}{.port}{" -> "}{.targetPort}{"\n"}{end}`)})
	return newProblem(p, cs.Name, "KD218", "Container connects to a port the Service does not expose", Critical,
		fmt.Sprintf("container %s exits because its connection to Service %s on port %d %s: the Service does not expose %d, %s; its log says: %q",
			cs.Name, name, port, result, port, listens, clip(line, 200)),
		"svcport|"+name+"|"+strconv.Itoa(int(port)), fix, ev...)
}

// rePortInCommand matches a port given to a server on its command line: "-p 8080", "--port=8080", "--listen :8080",
// "--bind 0.0.0.0:8080".
var rePortInCommand = regexp.MustCompile(`(?:(?:^|\s)-p|--[a-z-]*(?:port|listen|bind|addr[a-z]*))[ =](?:[^\s:]*:)?(\d{2,5})\b`)

// commandPorts lists the ports a pod's containers are told to listen on by their command lines or by a PORT-like
// variable, in the order found.
func commandPorts(p kube.Pod) []int32 {
	var out []int32
	add := func(s string) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return
		}
		for _, x := range out {
			if x == int32(n) {
				return
			}
		}
		out = append(out, int32(n))
	}
	for _, c := range p.Spec.Containers {
		cmd := strings.Join(append(append([]string{}, c.Command...), c.Args...), " ")
		for _, m := range rePortInCommand.FindAllStringSubmatch(cmd, -1) {
			add(m[1])
		}
		for _, e := range c.Env {
			if e.Name == "PORT" || strings.HasSuffix(e.Name, "_PORT") {
				add(e.Value)
			}
		}
	}
	return out
}

// probesPort reports whether a readiness probe of the pod checks the port over the network.
func probesPort(p kube.Pod, port int32, name string) bool {
	is := func(v kube.IntOrString) bool {
		return (!v.IsName && v.Int == port) || (v.IsName && name != "" && v.Str == name)
	}
	for _, c := range p.Spec.Containers {
		pr := c.ReadinessProbe
		if pr == nil {
			continue
		}
		if (pr.HTTPGet != nil && is(pr.HTTPGet.Port)) || (pr.TCPSocket != nil && is(pr.TCPSocket.Port)) || (pr.GRPC != nil && pr.GRPC.Port == port) {
			return true
		}
	}
	return false
}

// refusedByReadyPods finds a container that exits because a Service of its namespace refuses its connection on a
// port the Service does expose, while the Service has ready pods. With endpoints behind it a cluster IP forwards
// the connection, so the refusal comes from the pod: nothing listens on the Service's targetPort there. The pod
// still counts as ready when no readiness probe checks that port.
func refusedByReadyPods(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	host, port, how, line := connectFailure(lines)
	if how != "refused" || loopback(host) {
		return nil
	}
	ns := p.Metadata.Namespace
	svc, ok := serviceByHost(ix, ns, host)
	if !ok || len(svc.Spec.Selector) == 0 || svc.Spec.ClusterIP == "None" || svc.Spec.Type == "ExternalName" {
		return nil
	}
	var sp *kube.ServicePort
	for i, q := range svc.Spec.Ports {
		if q.Port == port || (port == 0 && len(svc.Spec.Ports) == 1) {
			sp = &svc.Spec.Ports[i]
		}
	}
	if sp == nil {
		return nil
	}
	var backend *kube.Pod
	for i, q := range ix.s.Pods {
		if q.Metadata.Namespace == ns && q.Ready() && kube.MatchesMap(svc.Spec.Selector, q.Metadata.Labels) {
			backend = &ix.s.Pods[i]
			break
		}
	}
	if backend == nil {
		return nil // no ready pods: KD124
	}
	tport, tname := backendPort(svc, sp.Port, *backend)
	if probesPort(*backend, tport, tname) {
		return nil // the kubelet reaches that port, so something listens there: the refusal has another cause
	}
	// A server with no readiness probe is Ready the moment its container starts, before it listens: a client that
	// was refused within the server's first half minute may only have been early.
	if t := lastExit(cs); t != nil && !t.FinishedAt.IsZero() {
		for _, bs := range backend.Status.ContainerStatuses {
			if r := bs.State.Running; r != nil && !r.StartedAt.IsZero() && t.FinishedAt.Before(r.StartedAt.Add(30*time.Second)) {
				return nil
			}
		}
	}
	name := svc.Metadata.Name
	hint, fixPort := "", "the port the app listens on"
	for _, n := range commandPorts(*backend) {
		if n != tport {
			hint = fmt.Sprintf("; the pod's command or env names port %d, which is likely where the app listens", n)
			fixPort = fmt.Sprintf("%d, the port the app listens on by its command or env", n)
			break
		}
	}
	ev = append(ev, Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s forwards port %d to the pods' port %d", name, sp.Port, tport),
		Command: cmdGet("service", ns, name, `{range .spec.ports[*]}{.port}{" -> "}{.targetPort}{"\n"}{end}`)},
		Evidence{Object: backend.Ref(), What: fmt.Sprintf("pod %s is Ready and behind Service %s, and no readiness probe of it checks port %d", backend.Metadata.Name, name, tport),
			Command: cmdGet("pod", ns, backend.Metadata.Name, `{range .spec.containers[*]}{.name}{" ports="}{.ports[*].containerPort}{" readiness="}{.readinessProbe}{" command="}{.command}{" "}{.args}{"\n"}{end}`)})
	return newProblem(p, cs.Name, "KD225", "Service's pods refuse the port it targets", Critical,
		fmt.Sprintf("container %s exits because Service %s refuses its connection on port %d, though the Service has ready pods: it forwards port %d to the pods' port %d, and nothing in pod %s listens there, so the pod itself refuses. The pod counts as ready only because no readiness probe checks that port%s; its log says: %q",
			cs.Name, name, sp.Port, sp.Port, tport, backend.Metadata.Name, hint, clip(line, 200)),
		"notlistening|"+name+"|"+strconv.Itoa(int(sp.Port)),
		fmt.Sprintf("Set Service %s's targetPort to %s (a containerPort in the pod spec is a label, not a setting: it does not make the app listen there), or make the app listen on %d on all interfaces (0.0.0.0, not 127.0.0.1). Then add a readiness probe on that port, so a pod that does not answer gets no traffic and shows as not ready.",
			name, fixPort, tport), ev...)
}

var (
	reIPv4        = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	reConnFailure = regexp.MustCompile(`(?i)timed out|connection refused|no route to host|network is unreachable|i/o timeout|can't connect`)
)

// fixedServiceIP finds a container that exits because it connects to an IP address written into its environment,
// in a variable named for a Service of its namespace (DB_HOST=10.96.0.201 beside Service db) whose cluster IP is now
// another: the address of the Service before it was recreated, most often. A cluster IP is not kept when a Service
// is deleted and created again; its name is.
func fixedServiceIP(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	if !ix.read("services") {
		return nil
	}
	failed := ""
	for i := len(lines) - 1; i >= 0 && failed == ""; i-- {
		if reConnFailure.MatchString(lines[i]) {
			failed = lines[i]
		}
	}
	if failed == "" {
		return nil
	}
	c, _ := containerSpec(p, cs.Name)
	ns := p.Metadata.Namespace
	for _, e := range c.Env {
		m := reIPv4.FindStringSubmatch(e.Value)
		if m == nil || !mentions(lines, m[1]) {
			continue
		}
		ip := m[1]
		for _, svc := range ix.s.Services {
			if svc.Metadata.Namespace != ns || svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" || svc.Spec.ClusterIP == ip {
				continue
			}
			prefix := strings.ToUpper(strings.ReplaceAll(svc.Metadata.Name, "-", "_")) + "_"
			if !strings.HasPrefix(e.Name, prefix) {
				continue
			}
			cause := fmt.Sprintf("container %s exits because its connection to %s fails: the address is written into %s=%s, and Service %s, which %s names, has cluster IP %s, not %s; a Service gets a new cluster IP when it is created again, and its name stays; its log says: %q",
				cs.Name, ip, e.Name, e.Value, svc.Metadata.Name, e.Name, svc.Spec.ClusterIP, ip, clip(failed, 200))
			fix := fmt.Sprintf("Set %s to the Service's name, %s (or %s.%s.svc), which cluster DNS keeps pointing at its current address, in place of %s.",
				e.Name, strings.Replace(e.Value, ip, svc.Metadata.Name, 1), svc.Metadata.Name, ns, ip)
			return newProblem(p, cs.Name, "KD361", "Container connects to a fixed IP, not the Service's address", Critical, cause,
				"fixedip|"+e.Name+"|"+svc.Metadata.Name, fix,
				append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s has %s=%s", cs.Name, e.Name, e.Value),
					Command: cmdGet("pod", ns, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].env}`, cs.Name))},
					Evidence{Object: svc.Ref(), What: fmt.Sprintf("Service %s has cluster IP %s", svc.Metadata.Name, svc.Spec.ClusterIP),
						Command: cmdGet("service", ns, svc.Metadata.Name, "{.spec.clusterIP}")})...)
		}
	}
	return nil
}

// mentions reports whether any line holds the IP address as a whole word.
func mentions(lines []string, ip string) bool {
	for _, l := range lines {
		for _, m := range reIPv4.FindAllString(l, -1) {
			if m == ip {
				return true
			}
		}
	}
	return false
}
