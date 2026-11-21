package diagnose

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

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
