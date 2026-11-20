package diagnose

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// probeOf returns the container's probe of the given kind: "liveness", "readiness" or "startup".
func probeOf(c kube.Container, kind string) *kube.Probe {
	switch kind {
	case "liveness":
		return c.LivenessProbe
	case "readiness":
		return c.ReadinessProbe
	case "startup":
		return c.StartupProbe
	}
	return nil
}

// probeEvent returns the newest Unhealthy event about the container's probe of the given kind whose message matches.
func probeEvent(ix *index, p kube.Pod, container, kind string, re *regexp.Regexp) (kube.Event, bool) {
	for _, e := range ix.eventsFor(p.Ref(), "Unhealthy") {
		if mentionsContainer(e, container) && strings.HasPrefix(strings.ToLower(e.Message), kind+" probe") && re.MatchString(e.Message) {
			return e, true
		}
	}
	return kube.Event{}, false
}

func probeSpecEvidence(p kube.Pod, container, kind string) Evidence {
	return Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's %s probe", container, kind),
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].%sProbe}`, container, kind))}
}

// probeEffect says what a probe that can never pass does to the container.
func probeEffect(kind string, restarts int32) string {
	switch kind {
	case "readiness":
		return "so the container never becomes ready and gets no traffic"
	case "startup":
		return fmt.Sprintf("so the kubelet restarts the container before it is ever marked started (%d restarts)", restarts)
	}
	return fmt.Sprintf("so the kubelet restarts the container (%d restarts)", restarts)
}

var reProbeHTTPS = regexp.MustCompile(`server gave HTTP response to HTTPS client`)

// probeScheme finds an httpGet probe with scheme HTTPS against a port that answers plain HTTP: the kubelet's client
// gets an HTTP answer to its TLS handshake, and every probe fails.
func probeScheme(ix *index, p kube.Pod, cs kube.ContainerStatus, kind string) *problem {
	e, ok := probeEvent(ix, p, cs.Name, kind, reProbeHTTPS)
	if !ok {
		return nil
	}
	c, _ := containerSpec(p, cs.Name)
	port := "its port"
	if pr := probeOf(c, kind); pr != nil && pr.HTTPGet != nil {
		port = "port " + pr.HTTPGet.Port.String()
	}
	return newProblem(p, cs.Name, "KD202", "Probe speaks HTTPS to a plain-HTTP port", Critical,
		fmt.Sprintf("container %s's %s probe uses scheme HTTPS, but the app answers plain HTTP on %s, so every probe fails (server gave HTTP response to HTTPS client), %s",
			cs.Name, kind, port, probeEffect(kind, cs.RestartCount)),
		"scheme|"+kind, "Set the probe's httpGet.scheme to HTTP, the default, or serve TLS on that port if the probe should use HTTPS.",
		eventEvidence(p.Ref(), e), probeSpecEvidence(p, cs.Name, kind))
}

// probeHost finds a failing httpGet or tcpSocket probe that sets host. The kubelet connects to that address instead of
// the pod's IP, from the node: localhost or 127.0.0.1 is the node itself, where the app is not listening, and any other
// address checks something other than this container.
func probeHost(ix *index, p kube.Pod, cs kube.ContainerStatus, kind string) *problem {
	c, _ := containerSpec(p, cs.Name)
	pr := probeOf(c, kind)
	if pr == nil {
		return nil
	}
	host, port := "", ""
	switch {
	case pr.HTTPGet != nil:
		host, port = pr.HTTPGet.Host, pr.HTTPGet.Port.String()
	case pr.TCPSocket != nil:
		host, port = pr.TCPSocket.Host, pr.TCPSocket.Port.String()
	}
	if host == "" || host == p.Status.PodIP {
		return nil
	}
	e, ok := probeEvent(ix, p, cs.Name, kind, reAnyProbeFailure)
	if !ok {
		return nil
	}
	where := "host " + host + ", not the pod"
	if loopback(host) {
		where = "host " + host + ", which the kubelet reaches on the node itself, not in the pod, where nothing listens on port " + port
	}
	return newProblem(p, cs.Name, "KD206", "Probe checks a host other than the pod", Critical,
		fmt.Sprintf("container %s's %s probe sets host, so the kubelet connects to %s, and the probe fails, %s", cs.Name, kind, where, probeEffect(kind, cs.RestartCount)),
		"host|"+kind+"|"+host,
		"Remove host from the probe so the kubelet connects to the pod's IP; to send a Host header for a virtual host, use httpGet.httpHeaders with name Host instead.",
		eventEvidence(p.Ref(), e), probeSpecEvidence(p, cs.Name, kind))
}

var reAnyProbeFailure = regexp.MustCompile(`(?i)probe (failed|errored)`)

var (
	reProbeRefused = regexp.MustCompile(`connect: connection refused`)
	// A flag that sets the address a server binds: --host 127.0.0.1, --bind=localhost, -b 127.0.0.1 and the like.
	reBindFlag = regexp.MustCompile(`(?i)(?:^|\s)(--?(?:host|bind|bind-address|bind-addr|listen|listen-address|listen-addr|address|addr|b|H))[= ]+(127\.0\.0\.1|localhost|\[?::1\]?)(?::\d+)?(?:\s|$)`)
	// A server saying where it listens: "Listening on 127.0.0.1:8080", "Running on http://localhost:8080".
	reLoopbackLog = regexp.MustCompile(`(?i)(?:listen|running|serving|started|bound|available)[^\n]*?(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)`)
)

// bindEnv names the environment variables servers read their bind address from.
var bindEnv = map[string]bool{"HOST": true, "BIND": true, "BIND_ADDR": true, "BIND_ADDRESS": true, "LISTEN_ADDR": true,
	"LISTEN_ADDRESS": true, "LISTEN_HOST": true, "SERVER_HOST": true, "UVICORN_HOST": true, "GUNICORN_BIND": true}

// loopbackOnly says how the spec or the log shows the app listening on the loopback address only, for the port a
// probe uses: an address in the command (127.0.0.1:8080, --host localhost), a bind variable in env, or the server's
// own line in the log.
func loopbackOnly(c kube.Container, lines []string, port int32) (string, bool) {
	ps := strconv.Itoa(int(port))
	cmd := strings.Join(append(append([]string{}, c.Command...), c.Args...), " ")
	for _, a := range []string{"127.0.0.1:" + ps, "localhost:" + ps, "[::1]:" + ps} {
		if strings.Contains(cmd, a) {
			return fmt.Sprintf("its command binds %s", a), true
		}
	}
	if m := reBindFlag.FindStringSubmatch(cmd); m != nil {
		return fmt.Sprintf("its command sets %s %s", m[1], m[2]), true
	}
	for _, e := range c.Env {
		v := strings.TrimSuffix(e.Value, ":"+ps)
		if bindEnv[e.Name] && (v == "127.0.0.1" || v == "localhost" || v == "::1") {
			return fmt.Sprintf("its env sets %s=%s", e.Name, e.Value), true
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if m := reLoopbackLog.FindStringSubmatch(lines[i]); m != nil && m[1] == ps {
			return fmt.Sprintf("its log says: %q", clip(lines[i], 160)), true
		}
	}
	return "", false
}

// probeLoopback finds a probe that is refused because the app listens on 127.0.0.1 only. Inside a pod the loopback
// address is reachable from the pod's own containers and from nothing else: not the kubelet's probes, not Services,
// not other pods.
func probeLoopback(ix *index, p kube.Pod, cs kube.ContainerStatus, kind string) *problem {
	c, _ := containerSpec(p, cs.Name)
	pr := probeOf(c, kind)
	if pr == nil {
		return nil
	}
	var port kube.IntOrString
	switch {
	case pr.HTTPGet != nil && pr.HTTPGet.Host == "":
		port = pr.HTTPGet.Port
	case pr.TCPSocket != nil && pr.TCPSocket.Host == "":
		port = pr.TCPSocket.Port
	default:
		return nil
	}
	n := port.Int
	if port.IsName {
		for _, cp := range c.Ports {
			if cp.Name == port.Str {
				n = cp.ContainerPort
			}
		}
	}
	if n == 0 {
		return nil
	}
	e, ok := probeEvent(ix, p, cs.Name, kind, reProbeRefused)
	if !ok {
		return nil
	}
	how, ok := loopbackOnly(c, ix.logs[logKey{p.Metadata.Namespace, p.Metadata.Name, cs.Name}].Lines, n)
	if !ok {
		return nil
	}
	return newProblem(p, cs.Name, "KD215", "App listens on localhost only", Critical,
		fmt.Sprintf("container %s's %s probe is refused on port %d because the app listens on the loopback address only (%s): in a pod, 127.0.0.1 is reachable from the pod's own containers and from nothing else, not the kubelet, a Service or another pod, %s",
			cs.Name, kind, n, how, probeEffect(kind, cs.RestartCount)),
		"loopback|"+strconv.Itoa(int(n)),
		"Have the app listen on 0.0.0.0 (or [::]) instead of 127.0.0.1 or localhost: its bind flag or variable, such as --host 0.0.0.0.",
		eventEvidence(p.Ref(), e), probeSpecEvidence(p, cs.Name, kind),
		Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's command and env", cs.Name),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].command}{" "}{.spec.containers[?(@.name=="%s")].args}{"\n"}{.spec.containers[?(@.name=="%s")].env}`, cs.Name, cs.Name, cs.Name))})
}

// The kubelet's gRPC probe messages (pkg/probe/grpc): a server without the health service, and a port where no gRPC
// server answers (it cannot connect, or the call fails before any reply).
var (
	reGRPCNoHealth = regexp.MustCompile(`does not implement the grpc health protocol`)
	reGRPCConnect  = regexp.MustCompile(`failed to connect service|health rpc probe failed|health rpc did not complete`)
)

// probeGRPC finds a failing gRPC probe that cannot pass: the server answers gRPC but does not implement
// grpc.health.v1.Health, or nothing on the port speaks gRPC at all (an HTTP/1 server, or nothing listening).
func probeGRPC(ix *index, p kube.Pod, cs kube.ContainerStatus, kind string) *problem {
	c, _ := containerSpec(p, cs.Name)
	pr := probeOf(c, kind)
	if pr == nil || pr.GRPC == nil {
		return nil
	}
	port := pr.GRPC.Port
	if e, ok := probeEvent(ix, p, cs.Name, kind, reGRPCNoHealth); ok {
		return newProblem(p, cs.Name, "KD209", "gRPC probe cannot pass on this port", Critical,
			fmt.Sprintf("container %s's %s probe calls the gRPC health service on port %d, and the server there answers gRPC but does not implement grpc.health.v1.Health, so the probe fails, %s", cs.Name, kind, port, probeEffect(kind, cs.RestartCount)),
			"grpc|"+kind, "Register the standard health service in the app (grpc-go: health.NewServer; most frameworks have it), or probe with tcpSocket or httpGet instead.",
			eventEvidence(p.Ref(), e), probeSpecEvidence(p, cs.Name, kind))
	}
	e, ok := probeEvent(ix, p, cs.Name, kind, reGRPCConnect)
	if !ok {
		return nil
	}
	declared := ""
	for _, cp := range c.Ports {
		if cp.ContainerPort == port && cp.Name != "" {
			declared = fmt.Sprintf(" (the container calls it %s)", cp.Name)
		}
	}
	return newProblem(p, cs.Name, "KD209", "gRPC probe cannot pass on this port", Critical,
		fmt.Sprintf("container %s's %s probe calls the gRPC health service on port %d%s, but nothing there speaks gRPC: the app serves something else on that port, such as plain HTTP, or does not listen on it, so the probe fails, %s", cs.Name, kind, port, declared, probeEffect(kind, cs.RestartCount)),
		"grpc|"+kind, "Point the probe's grpc.port at the app's gRPC port, or, if the app speaks HTTP, use an httpGet probe.",
		eventEvidence(p.Ref(), e), probeSpecEvidence(p, cs.Name, kind))
}

func loopback(host string) bool {
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" || host == "[::1]"
}

var reProbePort = regexp.MustCompile(`(?i)probe errored`)

// probePortMissing finds a probe that names a port (port: health) the container does not declare. The kubelet cannot
// resolve the name, so it reports the probe as errored rather than failed: a readiness or startup probe never passes,
// and a liveness probe never fails, so it checks nothing.
func probePortMissing(ix *index, p kube.Pod, cs kube.ContainerStatus, kinds ...string) *problem {
	if cs.State.Running == nil {
		return nil
	}
	c, _ := containerSpec(p, cs.Name)
	for _, kind := range kinds {
		pr := probeOf(c, kind)
		if pr == nil {
			continue
		}
		var port kube.IntOrString
		switch {
		case pr.HTTPGet != nil:
			port = pr.HTTPGet.Port
		case pr.TCPSocket != nil:
			port = pr.TCPSocket.Port
		default:
			continue
		}
		if !port.IsName || declaresPort(c, port) {
			continue
		}
		var have []string
		for _, cp := range c.Ports {
			if cp.Name != "" {
				have = append(have, fmt.Sprintf("%s (%d)", cp.Name, cp.ContainerPort))
			} else {
				have = append(have, strconv.Itoa(int(cp.ContainerPort)))
			}
		}
		declared := "no ports"
		if len(have) > 0 {
			declared = "ports " + strings.Join(have, ", ")
		}
		var ev []Evidence
		if e, ok := probeEvent(ix, p, cs.Name, kind, reProbePort); ok {
			ev = append(ev, eventEvidence(p.Ref(), e))
		}
		ev = append(ev, probeSpecEvidence(p, cs.Name, kind),
			Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s declares %s", cs.Name, declared),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].ports}`, cs.Name))})
		effect, sev := "so it never passes and the container never becomes ready", Critical
		switch kind {
		case "startup":
			effect = "so it never passes: the container is never marked started, its other probes never run, and it never becomes ready"
		case "liveness":
			effect, sev = "so it never fails either: it checks nothing and will not restart a hung container", Warning
		}
		return newProblem(p, cs.Name, "KD203", "Probe names a port the container does not have", sev,
			fmt.Sprintf("container %s's %s probe names port %q, but the container declares %s; the kubelet cannot resolve the name and reports the probe as errored, %s", cs.Name, kind, port.Str, declared, effect),
			"probeport|"+kind+"|"+port.Str,
			fmt.Sprintf("Name a port the container declares, or give the number; or add a ports entry named %q.", port.Str), ev...)
	}
	return nil
}
