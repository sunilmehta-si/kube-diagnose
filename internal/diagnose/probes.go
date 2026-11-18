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
