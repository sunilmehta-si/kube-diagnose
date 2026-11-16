package collect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// Options says what to read.
type Options struct {
	Namespace     string // one namespace; ignored when AllNamespaces is set
	AllNamespaces bool
	Context       string // recorded in the snapshot; the Runner applies it
	LogLines      int    // lines of log to keep per container (default 20)
	MaxLogs       int    // most containers to read logs from (default 40)
	Tool          string // kube-diagnose version, recorded in the snapshot
	Now           func() time.Time
}

// Key names only: kubectl receives the objects, but this process sees names, types and key names, never values.
const (
	configMapKeys = `{{range .items}}{{.metadata.namespace}}{{"\t"}}{{.metadata.name}}{{"\t"}}{{"\t"}}` +
		`{{range $k, $v := .data}}{{$k}},{{end}}{{range $k, $v := .binaryData}}{{$k}},{{end}}{{"\n"}}{{end}}`
	secretKeys = `{{range .items}}{{.metadata.namespace}}{{"\t"}}{{.metadata.name}}{{"\t"}}{{.type}}{{"\t"}}` +
		`{{range $k, $v := .data}}{{$k}},{{end}}{{"\n"}}{{end}}`
)

// Collect reads everything the rules use. A resource the user may not read is recorded as a gap, not an error: a
// diagnosis from the rest is still useful, and the report says what it could not see.
func Collect(ctx context.Context, r Runner, o Options) (*snapshot.Snapshot, error) {
	if o.LogLines <= 0 {
		o.LogLines = 20
	}
	if o.MaxLogs <= 0 {
		o.MaxLogs = 40
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	s := &snapshot.Snapshot{SchemaVersion: snapshot.SchemaVersion, Tool: o.Tool, CollectedAt: now().UTC(), Context: o.Context}
	scope := []string{"-A"}
	if !o.AllNamespaces {
		if o.Namespace == "" {
			return nil, fmt.Errorf("a namespace or all namespaces is required")
		}
		scope = []string{"-n", o.Namespace}
		s.Namespaces = []string{o.Namespace}
	}
	if s.Context == "" {
		if out, err := r.Run(ctx, "config", "current-context"); err == nil {
			s.Context = strings.TrimSpace(string(out))
		}
	}
	if out, err := r.Run(ctx, "version", "-o", "json"); err == nil {
		var v struct {
			ServerVersion struct {
				GitVersion string `json:"gitVersion"`
			} `json:"serverVersion"`
		}
		if json.Unmarshal(out, &v) == nil {
			s.ServerVersion = v.ServerVersion.GitVersion
		}
	}
	ns := o.Namespace
	if o.AllNamespaces {
		ns = ""
	}
	// The first read decides whether the cluster is reachable at all: if pods cannot be listed for any reason but
	// RBAC, nothing else will work either.
	if err := list(ctx, r, s, "pods", ns, scope, &s.Pods); err != nil {
		return nil, err
	}
	steps := []func() error{
		func() error { return list(ctx, r, s, "events", ns, scope, &s.Events) },
		func() error { return list(ctx, r, s, "services", ns, scope, &s.Services) },
		func() error { return list(ctx, r, s, "endpointslices.discovery.k8s.io", ns, scope, &s.EndpointSlices) },
		func() error { return list(ctx, r, s, "ingresses.networking.k8s.io", ns, scope, &s.Ingresses) },
		func() error { return workloads(ctx, r, s, ns, scope) },
		func() error { return list(ctx, r, s, "jobs.batch", ns, scope, &s.Jobs) },
		func() error { return list(ctx, r, s, "horizontalpodautoscalers.autoscaling", ns, scope, &s.HPAs) },
		func() error { return list(ctx, r, s, "poddisruptionbudgets.policy", ns, scope, &s.PDBs) },
		func() error { return list(ctx, r, s, "persistentvolumeclaims", ns, scope, &s.PVCs) },
		func() error {
			return list(ctx, r, s, "networkpolicies.networking.k8s.io", ns, scope, &s.NetworkPolicies)
		},
		func() error { return list(ctx, r, s, "resourcequotas", ns, scope, &s.ResourceQuotas) },
		func() error { return list(ctx, r, s, "serviceaccounts", ns, scope, &s.ServiceAccounts) },
		func() error { return keys(ctx, r, s, "configmaps", ns, scope, configMapKeys, &s.ConfigMaps) },
		func() error { return keys(ctx, r, s, "secrets", ns, scope, secretKeys, &s.Secrets) },
		func() error { return list(ctx, r, s, "nodes", "", nil, &s.Nodes) },
		func() error { return list(ctx, r, s, "storageclasses.storage.k8s.io", "", nil, &s.StorageClasses) },
		func() error { return list(ctx, r, s, "ingressclasses.networking.k8s.io", "", nil, &s.IngressClasses) },
		func() error { return list(ctx, r, s, "persistentvolumes", "", nil, &s.PVs) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	logs(ctx, r, s, o.LogLines, o.MaxLogs)
	return s, nil
}

// list runs `kubectl get <resource> -o json` into out. Errors become gaps unless the context is cancelled.
func list[T any](ctx context.Context, r Runner, s *snapshot.Snapshot, resource, ns string, scope []string, out *[]T) error {
	args := append([]string{"get", resource, "-o", "json"}, scope...)
	b, err := r.Run(ctx, args...)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if resource == "pods" && !Forbidden(err) {
			return fmt.Errorf("cannot read the cluster: %w", err)
		}
		s.Gaps = append(s.Gaps, snapshot.Gap{Resource: resource, Namespace: ns, Error: firstLine(err.Error())})
		return nil
	}
	var l kube.List[T]
	if err := json.Unmarshal(b, &l); err != nil {
		return fmt.Errorf("kubectl get %s: unexpected output: %w", resource, err)
	}
	*out = append(*out, l.Items...)
	return nil
}

func workloads(ctx context.Context, r Runner, s *snapshot.Snapshot, ns string, scope []string) error {
	for _, k := range []struct{ resource, kind string }{
		{"deployments.apps", "Deployment"}, {"replicasets.apps", "ReplicaSet"},
		{"statefulsets.apps", "StatefulSet"}, {"daemonsets.apps", "DaemonSet"},
	} {
		var ws []kube.Workload
		if err := list(ctx, r, s, k.resource, ns, scope, &ws); err != nil {
			return err
		}
		for i := range ws {
			ws[i].Kind = k.kind
		}
		s.Workloads = append(s.Workloads, ws...)
	}
	return nil
}

func keys(ctx context.Context, r Runner, s *snapshot.Snapshot, resource, ns string, scope []string, tmpl string, out *[]kube.KeySet) error {
	args := append([]string{"get", resource, "-o", "go-template=" + tmpl}, scope...)
	b, err := r.Run(ctx, args...)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.Gaps = append(s.Gaps, snapshot.Gap{Resource: resource, Namespace: ns, Error: firstLine(err.Error())})
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 4 {
			continue
		}
		k := kube.KeySet{Namespace: f[0], Name: f[1], Type: strings.TrimSpace(strings.ReplaceAll(f[2], "<no value>", "")), Keys: []string{}}
		for _, key := range strings.Split(f[3], ",") {
			if key != "" {
				k.Keys = append(k.Keys, key)
			}
		}
		sort.Strings(k.Keys)
		*out = append(*out, k)
	}
	return nil
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// logs reads the tail of the log of every container that crashed or is restarting: the previous instance's log
// when there is one, since that is the run that failed. It also reads the current log of an init container that is
// still running in a pending pod, since what it waits for is usually what it prints.
func logs(ctx context.Context, r Runner, s *snapshot.Snapshot, lines, max int) {
	type want struct {
		pod       kube.Pod
		container string
		previous  bool
	}
	var wants []want
	for _, p := range s.Pods {
		for _, c := range p.Status.InitContainerStatuses {
			if p.Status.Phase == "Pending" && c.State.Running != nil && c.RestartCount == 0 && !sidecar(p, c.Name) {
				wants = append(wants, want{p, c.Name, false})
			}
		}
		statuses := append(append([]kube.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
		for _, c := range statuses {
			crashed := c.LastTerminationState.Terminated != nil && c.LastTerminationState.Terminated.ExitCode != 0
			failedNow := c.State.Terminated != nil && c.State.Terminated.ExitCode != 0
			// A container that has just exited is the run that failed: its log is the current one. Otherwise the
			// failed run is the previous instance.
			if failedNow {
				wants = append(wants, want{p, c.Name, false})
			} else if c.RestartCount > 0 || crashed {
				wants = append(wants, want{p, c.Name, c.LastTerminationState.Terminated != nil})
			}
		}
	}
	for i, w := range wants {
		if i >= max {
			s.Gaps = append(s.Gaps, snapshot.Gap{Resource: "logs", Error: fmt.Sprintf("read the logs of %d of the %d containers that crashed or restarted; --max-logs reads more", max, len(wants))})
			return
		}
		args := []string{"logs", w.pod.Metadata.Name, "-n", w.pod.Metadata.Namespace, "-c", w.container, fmt.Sprintf("--tail=%d", lines)}
		previous := w.previous
		b, err := readLog(ctx, r, args, previous)
		if err == nil && unretrievable(b) {
			// The kubelet keeps one dead instance's log; when that is the other one, read it instead.
			previous = !previous
			b, err = readLog(ctx, r, args, previous)
			if err == nil && unretrievable(b) {
				err = fmt.Errorf("kubectl logs %s -c %s: %s", w.pod.Metadata.Name, w.container, firstLine(string(b)))
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.Gaps = append(s.Gaps, snapshot.Gap{Resource: "logs", Namespace: w.pod.Metadata.Namespace,
				Error: firstLine(err.Error())})
			continue
		}
		l := snapshot.Log{Pod: w.pod.Ref(), Container: w.container, Previous: previous, Lines: []string{}}
		for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			line = ansi.ReplaceAllString(strings.TrimRight(line, "\r"), "")
			if len(line) > 400 {
				line = line[:400] + "…"
			}
			if line != "" {
				l.Lines = append(l.Lines, line)
			}
		}
		s.Logs = append(s.Logs, l)
	}
}

// sidecar reports whether the named init container has restartPolicy Always: it is meant to keep running, so its
// running in a pending pod says nothing about why the pod waits.
func sidecar(p kube.Pod, name string) bool {
	for _, c := range p.Spec.InitContainers {
		if c.Name == name {
			return c.RestartPolicy == "Always"
		}
	}
	return false
}

func readLog(ctx context.Context, r Runner, args []string, previous bool) ([]byte, error) {
	if previous {
		args = append(append([]string{}, args...), "--previous")
	}
	return r.Run(ctx, args...)
}

// unretrievable reports whether kubectl printed the kubelet's note that a container's log is gone instead of a log.
func unretrievable(b []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(b), []byte("unable to retrieve container logs"))
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
