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
	"sync"
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

// maxParallel is how many kubectl reads run at once.
const maxParallel = 8

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
	steps := []func(g *snapshot.Snapshot) error{
		func(g *snapshot.Snapshot) error { return list(ctx, r, g, "events", ns, scope, &s.Events) },
		func(g *snapshot.Snapshot) error { return list(ctx, r, g, "services", ns, scope, &s.Services) },
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "endpointslices.discovery.k8s.io", ns, scope, &s.EndpointSlices)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "ingresses.networking.k8s.io", ns, scope, &s.Ingresses)
		},
		func(g *snapshot.Snapshot) error { return workloads(ctx, r, g, ns, scope, &s.Workloads) },
		func(g *snapshot.Snapshot) error { return list(ctx, r, g, "jobs.batch", ns, scope, &s.Jobs) },
		func(g *snapshot.Snapshot) error { return list(ctx, r, g, "cronjobs.batch", ns, scope, &s.CronJobs) },
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "horizontalpodautoscalers.autoscaling", ns, scope, &s.HPAs)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "poddisruptionbudgets.policy", ns, scope, &s.PDBs)
		},
		func(g *snapshot.Snapshot) error { return list(ctx, r, g, "persistentvolumeclaims", ns, scope, &s.PVCs) },
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "networkpolicies.networking.k8s.io", ns, scope, &s.NetworkPolicies)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "resourcequotas", ns, scope, &s.ResourceQuotas)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "serviceaccounts", ns, scope, &s.ServiceAccounts)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "roles.rbac.authorization.k8s.io", ns, scope, &s.Roles)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "rolebindings.rbac.authorization.k8s.io", ns, scope, &s.RoleBindings)
		},
		func(g *snapshot.Snapshot) error {
			return names(ctx, r, g, "clusterroles.rbac.authorization.k8s.io", &s.ClusterRoles)
		},
		func(g *snapshot.Snapshot) error {
			return keys(ctx, r, g, "configmaps", ns, scope, configMapKeys, &s.ConfigMaps)
		},
		func(g *snapshot.Snapshot) error { return keys(ctx, r, g, "secrets", ns, scope, secretKeys, &s.Secrets) },
		func(g *snapshot.Snapshot) error { return list(ctx, r, g, "nodes", "", nil, &s.Nodes) },
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "storageclasses.storage.k8s.io", "", nil, &s.StorageClasses)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "ingressclasses.networking.k8s.io", "", nil, &s.IngressClasses)
		},
		func(g *snapshot.Snapshot) error { return list(ctx, r, g, "persistentvolumes", "", nil, &s.PVs) },
		func(g *snapshot.Snapshot) error { return namespaces(ctx, r, g, &s.NamespaceObjects) },
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "gateways.gateway.networking.k8s.io", ns, scope, &s.Gateways)
		},
		func(g *snapshot.Snapshot) error {
			return list(ctx, r, g, "gatewayclasses.gateway.networking.k8s.io", "", nil, &s.GatewayClasses)
		},
		func(g *snapshot.Snapshot) error { return routes(ctx, r, g, ns, scope, &s.Routes) },
	}
	// The reads are independent, each a kubectl process and one API request, so a few run at once. Every step
	// writes its own field of the snapshot and collects its gaps apart, which are then added in the steps' order: the
	// snapshot comes out the same as if they had run one by one.
	gaps := make([]snapshot.Snapshot, len(steps))
	errs := make([]error, len(steps))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, step := range steps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			errs[i] = step(&gaps[i])
		}()
	}
	wg.Wait()
	for i := range steps {
		if errs[i] != nil {
			return nil, errs[i]
		}
		s.Gaps = append(s.Gaps, gaps[i].Gaps...)
	}
	logs(ctx, r, s, o.LogLines, o.MaxLogs)
	return s, nil
}

// names reads the names of a cluster-scoped resource, and nothing else of it.
func names(ctx context.Context, r Runner, s *snapshot.Snapshot, resource string, out *[]string) error {
	b, err := r.Run(ctx, "get", resource, "-o", `go-template={{range .items}}{{.metadata.name}}{{"\n"}}{{end}}`)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.Gaps = append(s.Gaps, snapshot.Gap{Resource: resource, Error: firstLine(err.Error())})
		return nil
	}
	for _, n := range strings.Fields(string(b)) {
		*out = append(*out, n)
	}
	sort.Strings(*out)
	return nil
}

// namespaces reads every namespace of the cluster and keeps its name and labels only: a NetworkPolicy's
// namespaceSelector is judged against the labels, and nothing else of a namespace is needed or kept.
func namespaces(ctx context.Context, r Runner, s *snapshot.Snapshot, out *[]kube.Namespace) error {
	var all []kube.Namespace
	if err := list(ctx, r, s, "namespaces", "", nil, &all); err != nil {
		return err
	}
	for _, n := range all {
		*out = append(*out, kube.Namespace{Metadata: kube.ObjectMeta{Name: n.Metadata.Name, Labels: n.Metadata.Labels}})
	}
	return nil
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
		if strings.HasSuffix(resource, ".gateway.networking.k8s.io") && notServed(err) {
			return nil // the cluster has no Gateway API: nothing to read, and nothing missed
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

// notServed reports whether kubectl failed because the API server does not serve the resource at all: its CRD is
// not installed.
func notServed(err error) bool {
	return strings.Contains(err.Error(), "doesn't have a resource type")
}

// routes reads the HTTPRoutes and GRPCRoutes, which are read alike.
func routes(ctx context.Context, r Runner, s *snapshot.Snapshot, ns string, scope []string, out *[]kube.Route) error {
	for _, k := range []struct{ resource, kind string }{
		{"httproutes.gateway.networking.k8s.io", "HTTPRoute"}, {"grpcroutes.gateway.networking.k8s.io", "GRPCRoute"},
	} {
		var rs []kube.Route
		if err := list(ctx, r, s, k.resource, ns, scope, &rs); err != nil {
			return err
		}
		for i := range rs {
			rs[i].Kind = k.kind
		}
		*out = append(*out, rs...)
	}
	return nil
}

func workloads(ctx context.Context, r Runner, s *snapshot.Snapshot, ns string, scope []string, out *[]kube.Workload) error {
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
		*out = append(*out, ws...)
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
			if p.Status.Phase == "Pending" && c.State.Running != nil && c.RestartCount == 0 && !p.IsSidecar(c.Name) {
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
	if len(wants) > max {
		s.Gaps = append(s.Gaps, snapshot.Gap{Resource: "logs", Error: fmt.Sprintf("read the logs of %d of the %d containers that crashed or restarted; --max-logs reads more", max, len(wants))})
		wants = wants[:max]
	}
	// Read a few at once, and keep the containers' order in the snapshot.
	read := make([]*snapshot.Log, len(wants))
	failed := make([]*snapshot.Gap, len(wants))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, w := range wants {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
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
				if ctx.Err() == nil {
					failed[i] = &snapshot.Gap{Resource: "logs", Namespace: w.pod.Metadata.Namespace, Error: firstLine(err.Error())}
				}
				return
			}
			l := &snapshot.Log{Pod: w.pod.Ref(), Container: w.container, Previous: previous, Lines: []string{}}
			for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
				line = ansi.ReplaceAllString(strings.TrimRight(line, "\r"), "")
				if len(line) > 400 {
					line = line[:400] + "…"
				}
				if line != "" {
					l.Lines = append(l.Lines, line)
				}
			}
			read[i] = l
		}()
	}
	wg.Wait()
	for i := range wants {
		if failed[i] != nil {
			s.Gaps = append(s.Gaps, *failed[i])
		}
		if read[i] != nil {
			s.Logs = append(s.Logs, *read[i])
		}
	}
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
