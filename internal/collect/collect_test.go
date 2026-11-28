package collect

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

func TestCheckReadOnly(t *testing.T) {
	ok := [][]string{
		{"get", "pods", "-o", "json", "-A"}, {"logs", "web-1", "-n", "shop", "-c", "web", "--tail=20", "--previous"},
		{"version", "-o", "json"}, {"config", "current-context"}, strings.Fields(CurrentNamespace),
	}
	for _, a := range ok {
		if err := CheckReadOnly(a); err != nil {
			t.Errorf("CheckReadOnly(%v) = %v; want allowed", a, err)
		}
	}
	refused := [][]string{
		{}, {"delete", "pod", "x"}, {"apply", "-f", "x.yaml"}, {"edit", "deploy", "x"}, {"exec", "x", "--", "sh"},
		{"patch", "deploy", "x"}, {"scale", "deploy", "x", "--replicas=0"}, {"rollout", "restart", "deploy/x"},
		{"label", "pod", "x", "a=b"}, {"annotate", "pod", "x", "a=b"}, {"cordon", "n1"}, {"drain", "n1"},
		{"taint", "nodes", "n1", "k=v:NoSchedule"}, {"create", "ns", "x"}, {"replace", "-f", "x"}, {"set", "image", "x"},
		{"debug", "x"}, {"cp", "x:/a", "b"}, {"port-forward", "x", "80"}, {"proxy"}, {"auth", "reconcile"},
		{"config", "use-context", "prod"}, {"config", "set-context", "x"}, {"config", "current-context", "extra"},
		{"config", "view", "--raw"}, {"config", "view", "--minify", "-o", "jsonpath={.users}"},
		{"get", "pods", "-w"}, {"get", "pods", "--watch"}, {"get", "--raw", "/api"}, {"get", "-f", "x.yaml"},
		{"logs", "x", "-f"}, {"logs", "x", "--follow"}, {"get", "-k", "dir"}, {"get", "pods", "--watch-only=true"},
	}
	for _, a := range refused {
		if err := CheckReadOnly(a); !errors.Is(err, ErrNotReadOnly) {
			t.Errorf("CheckReadOnly(%v) = %v; want refused", a, err)
		}
	}
}

func TestKubectlRefusesBeforeRunningAnything(t *testing.T) {
	k := Kubectl{Path: "/nonexistent/kubectl-must-not-run"}
	if _, err := k.Run(context.Background(), "delete", "pod", "x"); !errors.Is(err, ErrNotReadOnly) {
		t.Fatalf("Run(delete) = %v; want ErrNotReadOnly", err)
	}
	if _, err := k.Run(context.Background(), "get", "pods"); err == nil || errors.Is(err, ErrNotReadOnly) {
		t.Fatalf("an allowed command should reach exec and fail there, got %v", err)
	}
}

// fake answers kubectl commands from a table keyed by the first three arguments.
type fake struct {
	answers map[string]string
	errs    map[string]error
	mu      sync.Mutex // the collector runs several reads at once
	calls   [][]string
}

func (f *fake) Run(_ context.Context, args ...string) ([]byte, error) {
	if err := CheckReadOnly(args); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, args)
	f.mu.Unlock()
	key := strings.Join(args[:min(2, len(args))], " ")
	if args[0] == "logs" {
		key = "logs " + args[1] + " " + args[5]
	}
	if err, ok := f.errs[key]; ok {
		return nil, err
	}
	if out, ok := f.answers[key]; ok {
		return []byte(out), nil
	}
	return []byte(`{"items":[]}`), nil
}

const pods = `{"items":[
 {"metadata":{"name":"web-1","namespace":"shop"},"spec":{"containers":[{"name":"web","image":"nginx"}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"web","restartCount":3,
   "state":{"waiting":{"reason":"CrashLoopBackOff"}},"lastState":{"terminated":{"exitCode":1,"reason":"Error"}}}]}},
 {"metadata":{"name":"ok-1","namespace":"shop"},"spec":{"containers":[{"name":"ok","image":"nginx"}]},
  "status":{"phase":"Running","containerStatuses":[{"name":"ok","ready":true,"restartCount":0,"state":{"running":{}}}]}}]}`

func TestCollect(t *testing.T) {
	f := &fake{
		answers: map[string]string{
			"config current-context":                     "kind-faults\n",
			"version -o":                                 `{"serverVersion":{"gitVersion":"v1.37.0"}}`,
			"get pods":                                   pods,
			"get deployments.apps":                       `{"items":[{"metadata":{"name":"web","namespace":"shop"},"spec":{"replicas":2}}]}`,
			"get ingresses.networking.k8s.io":            `{"items":[{"metadata":{"name":"web","namespace":"shop"},"spec":{"ingressClassName":"nginx","rules":[{"host":"shop.example.com","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"web","port":{"number":80}}}}]}}]}}]}`,
			"get ingressclasses.networking.k8s.io":       `{"items":[{"metadata":{"name":"nginx","annotations":{"ingressclass.kubernetes.io/is-default-class":"true"}},"spec":{"controller":"k8s.io/ingress-nginx"}}]}`,
			"get poddisruptionbudgets.policy":            `{"items":[{"metadata":{"name":"web","namespace":"shop"},"spec":{"minAvailable":"100%"},"status":{"disruptionsAllowed":0,"currentHealthy":2,"desiredHealthy":2,"expectedPods":2}}]}`,
			"get horizontalpodautoscalers.autoscaling":   `{"items":[{"metadata":{"name":"web","namespace":"shop"},"spec":{"scaleTargetRef":{"kind":"Deployment","name":"web"},"maxReplicas":5},"status":{"conditions":[{"type":"ScalingActive","status":"False","reason":"FailedGetResourceMetric"}]}}]}`,
			"get cronjobs.batch":                         `{"items":[{"metadata":{"name":"nightly","namespace":"shop"},"spec":{"schedule":"0 2 * * *","concurrencyPolicy":"Forbid","suspend":false},"status":{"active":[{"kind":"Job","name":"nightly-29001"}],"lastScheduleTime":"2026-11-13T02:00:00Z"}}]}`,
			"get configmaps":                             "shop\tapp-config\t\tLOG_LEVEL,PORT,\nshop\tempty\t\t\n",
			"get rolebindings.rbac.authorization.k8s.io": `{"items":[{"metadata":{"name":"read-config","namespace":"shop"},"subjects":[{"kind":"ServiceAccount","name":"app","namespace":"shop"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"config-reader"}}]}`,
			"get roles.rbac.authorization.k8s.io":        `{"items":[{"metadata":{"name":"config-reader","namespace":"shop"},"rules":[{"apiGroups":[""],"resources":["configmaps"],"verbs":["get","list"]}]}]}`,
			"get clusterroles.rbac.authorization.k8s.io": "view\nedit\nadmin\n",
			"get namespaces":                             `{"items":[{"metadata":{"name":"shop","uid":"1f0c","labels":{"kubernetes.io/metadata.name":"shop","team":"web"},"annotations":{"owner":"someone@example.com"}}},{"metadata":{"name":"kube-system","labels":{"kubernetes.io/metadata.name":"kube-system"}}}]}`,
			"get secrets":                                "shop\tdb\tOpaque\tpassword,user,\n",
			"logs web-1 web":                             "\x1b[31mstarting\x1b[0m\nerror: DATABASE_URL is not set\n",
		},
		errs: map[string]error{
			"get nodes": &CommandError{Args: []string{"get", "nodes"}, Message: `Error from server (Forbidden): nodes is forbidden: User "dev" cannot list resource "nodes"`},
		},
	}
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	s, err := Collect(context.Background(), f, Options{Namespace: "shop", Tool: "test", Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Context != "kind-faults" || s.ServerVersion != "v1.37.0" || !s.CollectedAt.Equal(at) || s.Namespaces[0] != "shop" {
		t.Errorf("header: %+v", s)
	}
	if len(s.Ingresses) != 1 || s.Ingresses[0].Spec.Rules[0].HTTP.Paths[0].Backend.Service.Port.Number != 80 ||
		len(s.IngressClasses) != 1 || !s.IngressClasses[0].IsDefault() {
		t.Errorf("ingresses %+v classes %+v", s.Ingresses, s.IngressClasses)
	}
	if len(s.PDBs) != 1 || s.PDBs[0].Spec.MinAvailable.Str != "100%" || s.PDBs[0].Status.ExpectedPods != 2 {
		t.Errorf("pdbs %+v", s.PDBs)
	}
	if len(s.HPAs) != 1 || s.HPAs[0].Spec.MaxReplicas != 5 || s.HPAs[0].Spec.ScaleTargetRef.Name != "web" {
		t.Errorf("hpas %+v", s.HPAs)
	}
	if len(s.CronJobs) != 1 || s.CronJobs[0].Spec.ConcurrencyPolicy != "Forbid" || s.CronJobs[0].Status.Active[0].Name != "nightly-29001" ||
		s.CronJobs[0].Status.LastScheduleTime == nil {
		t.Errorf("cronjobs %+v", s.CronJobs)
	}
	if len(s.Pods) != 2 || len(s.Workloads) != 1 || s.Workloads[0].Kind != "Deployment" {
		t.Errorf("pods %d workloads %+v", len(s.Pods), s.Workloads)
	}
	if len(s.ConfigMaps) != 2 || !s.ConfigMaps[0].Has("PORT") || len(s.ConfigMaps[1].Keys) != 0 {
		t.Errorf("configmaps %+v", s.ConfigMaps)
	}
	if len(s.Secrets) != 1 || s.Secrets[0].Type != "Opaque" || !s.Secrets[0].Has("password") {
		t.Errorf("secrets %+v", s.Secrets)
	}
	if len(s.Gaps) != 1 || s.Gaps[0].Resource != "nodes" || !strings.Contains(s.Gaps[0].Error, "forbidden") {
		t.Errorf("gaps %+v", s.Gaps)
	}
	if len(s.Roles) != 1 || s.Roles[0].Rules[0].Verbs[1] != "list" || len(s.RoleBindings) != 1 || s.RoleBindings[0].Subjects[0].Name != "app" ||
		s.RoleBindings[0].RoleRef.Kind != "Role" || s.RoleBindings[0].RoleRef.Name != "config-reader" || strings.Join(s.ClusterRoles, ",") != "admin,edit,view" {
		t.Errorf("rbac: %+v %+v %v", s.Roles, s.RoleBindings, s.ClusterRoles)
	}
	// Namespaces are kept as a name and labels, nothing else.
	if len(s.NamespaceObjects) != 2 || s.NamespaceObjects[0].Metadata.Labels["team"] != "web" || s.NamespaceObjects[0].Metadata.UID != "" || len(s.NamespaceObjects[0].Metadata.Annotations) != 0 {
		t.Errorf("namespaces %+v", s.NamespaceObjects)
	}
	if len(s.Logs) != 1 || !s.Logs[0].Previous || s.Logs[0].Lines[0] != "starting" || len(s.Logs[0].Lines) != 2 {
		t.Errorf("logs %+v", s.Logs)
	}
	for _, c := range f.calls {
		if c[0] == "get" && c[1] == "secrets" && !strings.HasPrefix(c[3], "go-template=") {
			t.Errorf("secrets must be read as key names only: %v", c)
		}
		if c[0] == "get" && c[1] != "nodes" && c[1] != "storageclasses.storage.k8s.io" && c[1] != "persistentvolumes" && c[1] != "ingressclasses.networking.k8s.io" && c[1] != "namespaces" && c[1] != "clusterroles.rbac.authorization.k8s.io" && c[1] != "gatewayclasses.gateway.networking.k8s.io" &&
			c[1] != "deviceclasses.resource.k8s.io" && c[1] != "resourceslices.resource.k8s.io" && c[1] != "runtimeclasses.node.k8s.io" &&
			!(c[len(c)-2] == "-n" && c[len(c)-1] == "shop") {
			t.Errorf("namespaced read not scoped to the namespace: %v", c)
		}
	}
}

func TestCollectFailsWhenTheClusterIsUnreachable(t *testing.T) {
	f := &fake{errs: map[string]error{"get pods": &CommandError{Message: "dial tcp 127.0.0.1:6443: connect: connection refused"}}}
	if _, err := Collect(context.Background(), f, Options{AllNamespaces: true}); err == nil || !strings.Contains(err.Error(), "cannot read the cluster") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Collect(context.Background(), &fake{}, Options{}); err == nil {
		t.Fatal("no namespace and not all namespaces should be an error")
	}
}

func TestCollectCapsLogReads(t *testing.T) {
	two := strings.Replace(pods, `"name":"ok","ready":true,"restartCount":0`, `"name":"ok","ready":false,"restartCount":2`, 1)
	f := &fake{answers: map[string]string{"get pods": two}}
	s, err := Collect(context.Background(), f, Options{AllNamespaces: true, MaxLogs: 1, LogLines: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Logs) != 1 || len(s.Gaps) != 1 || !strings.Contains(s.Gaps[0].Error, "1 of the 2 containers") {
		t.Errorf("logs %d gaps %+v", len(s.Logs), s.Gaps)
	}
	for _, c := range f.calls {
		if c[0] == "logs" && c[6] != "--tail=5" {
			t.Errorf("tail flag %v", c)
		}
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	f := &fake{answers: map[string]string{"get pods": pods}}
	s, err := Collect(context.Background(), f, Options{AllNamespaces: true, Tool: "v0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"s.json", "s.json.gz"} {
		path := filepath.Join(t.TempDir(), name)
		if err := snapshot.Write(path, s); err != nil {
			t.Fatal(err)
		}
		back, err := snapshot.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(back.Pods) != 2 || back.Tool != "v0" || back.Pods[0].Status.ContainerStatuses[0].RestartCount != 3 {
			t.Errorf("%s: %+v", name, back)
		}
	}
	if _, err := snapshot.Decode(strings.NewReader(`{"schemaVersion":99}`)); err == nil {
		t.Error("a future schema should be refused")
	}
}

// TestLogsOfAJustExitedContainer reads the current log (the run that failed), and falls back to the other instance
// when the kubelet says a log is gone, as it did for every crashed container in the fault suite's first run.
func TestLogsOfAJustExitedContainer(t *testing.T) {
	exited := strings.Replace(pods, `"state":{"waiting":{"reason":"CrashLoopBackOff"}}`, `"state":{"terminated":{"exitCode":1,"reason":"Error"}}`, 1)
	f := &fake{answers: map[string]string{"get pods": exited, "logs web-1 web": "error: DATABASE_URL is not set\n"}}
	s, err := Collect(context.Background(), f, Options{AllNamespaces: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Logs) != 1 || s.Logs[0].Previous || s.Logs[0].Lines[0] != "error: DATABASE_URL is not set" {
		t.Errorf("logs %+v", s.Logs)
	}
	for _, c := range f.calls {
		if c[0] == "logs" && c[len(c)-1] == "--previous" {
			t.Errorf("a just-exited container's log is the current one: %v", c)
		}
	}

	gone := &goneLog{fake: fake{answers: map[string]string{"get pods": pods}}}
	s, err = Collect(context.Background(), gone, Options{AllNamespaces: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Logs) != 1 || s.Logs[0].Previous || s.Logs[0].Lines[0] != "the current run's log" {
		t.Errorf("fallback: %+v", s.Logs)
	}

	gone.always = true
	s, _ = Collect(context.Background(), gone, Options{AllNamespaces: true})
	if len(s.Logs) != 0 || len(s.Gaps) != 1 || !strings.Contains(s.Gaps[0].Error, "unable to retrieve") {
		t.Errorf("both gone: logs %+v gaps %+v", s.Logs, s.Gaps)
	}
}

// goneLog answers --previous with the kubelet's note that the log is gone, and the current log normally (or never).
type goneLog struct {
	fake
	always bool
}

func (g *goneLog) Run(ctx context.Context, args ...string) ([]byte, error) {
	if args[0] == "logs" {
		if args[len(args)-1] == "--previous" || g.always {
			return []byte("unable to retrieve container logs for containerd://81d11b66\n"), nil
		}
		return []byte("the current run's log\n"), nil
	}
	return g.fake.Run(ctx, args...)
}

// TestLogsOfARunningInitContainer reads the current log of an init container that has not finished, the one place
// that says what it waits for.
func TestLogsOfARunningInitContainer(t *testing.T) {
	waiting := `{"items":[{"metadata":{"name":"web-1","namespace":"shop"},"spec":{"initContainers":[{"name":"wait-for-db","image":"busybox"}],"containers":[{"name":"web","image":"nginx"}]},
  "status":{"phase":"Pending","initContainerStatuses":[{"name":"wait-for-db","restartCount":0,"state":{"running":{}}}],
   "containerStatuses":[{"name":"web","restartCount":0,"state":{"waiting":{"reason":"PodInitializing"}}}]}}]}`
	f := &fake{answers: map[string]string{"get pods": waiting, "logs web-1 wait-for-db": "waiting for db:5432\n"}}
	s, err := Collect(context.Background(), f, Options{AllNamespaces: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Logs) != 1 || s.Logs[0].Container != "wait-for-db" || s.Logs[0].Previous || s.Logs[0].Lines[0] != "waiting for db:5432" {
		t.Errorf("logs %+v", s.Logs)
	}
}

// TestLogsSkipARunningSidecar leaves a sidecar's log unread: it is meant to keep running, so its log says nothing
// about why the pod waits, and reading it would use up the log budget.
func TestLogsSkipARunningSidecar(t *testing.T) {
	waiting := `{"items":[{"metadata":{"name":"web-1","namespace":"shop"},"spec":{"initContainers":[{"name":"proxy","image":"envoy","restartPolicy":"Always"},{"name":"wait-for-db","image":"busybox"}],"containers":[{"name":"web","image":"nginx"}]},
  "status":{"phase":"Pending","initContainerStatuses":[{"name":"proxy","restartCount":0,"state":{"running":{}}},{"name":"wait-for-db","restartCount":0,"state":{"running":{}}}],
   "containerStatuses":[{"name":"web","restartCount":0,"state":{"waiting":{"reason":"PodInitializing"}}}]}}]}`
	f := &fake{answers: map[string]string{"get pods": waiting, "logs web-1 wait-for-db": "waiting for db:5432\n", "logs web-1 proxy": "listening\n"}}
	s, err := Collect(context.Background(), f, Options{AllNamespaces: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Logs) != 1 || s.Logs[0].Container != "wait-for-db" {
		t.Errorf("logs %+v", s.Logs)
	}
}

// slow is a kubectl whose every read takes a moment; it counts how many run at once and refuses two resources.
type slow struct {
	mu       sync.Mutex
	inFlight int
	most     int
}

func (s *slow) Run(_ context.Context, args ...string) ([]byte, error) {
	s.mu.Lock()
	s.inFlight++
	if s.inFlight > s.most {
		s.most = s.inFlight
	}
	s.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	s.mu.Lock()
	s.inFlight--
	s.mu.Unlock()
	if len(args) > 1 && (args[1] == "secrets" || args[1] == "jobs.batch") {
		return nil, &CommandError{Args: args, Message: "Error from server (Forbidden): " + args[1] + " is forbidden"}
	}
	if args[0] == "get" && strings.HasPrefix(args[3], "go-template=") {
		return nil, nil
	}
	return []byte(`{"items":[]}`), nil
}

// TestCollectReadsSeveralAtOnce holds the collector to running a few kubectl reads at a time, never more than
// maxParallel, and to a snapshot that does not depend on which finished first: gaps come out in the order of the reads.
func TestCollectReadsSeveralAtOnce(t *testing.T) {
	for i := 0; i < 20; i++ {
		r := &slow{}
		s, err := Collect(context.Background(), r, Options{Namespace: "shop"})
		if err != nil {
			t.Fatal(err)
		}
		if r.most < 2 || r.most > maxParallel {
			t.Fatalf("reads at once: %d; want 2 to %d", r.most, maxParallel)
		}
		if len(s.Gaps) != 2 || s.Gaps[0].Resource != "jobs.batch" || s.Gaps[1].Resource != "secrets" {
			t.Fatalf("gaps %+v", s.Gaps)
		}
	}
}

func TestCollectReadsTheGatewayAPIWhenTheClusterServesIt(t *testing.T) {
	f := &fake{answers: map[string]string{
		"get gateways.gateway.networking.k8s.io":           `{"items":[{"metadata":{"name":"public","namespace":"shop"},"spec":{"gatewayClassName":"envoy","listeners":[{"name":"http","port":80,"protocol":"HTTP"}]}}]}`,
		"get gatewayclasses.gateway.networking.k8s.io":     `{"items":[{"metadata":{"name":"envoy"},"spec":{"controllerName":"gateway.envoyproxy.io/gatewayclass-controller"}}]}`,
		"get httproutes.gateway.networking.k8s.io":         `{"items":[{"metadata":{"name":"shop","namespace":"shop"},"spec":{"parentRefs":[{"name":"public"}],"rules":[{"backendRefs":[{"name":"storefront","port":80}]}]}}]}`,
		"get grpcroutes.gateway.networking.k8s.io":         `{"items":[{"metadata":{"name":"orders","namespace":"shop"},"spec":{"parentRefs":[{"name":"public"}]}}]}`,
		"get referencegrants.gateway.networking.k8s.io":    `{"items":[{"metadata":{"name":"from-web","namespace":"shop"},"spec":{"from":[{"group":"gateway.networking.k8s.io","kind":"HTTPRoute","namespace":"web"}],"to":[{"group":"","kind":"Service"}]}}]}`,
		"get backendtlspolicies.gateway.networking.k8s.io": `{"items":[{"metadata":{"name":"auth-tls","namespace":"shop"},"spec":{"targetRefs":[{"group":"","kind":"Service","name":"auth"}],"validation":{"caCertificateRefs":[{"group":"","kind":"ConfigMap","name":"auth-ca"}],"hostname":"auth.shop.svc"}}}]}`,
	}}
	s, err := Collect(context.Background(), f, Options{Namespace: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Gateways) != 1 || s.Gateways[0].Spec.Listeners[0].Name != "http" || len(s.GatewayClasses) != 1 {
		t.Errorf("gateways %+v classes %+v", s.Gateways, s.GatewayClasses)
	}
	if len(s.ReferenceGrants) != 1 || s.ReferenceGrants[0].Spec.From[0].Namespace != "web" {
		t.Errorf("reference grants %+v", s.ReferenceGrants)
	}
	if b := s.BackendTLSPolicies; len(b) != 1 || b[0].Spec.TargetRefs[0].Name != "auth" || b[0].Spec.Validation.CACertificateRefs[0].Name != "auth-ca" {
		t.Errorf("backend TLS policies %+v", b)
	}
	if len(s.Routes) != 2 || s.Routes[0].Kind != "HTTPRoute" || s.Routes[1].Kind != "GRPCRoute" || *s.Routes[0].Spec.Rules[0].BackendRefs[0].Port != 80 {
		t.Errorf("routes %+v", s.Routes)
	}

	// A cluster without the Gateway API: nothing read, and no gap reported.
	notServed := errors.New(`kubectl: error: the server doesn't have a resource type "gateways"`)
	f = &fake{errs: map[string]error{
		"get gateways.gateway.networking.k8s.io": notServed, "get gatewayclasses.gateway.networking.k8s.io": notServed,
		"get httproutes.gateway.networking.k8s.io": notServed, "get grpcroutes.gateway.networking.k8s.io": notServed,
		"get referencegrants.gateway.networking.k8s.io": notServed, "get backendtlspolicies.gateway.networking.k8s.io": notServed,
	}}
	s, err = Collect(context.Background(), f, Options{Namespace: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Gaps) != 0 || len(s.Gateways)+len(s.Routes)+len(s.GatewayClasses) != 0 {
		t.Errorf("gaps %+v", s.Gaps)
	}

	// Served, but forbidden: a gap, as for any other resource.
	f = &fake{errs: map[string]error{"get httproutes.gateway.networking.k8s.io": errors.New(`Error from server (Forbidden): httproutes.gateway.networking.k8s.io is forbidden`)}}
	s, _ = Collect(context.Background(), f, Options{Namespace: "shop"})
	if len(s.Gaps) != 1 || s.Gaps[0].Resource != "httproutes.gateway.networking.k8s.io" {
		t.Errorf("gaps %+v", s.Gaps)
	}
}

func TestCollectReadsDynamicResourceAllocationWhenTheClusterServesIt(t *testing.T) {
	f := &fake{answers: map[string]string{
		"get deviceclasses.resource.k8s.io":          `{"items":[{"metadata":{"name":"gpu.example.com"},"spec":{"selectors":[{"cel":{"expression":"device.driver == 'gpu.example.com'"}}]}}]}`,
		"get resourceclaims.resource.k8s.io":         `{"items":[{"metadata":{"name":"train-gpu","namespace":"shop"},"spec":{"devices":{"requests":[{"name":"gpu","exactly":{"deviceClassName":"gpu.example.com","count":2}}]}}}]}`,
		"get resourceclaimtemplates.resource.k8s.io": `{"items":[{"metadata":{"name":"one-gpu","namespace":"shop"},"spec":{"spec":{"devices":{"requests":[{"name":"gpu","deviceClassName":"gpu.example.com"}]}}}}]}`,
		"get resourceslices.resource.k8s.io":         `{"items":[{"metadata":{"name":"node-1-gpu"},"spec":{"driver":"gpu.example.com","nodeName":"node-1","pool":{"name":"node-1"},"devices":[{"name":"gpu-0","attributes":{"model":{"string":"L4"}}}]}}]}`,
	}}
	s, err := Collect(context.Background(), f, Options{Namespace: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if !s.ResourceAllocationRead || len(s.DeviceClasses) != 1 || len(s.ResourceSlices) != 1 || s.ResourceSlices[0].Spec.Devices[0].Name != "gpu-0" {
		t.Errorf("read %v classes %+v slices %+v", s.ResourceAllocationRead, s.DeviceClasses, s.ResourceSlices)
	}
	// Of a slice, the driver, its nodes and the device names are kept, as the README says; not the attributes.
	if b, _ := json.Marshal(s.ResourceSlices); strings.Contains(string(b), "attributes") || strings.Contains(string(b), "L4") {
		t.Errorf("slice keeps more than it should: %s", b)
	}
	readme, _ := os.ReadFile("../../README.md")
	if !strings.Contains(strings.Join(strings.Fields(string(readme)), " "), "ResourceSlices in the cluster, keeping of each slice its driver, nodes and device names") {
		t.Error("README should say what is read of ResourceSlices")
	}
	// A v1 request and a v1beta1 one read alike.
	if a := s.ResourceClaims[0].Spec.Devices.Requests[0].Alternatives(); len(a) != 1 || a[0].DeviceClassName != "gpu.example.com" || a[0].Count != 2 {
		t.Errorf("claim %+v", a)
	}
	if a := s.ResourceClaimTemplates[0].Spec.Spec.Devices.Requests[0].Alternatives(); len(a) != 1 || a[0].DeviceClassName != "gpu.example.com" {
		t.Errorf("template %+v", a)
	}

	// A cluster that does not serve the API: nothing read, no gap, and the snapshot says so.
	notServed := errors.New(`kubectl: error: the server doesn't have a resource type "deviceclasses"`)
	f = &fake{errs: map[string]error{"get deviceclasses.resource.k8s.io": notServed}}
	s, err = Collect(context.Background(), f, Options{Namespace: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if s.ResourceAllocationRead || len(s.Gaps) != 0 {
		t.Errorf("read %v gaps %+v", s.ResourceAllocationRead, s.Gaps)
	}
	for _, c := range f.calls {
		if c[0] == "get" && strings.HasSuffix(c[1], ".resource.k8s.io") && c[1] != "deviceclasses.resource.k8s.io" {
			t.Errorf("read %v from a cluster without the API", c)
		}
	}

	// Served, but claims are forbidden: a gap.
	f = &fake{errs: map[string]error{"get resourceclaims.resource.k8s.io": errors.New(`Error from server (Forbidden): resourceclaims.resource.k8s.io is forbidden`)}}
	s, _ = Collect(context.Background(), f, Options{Namespace: "shop"})
	if !s.ResourceAllocationRead || len(s.Gaps) != 1 || s.Gaps[0].Resource != "resourceclaims.resource.k8s.io" {
		t.Errorf("gaps %+v", s.Gaps)
	}
}

func TestCollectReadsRuntimeClassesAndTheirScheduling(t *testing.T) {
	f := &fake{answers: map[string]string{
		"get runtimeclasses.node.k8s.io": `{"items":[{"metadata":{"name":"gvisor"},"handler":"runsc","scheduling":{"nodeSelector":{"sandbox":"gvisor"},"tolerations":[{"key":"sandbox","operator":"Exists"}]}}]}`,
	}}
	s, err := Collect(context.Background(), f, Options{Namespace: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.RuntimeClasses) != 1 || s.RuntimeClasses[0].Handler != "runsc" || s.RuntimeClasses[0].Scheduling.NodeSelector["sandbox"] != "gvisor" {
		t.Errorf("runtime classes %+v", s.RuntimeClasses)
	}
}

func TestCollectReadsKueuesLocalQueuesAndWhetherKueueIsServed(t *testing.T) {
	f := &fake{answers: map[string]string{
		"get localqueues.kueue.x-k8s.io": `{"items":[{"metadata":{"name":"team-a","namespace":"shop"},"spec":{"clusterQueue":"gpus"}}]}`,
	}}
	s, err := Collect(context.Background(), f, Options{Namespace: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	if s.KueueAPI != "served" || len(s.LocalQueues) != 1 || s.LocalQueues[0].Spec.ClusterQueue != "gpus" {
		t.Errorf("%q %+v", s.KueueAPI, s.LocalQueues)
	}
	// No Kueue: noted, and no gap.
	f = &fake{errs: map[string]error{"get localqueues.kueue.x-k8s.io": errors.New(`kubectl: error: the server doesn't have a resource type "localqueues"`)}}
	if s, _ = Collect(context.Background(), f, Options{Namespace: "shop"}); s.KueueAPI != "absent" || len(s.Gaps) != 0 {
		t.Errorf("%q %+v", s.KueueAPI, s.Gaps)
	}
	// Forbidden: a gap, and nothing known.
	f = &fake{errs: map[string]error{"get localqueues.kueue.x-k8s.io": errors.New(`Error from server (Forbidden): localqueues.kueue.x-k8s.io is forbidden`)}}
	if s, _ = Collect(context.Background(), f, Options{Namespace: "shop"}); s.KueueAPI != "" || len(s.Gaps) != 1 {
		t.Errorf("%q %+v", s.KueueAPI, s.Gaps)
	}
}
