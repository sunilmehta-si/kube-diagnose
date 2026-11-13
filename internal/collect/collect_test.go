package collect

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

func TestCheckReadOnly(t *testing.T) {
	ok := [][]string{
		{"get", "pods", "-o", "json", "-A"}, {"logs", "web-1", "-n", "shop", "-c", "web", "--tail=20", "--previous"},
		{"version", "-o", "json"}, {"config", "current-context"},
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
	calls   [][]string
}

func (f *fake) Run(_ context.Context, args ...string) ([]byte, error) {
	if err := CheckReadOnly(args); err != nil {
		return nil, err
	}
	f.calls = append(f.calls, args)
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
			"config current-context": "kind-faults\n",
			"version -o":             `{"serverVersion":{"gitVersion":"v1.37.0"}}`,
			"get pods":               pods,
			"get deployments.apps":   `{"items":[{"metadata":{"name":"web","namespace":"shop"},"spec":{"replicas":2}}]}`,
			"get configmaps":         "shop\tapp-config\t\tLOG_LEVEL,PORT,\nshop\tempty\t\t\n",
			"get secrets":            "shop\tdb\tOpaque\tpassword,user,\n",
			"logs web-1 web":         "\x1b[31mstarting\x1b[0m\nerror: DATABASE_URL is not set\n",
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
	if len(s.Logs) != 1 || !s.Logs[0].Previous || s.Logs[0].Lines[0] != "starting" || len(s.Logs[0].Lines) != 2 {
		t.Errorf("logs %+v", s.Logs)
	}
	for _, c := range f.calls {
		if c[0] == "get" && c[1] == "secrets" && !strings.HasPrefix(c[3], "go-template=") {
			t.Errorf("secrets must be read as key names only: %v", c)
		}
		if c[0] == "get" && c[1] != "nodes" && c[1] != "storageclasses.storage.k8s.io" && c[1] != "persistentvolumes" &&
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
