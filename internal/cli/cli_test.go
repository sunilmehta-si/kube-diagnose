package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/collect"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// fakeKubectl answers from a table keyed by "verb resource", and records every call.
type fakeKubectl struct {
	context string
	answers map[string]string
	calls   *[][]string
}

func (f fakeKubectl) Run(_ context.Context, args ...string) ([]byte, error) {
	if err := collect.CheckReadOnly(args); err != nil {
		return nil, err
	}
	*f.calls = append(*f.calls, append([]string{"@" + f.context}, args...))
	key := args[0]
	if len(args) > 1 {
		key += " " + args[1]
	}
	if out, ok := f.answers[key]; ok {
		return []byte(out), nil
	}
	return []byte(`{"items":[]}`), nil
}

const brokenPods = `{"items":[{"metadata":{"name":"web-1","namespace":"shop","labels":{"app":"web"}},
 "spec":{"containers":[{"name":"web","image":"registry.example.com/web:9.9.9"}]},
 "status":{"phase":"Pending","conditions":[{"type":"PodScheduled","status":"True"}],
  "containerStatuses":[{"name":"web","ready":false,"restartCount":0,
   "state":{"waiting":{"reason":"ImagePullBackOff","message":"Back-off pulling image"}}}]}}]}`

const brokenEvents = `{"items":[{"metadata":{"name":"e1","namespace":"shop"},
 "involvedObject":{"kind":"Pod","namespace":"shop","name":"web-1"},"reason":"Failed","type":"Warning","count":4,
 "lastTimestamp":"2026-11-13T09:58:00Z",
 "message":"Failed to pull image \"registry.example.com/web:9.9.9\": rpc error: code = NotFound desc = failed to resolve reference \"registry.example.com/web:9.9.9\": not found"}]}`

func testEnv(answers map[string]string) (Env, *bytes.Buffer, *bytes.Buffer, *[][]string) {
	var out, errb bytes.Buffer
	calls := &[][]string{}
	return Env{Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
		Now:     func() time.Time { return time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC) },
		Kubectl: func(c string) collect.Runner { return fakeKubectl{context: c, answers: answers, calls: calls} }}, &out, &errb, calls
}

func broken() map[string]string {
	return map[string]string{"config view": "shop", "config current-context": "kind-faults", "get pods": brokenPods, "get events": brokenEvents}
}

func TestScanUsesTheContextsNamespace(t *testing.T) {
	env, out, _, calls := testEnv(broken())
	if code := Run(nil, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	got := out.String()
	for _, want := range []string{"namespace shop", "1 problem: 1 critical.", "Image does not exist", "KD101", "Pod shop/web-1",
		"$ kubectl get events -n shop", "Fix: Correct the image tag"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Error("no colour when stdout is not a terminal")
	}
	for _, c := range *calls {
		if c[1] == "get" && c[2] == "pods" && strings.Join(c[len(c)-2:], " ") != "-n shop" {
			t.Errorf("pods not read from the context's namespace: %v", c)
		}
	}
}

func TestScanDefaultsToDefaultNamespaceAndHonoursFlags(t *testing.T) {
	a := broken()
	delete(a, "config view")
	env, _, _, calls := testEnv(a)
	Run([]string{"--context", "staging"}, env)
	var sawDefault bool
	for _, c := range *calls {
		if c[0] != "@staging" {
			t.Errorf("--context not passed through: %v", c)
		}
		if c[1] == "get" && c[2] == "pods" && c[len(c)-1] == "default" {
			sawDefault = true
		}
	}
	if !sawDefault {
		t.Error("with no namespace in the context, the default namespace is read")
	}
	env, _, _, calls = testEnv(a)
	Run([]string{"-A"}, env)
	for _, c := range *calls {
		if c[1] == "config" && c[2] == "view" {
			t.Error("-A needs no namespace lookup")
		}
	}
}

func TestOutputsAndFailOn(t *testing.T) {
	env, out, _, _ := testEnv(broken())
	if code := Run([]string{"-n", "shop", "-o", "json", "--fail-on", "critical"}, env); code != 1 {
		t.Errorf("--fail-on critical with a critical finding: exit %d", code)
	}
	var r struct {
		Findings []struct {
			Rule, Severity string
			Evidence       []struct{ Command string }
		}
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Findings) != 1 || r.Findings[0].Severity != "critical" {
		t.Fatalf("json: %v %s", err, out)
	}
	env, out, _, _ = testEnv(broken())
	Run([]string{"-n", "shop", "-o", "markdown"}, env)
	if !strings.Contains(out.String(), "### 1. Image does not exist (`KD101`, critical)") || !strings.Contains(out.String(), "```sh") {
		t.Errorf("markdown:\n%s", out)
	}
	env, out, _, _ = testEnv(broken())
	env.IsTTY = true
	Run([]string{"-n", "shop"}, env)
	if !strings.Contains(out.String(), "\x1b[31;1mCRITICAL") {
		t.Error("colour on a terminal")
	}
	env, _, _, _ = testEnv(map[string]string{})
	if code := Run([]string{"-n", "shop", "--fail-on", "warning"}, env); code != 0 {
		t.Errorf("no findings: exit %d", code)
	}
}

func TestRecordThenDiagnoseTheSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shop.snapshot.json.gz")
	env, _, errb, _ := testEnv(broken())
	if code := Run([]string{"record", "-n", "shop", "-o", path}, env); code != 0 {
		t.Fatalf("record: exit %d: %s", code, errb)
	}
	s, err := snapshot.Read(path)
	if err != nil || s.Context != "kind-faults" || len(s.Pods) != 1 || s.Tool != "kube-diagnose dev" {
		t.Fatalf("snapshot %v %+v", err, s)
	}
	offline, out, _, calls := testEnv(nil)
	if code := Run([]string{"--snapshot", path}, offline); code != 0 || !strings.Contains(out.String(), "KD101") {
		t.Fatalf("snapshot scan: exit %d\n%s", code, out)
	}
	if len(*calls) != 0 {
		t.Errorf("a snapshot scan must not run kubectl: %v", *calls)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--output", "yaml"}, {"--fail-on", "info"}, {"--snapshot", "x.json", "-n", "shop"}, {"extra"},
		{"record", "-n", "shop"}, {"rules", "KD999"}, {"--no-such-flag"},
	} {
		env, _, _, _ := testEnv(broken())
		if code := Run(args, env); code != 2 {
			t.Errorf("%v: exit %d; want 2", args, code)
		}
	}
	env, _, errb, _ := testEnv(map[string]string{})
	env.Kubectl = func(string) collect.Runner { return unreachable{} }
	if code := Run([]string{"-n", "shop"}, env); code != 2 || !strings.Contains(errb.String(), "cannot read the cluster") {
		t.Errorf("unreachable cluster: exit %d %s", code, errb)
	}
}

type unreachable struct{}

func (unreachable) Run(context.Context, ...string) ([]byte, error) {
	return nil, &collect.CommandError{Message: "The connection to the server localhost:8080 was refused"}
}

func TestVersionAndRules(t *testing.T) {
	env, out, _, _ := testEnv(nil)
	if Run([]string{"version"}, env) != 0 || out.String() != "kube-diagnose dev\n" {
		t.Errorf("version: %q", out)
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules"}, env) != 0 || !strings.Contains(out.String(), "KD160  critical  Service selects no pods") {
		t.Errorf("rules:\n%s", out)
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules", "kd163"}, env) != 0 || !strings.Contains(out.String(), "NetworkPolicy blocks all traffic") {
		t.Errorf("rules kd163:\n%s", out)
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules", "CronJob"}, env) != 0 || !strings.Contains(out.String(), "KD188") || !strings.Contains(out.String(), "KD189") ||
		strings.Contains(out.String(), "KD101") {
		t.Errorf("rules CronJob:\n%s", out)
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules", "read-only", "configmap"}, env) != 0 || !strings.Contains(out.String(), "KD138") || strings.Contains(out.String(), "KD118") {
		t.Errorf("rules read-only configmap (every word must match):\n%s", out)
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules", "subPath"}, env) != 0 || !strings.Contains(out.String(), "KD234") {
		t.Errorf("rules subPath:\n%s", out)
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules", "probe", "names", "port"}, env) != 0 || !strings.Contains(out.String(), "KD203") || strings.Contains(out.String(), "KD202") {
		t.Errorf("rules probe names port:\n%s", out)
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules", "kd28"}, env) != 0 || !strings.Contains(out.String(), "KD280") || !strings.Contains(out.String(), "KD288") {
		t.Errorf("rules kd28 (KD280-KD288):\n%s", out)
	}
	for _, c := range []struct {
		words []string
		want  string
	}{
		{[]string{"subdomain"}, "KD266"},
		{[]string{"activeDeadlineSeconds"}, "KD195"},
		{[]string{"30", "February"}, "KD284"},
		{[]string{"headless", "targetPort"}, "KD265"},
		{[]string{"NodePorts"}, "KD243"},
		{[]string{"NodeAffinity"}, "KD242"},
		{[]string{"seccomp"}, "KD207"},
		{[]string{"RuntimeClass", "handler"}, "KD196"},
		{[]string{"preStop"}, "KD208"},
		{[]string{"gRPC"}, "KD209"},
		{[]string{"operating", "system"}, "KD244"},
		{[]string{"API", "server"}, "KD267"},
		{[]string{"startingDeadlineSeconds"}, "KD285"},
		{[]string{"port", "name", "pods", "do", "not", "declare"}, "KD268"},
		{[]string{"unit", "bytes"}, "KD210"},
		{[]string{"initialDelaySeconds"}, "KD211"},
		{[]string{"dnsConfig"}, "KD269"},
		{[]string{"ExternalName", "resolve"}, "KD270"},
		{[]string{"protocol"}, "KD271"},
		{[]string{"TLS", "cover"}, "KD272"},
		{[]string{"pile", "up"}, "KD286"},
		{[]string{"ReadWriteOnce", "replicas"}, "KD287"},
		{[]string{"podFailurePolicy"}, "KD110"},
		{[]string{"millicore"}, "KD140"},
		{[]string{"shell", "variable"}, "KD213"},
		{[]string{"hides", "command"}, "KD214"},
		{[]string{"localhost"}, "KD215"},
		{[]string{"another", "workload"}, "KD273"},
		{[]string{"minReadySeconds"}, "KD288"},
		{[]string{"LimitRange", "memory"}, "KD111"},
		{[]string{"defined", "before"}, "KD216"},
		{[]string{"localhost", "Service"}, "KD217"},
		{[]string{"expose"}, "KD218"},
		{[]string{"capability"}, "KD219"},
		{[]string{"flag", "argument"}, "KD221"},
		{[]string{"interpreter"}, "KD222"},
		{[]string{"service", "link"}, "KD223"},
		{[]string{"non-root", "image"}, "KD224"},
		{[]string{"refuse", "targets"}, "KD225"},
		{[]string{"PersistentVolume", "fits"}, "KD250"},
		{[]string{"Released"}, "KD251"},
		{[]string{"Lost", "claim"}, "KD252"},
		{[]string{"ResourceQuota", "requires"}, "KD293"},
		{[]string{"namespaceSelector"}, "KD274"},
		{[]string{"RoleBinding", "Role", "exist"}, "KD294"},
		{[]string{"RoleBinding", "ServiceAccount"}, "KD295"},
		{[]string{"init", "own"}, "KD220"},
		{[]string{"more", "PodDisruptionBudget"}, "KD289"},
		{[]string{"switched", "off"}, "KD290"},
		{[]string{"AmbiguousSelector"}, "KD291"},
		{[]string{"sidecar", "Job"}, "KD292"},
	} {
		env, out, _, _ = testEnv(nil)
		if Run(append([]string{"rules"}, c.words...), env) != 0 || !strings.Contains(out.String(), c.want) {
			t.Errorf("rules %s: want %s in\n%s", strings.Join(c.words, " "), c.want, out)
		}
	}
	env, out, _, _ = testEnv(nil)
	if Run([]string{"rules", "kd26"}, env) != 0 || strings.Count(out.String(), "\n") != 10 || !strings.HasPrefix(out.String(), "KD260") {
		t.Errorf("rules kd26 (KD260-KD269, 10 rules):\n%s", out)
	}
	env, _, errb, _ := testEnv(nil)
	if Run([]string{"rules", "KD9"}, env) != 2 || !strings.Contains(errb.String(), "no rule starts with KD9") {
		t.Errorf("rules KD9: %s", errb)
	}
	env, _, errb, _ = testEnv(nil)
	if Run([]string{"rules", "no-such-thing"}, env) != 2 || !strings.Contains(errb.String(), "no rule mentions no-such-thing") {
		t.Errorf("rules no-such-thing: %s", errb)
	}
	env, _, _, _ = testEnv(nil)
	if Run([]string{"-h"}, env) != 0 {
		t.Error("-h exits 0")
	}
}

// TestReadmeExampleIsWhatTheCodePrints keeps the README's example output identical to a real run on its snapshot.
func TestReadmeExampleIsWhatTheCodePrints(t *testing.T) {
	env, out, errb, _ := testEnv(nil)
	if code := Run([]string{"--snapshot", "../../testdata/faults/kd-liveness-wrong-port.snapshot.json.gz", "--color", "never"}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "$ kubectl diagnose -n kd-liveness-wrong-port\n"+out.String()+"```") {
		t.Errorf("README example is stale; the code prints:\n%s", out)
	}
}

// TestNoModuleDependencies holds the README's promise that the code uses the standard library only.
func TestNoModuleDependencies(t *testing.T) {
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mod), "require") {
		t.Error("go.mod has dependencies; the README and SECURITY.md say it has none")
	}
}

func TestRecordRedacted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shop.snapshot.json.gz")
	env, _, errb, _ := testEnv(broken())
	if code := Run([]string{"record", "-n", "shop", "--redact", "-o", path}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	s, err := snapshot.Read(path)
	if err != nil || !s.Redacted || s.Context != "" {
		t.Fatalf("%v %+v", err, s)
	}
	text := fmt.Sprint(s.Pods, s.Events)
	for _, gone := range []string{"web-1", "registry.example.com/web", "kind-faults"} {
		if strings.Contains(text, gone) {
			t.Errorf("%q survived redaction", gone)
		}
	}
	offline, out, _, _ := testEnv(nil)
	if Run([]string{"--snapshot", path}, offline) != 0 || !strings.Contains(out.String(), "KD101") {
		t.Errorf("redacted snapshot should diagnose the same: %s", out)
	}
}

func TestIgnoreRules(t *testing.T) {
	env, out, errb, _ := testEnv(broken())
	if code := Run([]string{"-n", "shop", "-o", "json", "--ignore", "kd101, KD168", "--fail-on", "critical"}, env); code != 0 {
		t.Errorf("the only finding is ignored, so --fail-on passes: exit %d", code)
	}
	if !strings.Contains(out.String(), `"findings": []`) || !strings.Contains(errb.String(), "1 findings of ignored rules left out") {
		t.Errorf("out %s err %s", out, errb)
	}
	env, _, errb, _ = testEnv(broken())
	if code := Run([]string{"-n", "shop", "--ignore", "KD999"}, env); code != 2 || !strings.Contains(errb.String(), "no rule KD999") {
		t.Errorf("unknown rule: exit %d, %s", code, errb)
	}
}
