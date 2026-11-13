package diagnose

import (
	"strings"
	"testing"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/collect"
	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// Builders for the objects a test snapshot needs. Each returns a value a test can tweak before adding it.

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

func yes() *bool { b := true; return &b }

func snap() *snapshot.Snapshot {
	return &snapshot.Snapshot{SchemaVersion: snapshot.SchemaVersion, CollectedAt: t0, Namespaces: []string{"shop"},
		Nodes: []kube.Node{node("node-1", "8", "32Gi")}}
}

func node(name, cpu, mem string) kube.Node {
	var n kube.Node
	n.Metadata = kube.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/hostname": name}}
	n.Status.Allocatable = map[string]string{"cpu": cpu, "memory": mem, "pods": "110"}
	n.Status.Conditions = []kube.Condition{{Type: "Ready", Status: "True"}}
	return n
}

// pod returns a running, ready pod of Deployment owner (via ReplicaSet owner-rs), or a bare pod when owner is "".
func pod(name, owner string) kube.Pod {
	p := kube.Pod{Metadata: kube.ObjectMeta{Name: name, Namespace: "shop", Labels: map[string]string{"app": "web"}}}
	if owner != "" {
		p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "ReplicaSet", Name: owner + "-rs", Controller: yes()}}
	}
	p.Spec.Containers = []kube.Container{{Name: "web", Image: "registry.example.com/shop/web:1.4.2",
		Ports: []kube.ContainerPort{{Name: "http", ContainerPort: 8080}}}}
	p.Spec.NodeName = "node-1"
	p.Status.Phase = "Running"
	p.Status.Conditions = []kube.Condition{{Type: "PodScheduled", Status: "True"}, {Type: "Ready", Status: "True"}}
	p.Status.ContainerStatuses = []kube.ContainerStatus{{Name: "web", Ready: true, State: kube.ContainerState{Running: &kube.ContainerStateRunning{StartedAt: t0}}}}
	return p
}

func notReady(p *kube.Pod) {
	p.Status.Conditions[1].Status = "False"
	p.Status.ContainerStatuses[0].Ready = false
}

func waiting(p *kube.Pod, reason, msg string) {
	notReady(p)
	p.Status.ContainerStatuses[0].State = kube.ContainerState{Waiting: &kube.ContainerStateWaiting{Reason: reason, Message: msg}}
}

func crashed(p *kube.Pod, code int32, reason string, restarts int32) {
	waiting(p, "CrashLoopBackOff", "back-off 5m0s restarting failed container")
	p.Status.ContainerStatuses[0].RestartCount = restarts
	p.Status.ContainerStatuses[0].LastTerminationState = kube.ContainerState{Terminated: &kube.ContainerStateTerminated{ExitCode: code, Reason: reason}}
}

// deployment adds Deployment name, its ReplicaSet name-rs, with the given replicas and ready count.
func deployment(s *snapshot.Snapshot, name string, replicas, ready int32) {
	d := kube.Workload{Kind: "Deployment", Metadata: kube.ObjectMeta{Name: name, Namespace: "shop"}}
	d.Spec.Replicas = &replicas
	d.Spec.Template.Metadata.Labels = map[string]string{"app": "web"}
	d.Status.Replicas, d.Status.ReadyReplicas = replicas, ready
	rs := kube.Workload{Kind: "ReplicaSet", Metadata: kube.ObjectMeta{Name: name + "-rs", Namespace: "shop",
		OwnerReferences: []kube.OwnerReference{{Kind: "Deployment", Name: name, Controller: yes()}}}}
	rs.Spec.Replicas = &replicas
	rs.Status.Replicas, rs.Status.ReadyReplicas = replicas, ready
	s.Workloads = append(s.Workloads, d, rs)
}

func event(kind, name, reason, msg string, ago time.Duration) kube.Event {
	var e kube.Event
	e.InvolvedObject.Kind, e.InvolvedObject.Namespace, e.InvolvedObject.Name = kind, "shop", name
	if kind == "Node" || kind == "StorageClass" {
		e.InvolvedObject.Namespace = ""
	}
	e.Reason, e.Message, e.Type, e.Count = reason, msg, "Warning", 3
	last := t0.Add(-ago)
	e.LastTimestamp = &last
	return e
}

func service(name string, selector map[string]string, target kube.IntOrString) kube.Service {
	var s kube.Service
	s.Metadata = kube.ObjectMeta{Name: name, Namespace: "shop"}
	s.Spec.Type, s.Spec.Selector = "ClusterIP", selector
	s.Spec.Ports = []kube.ServicePort{{Port: 80, TargetPort: target}}
	return s
}

func slice(svc string, ready int) kube.EndpointSlice {
	e := kube.EndpointSlice{Metadata: kube.ObjectMeta{Name: svc + "-abc", Namespace: "shop",
		Labels: map[string]string{"kubernetes.io/service-name": svc}}}
	for i := 0; i < ready; i++ {
		e.Endpoints = append(e.Endpoints, kube.Endpoint{Addresses: []string{"10.0.0.1"}, Conditions: kube.EndpointConditions{Ready: yes()}})
	}
	return e
}

func port(n int32) kube.IntOrString   { return kube.IntOrString{Int: n} }
func named(s string) kube.IntOrString { return kube.IntOrString{Str: s, IsName: true} }
func strp(s string) *string           { return &s }
func keys(ns, name string, k ...string) kube.KeySet {
	return kube.KeySet{Namespace: ns, Name: name, Keys: k}
}

// only returns the single finding, failing the test when there is not exactly one.
func only(t *testing.T, r Report) Finding {
	t.Helper()
	if len(r.Findings) != 1 {
		var rules []string
		for _, f := range r.Findings {
			rules = append(rules, f.Rule+" "+f.Object.String()+": "+f.Cause)
		}
		t.Fatalf("want 1 finding, got %d:\n%s", len(r.Findings), strings.Join(rules, "\n"))
	}
	return r.Findings[0]
}

func expect(t *testing.T, f Finding, rule string, object string, causeHas ...string) {
	t.Helper()
	if f.Rule != rule {
		t.Errorf("rule = %s; want %s (cause: %s)", f.Rule, rule, f.Cause)
	}
	if f.Object.String() != object {
		t.Errorf("object = %s; want %s", f.Object, object)
	}
	for _, s := range causeHas {
		if !strings.Contains(f.Cause, s) {
			t.Errorf("cause %q does not mention %q", f.Cause, s)
		}
	}
	if len(f.Evidence) == 0 || f.Fix == "" || f.Title == "" {
		t.Errorf("finding without evidence, title or fix: %+v", f)
	}
	for _, e := range f.Evidence {
		checkCommand(t, e.Command)
	}
}

// checkCommand holds every cited command to the collector's read-only allowlist.
func checkCommand(t *testing.T, cmd string) {
	t.Helper()
	args := shellWords(cmd)
	if len(args) < 2 || args[0] != "kubectl" {
		t.Errorf("evidence command %q is not a kubectl command", cmd)
		return
	}
	if err := collect.CheckReadOnly(args[1:]); err != nil {
		t.Errorf("evidence command %q is not read-only: %v", cmd, err)
	}
}

// shellWords splits a command line on spaces, keeping single-quoted words whole, as a POSIX shell would for the
// commands this package writes.
func shellWords(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, has := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inQuote, has = !inQuote, true
		case c == '\\' && !inQuote && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == ' ' && !inQuote:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}
