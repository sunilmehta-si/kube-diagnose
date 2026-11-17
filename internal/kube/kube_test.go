package kube

import (
	"encoding/json"
	"testing"
	"time"
)

func TestParseQuantity(t *testing.T) {
	cases := map[string]float64{
		"500m": 0.5, "2": 2, "1.5": 1.5, "100Mi": 100 << 20, "1Gi": 1 << 30, "128974848": 128974848,
		"129M": 129e6, "1e3": 1000, "1E3": 1000, "2E": 2e18, "0.1": 0.1, "250u": 250e-6, "3Ki": 3072, "1k": 1000,
	}
	for in, want := range cases {
		got, err := ParseQuantity(in)
		if err != nil || got != want {
			t.Errorf("ParseQuantity(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "Mi", "abc", "1.2.3Gi", "NaN"} {
		if _, err := ParseQuantity(bad); err == nil {
			t.Errorf("ParseQuantity(%q) accepted a bad quantity", bad)
		}
	}
}

func TestFormatQuantity(t *testing.T) {
	cases := []struct {
		res  string
		v    float64
		want string
	}{
		{"cpu", 0.25, "250m"}, {"cpu", 64, "64"}, {"memory", 1 << 30, "1Gi"}, {"memory", 1.5 * (1 << 20), "1.5Mi"},
		{"storage", 10 << 30, "10Gi"}, {"pods", 110, "110"},
	}
	for _, c := range cases {
		if got := FormatQuantity(c.res, c.v); got != c.want {
			t.Errorf("FormatQuantity(%s, %v) = %s; want %s", c.res, c.v, got, c.want)
		}
	}
}

func TestLabelSelector(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "front"}
	cases := []struct {
		sel  LabelSelector
		want bool
	}{
		{LabelSelector{}, true},
		{LabelSelector{MatchLabels: map[string]string{"app": "web"}}, true},
		{LabelSelector{MatchLabels: map[string]string{"app": "api"}}, false},
		{LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: "In", Values: []string{"front", "edge"}}}}, true},
		{LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "tier", Operator: "NotIn", Values: []string{"front"}}}}, false},
		{LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "zone", Operator: "NotIn", Values: []string{"a"}}}}, true},
		{LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "app", Operator: "Exists"}}}, true},
		{LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "app", Operator: "DoesNotExist"}}}, false},
		{LabelSelector{MatchExpressions: []LabelSelectorRequirement{{Key: "app", Operator: "Gt"}}}, false},
	}
	for i, c := range cases {
		if got := c.sel.Matches(labels); got != c.want {
			t.Errorf("case %d: Matches = %v; want %v", i, got, c.want)
		}
	}
	if !MatchesMap(map[string]string{"app": "web"}, labels) || MatchesMap(map[string]string{"app": "web", "x": "y"}, labels) {
		t.Error("MatchesMap wrong")
	}
	if got := FormatMap(map[string]string{"tier": "front", "app": "web"}); got != "app=web,tier=front" {
		t.Errorf("FormatMap = %s", got)
	}
}

func TestIntOrString(t *testing.T) {
	var ports []IntOrString
	if err := json.Unmarshal([]byte(`[8080, "http", "9090"]`), &ports); err != nil {
		t.Fatal(err)
	}
	if ports[0].Int != 8080 || ports[0].IsName || ports[1].Str != "http" || !ports[1].IsName || ports[2].Int != 9090 {
		t.Fatalf("decoded %+v", ports)
	}
	b, _ := json.Marshal(ports)
	if string(b) != `[8080,"http",9090]` {
		t.Errorf("round trip = %s", b)
	}
}

func TestEventLastAndTimes(t *testing.T) {
	t0 := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	e := Event{Count: 4, LastTimestamp: &t1, FirstTimestamp: &t0}
	if e.Last() != t1 || e.Times() != 4 {
		t.Errorf("legacy event: %v %d", e.Last(), e.Times())
	}
	t2 := t1.Add(time.Minute)
	e = Event{EventTime: &t0, Series: &EventSeries{Count: 7, LastObservedTime: t2}}
	if e.Last() != t2 || e.Times() != 7 {
		t.Errorf("series event: %v %d", e.Last(), e.Times())
	}
	if (Event{}).Times() != 1 {
		t.Error("an event happened at least once")
	}
}

func TestWorkloadDesiredAndControllerAndPolicyDefaults(t *testing.T) {
	var w Workload
	w.Kind = "Deployment"
	if w.Desired() != 1 {
		t.Error("a Deployment without replicas defaults to 1")
	}
	ds := Workload{Kind: "DaemonSet"}
	ds.Status.DesiredNumberScheduled, ds.Status.NumberReady = 3, 2
	if ds.Desired() != 3 || ds.Ready() != 2 {
		t.Error("DaemonSet counts come from its status")
	}
	yes := true
	m := ObjectMeta{OwnerReferences: []OwnerReference{{Kind: "X", Name: "a"}, {Kind: "ReplicaSet", Name: "web-1", Controller: &yes}}}
	if o, ok := m.Controller(); !ok || o.Name != "web-1" {
		t.Errorf("Controller = %+v %v", o, ok)
	}
	var np NetworkPolicy
	if !np.AppliesToIngress() {
		t.Error("a policy with no policyTypes restricts ingress")
	}
	np.Spec.PolicyTypes = []string{"Egress"}
	if np.AppliesToIngress() {
		t.Error("an egress-only policy does not restrict ingress")
	}
}

func TestPodMountsAndUser(t *testing.T) {
	var p Pod
	err := json.Unmarshal([]byte(`{"metadata":{"name":"web","namespace":"shop"},"spec":{
	  "hostNetwork":true,"dnsPolicy":"ClusterFirst","securityContext":{"runAsUser":1000,"fsGroup":2000},
	  "containers":[{"name":"web","image":"busybox","securityContext":{"runAsUser":1001},"volumeMounts":[
	    {"name":"data","mountPath":"/data"},{"name":"conf","mountPath":"/data/conf/","readOnly":true},
	    {"name":"scripts","mountPath":"/scripts"}]},
	    {"name":"side","image":"busybox","volumeMounts":[{"name":"data","mountPath":"/var/data","subPath":"side"}]}],
	  "volumes":[{"name":"data","hostPath":{"path":"/var/lib/data","type":"DirectoryOrCreate"}},
	    {"name":"conf","configMap":{"name":"app","defaultMode":420,"items":[{"key":"a","path":"a.yaml","mode":493}]}},
	    {"name":"scripts","emptyDir":{"sizeLimit":"10Mi"}}]}}`), &p)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Spec.HostNetwork || p.Spec.DNSPolicy != "ClusterFirst" || *p.Spec.SecurityContext.FSGroup != 2000 {
		t.Errorf("pod spec fields not decoded: %+v", p.Spec)
	}
	m, ok := p.MountAt("web", "/data/conf/a.yaml")
	if !ok || m.Name != "conf" || m.Rel != "a.yaml" || !m.ReadOnly || !m.Volume.AlwaysReadOnly() ||
		m.Volume.Source() != "ConfigMap app" || *m.Volume.ConfigMap.DefaultMode != 420 || *m.Volume.ConfigMap.Items[0].Mode != 493 {
		t.Errorf("MountAt(/data/conf/a.yaml) = %+v, %v", m, ok)
	}
	if m, ok := p.MountAt("web", "/data/x"); !ok || m.Name != "data" || m.Rel != "x" || m.Volume.Source() != "hostPath /var/lib/data" {
		t.Errorf("MountAt(/data/x) = %+v, %v", m, ok)
	}
	if m, ok := p.MountAt("web", "/scripts"); !ok || m.Rel != "" || m.Volume.EmptyDir.SizeLimit != "10Mi" {
		t.Errorf("MountAt(/scripts) = %+v, %v", m, ok)
	}
	for _, path := range []string{"/datax/y", "/etc/x"} {
		if m, ok := p.MountAt("web", path); ok {
			t.Errorf("MountAt(%s) = %+v; want no mount", path, m)
		}
	}
	if m, ok := p.MountAt("side", "/var/data/f"); !ok || m.SubPath != "side" {
		t.Errorf("MountAt(side, /var/data/f) = %+v, %v", m, ok)
	}
	if u, ok := p.RunAsUser("web"); !ok || u != 1001 {
		t.Errorf("RunAsUser(web) = %d, %v; want the container's 1001", u, ok)
	}
	if u, ok := p.RunAsUser("side"); !ok || u != 1000 {
		t.Errorf("RunAsUser(side) = %d, %v; want the pod's 1000", u, ok)
	}
}
