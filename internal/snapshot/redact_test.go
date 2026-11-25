package snapshot

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

func TestRedactRemovesIdentifiersAndKeepsShape(t *testing.T) {
	paths, _ := filepath.Glob("../../testdata/faults/*.snapshot.json.gz")
	if len(paths) < 20 {
		t.Fatalf("recorded snapshots: %d", len(paths))
	}
	for _, path := range paths {
		s, err := Read(path)
		if err != nil {
			t.Fatal(err)
		}
		red, err := redactWithKey(s, []byte("test-key"))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(red)
		text := string(b)
		var secrets []string
		secrets = append(secrets, s.Namespaces...)
		for _, p := range s.Pods {
			secrets = append(secrets, p.Metadata.Name, p.Spec.NodeName)
			for _, c := range p.Spec.Containers {
				secrets = append(secrets, imageRepository(c.Image))
			}
		}
		for _, sec := range secrets {
			if sec != "" && strings.Contains(text, sec) {
				t.Errorf("%s: redacted snapshot still contains %q", filepath.Base(path), sec)
			}
		}
		if !red.Redacted || red.Context != "" || len(red.Logs) != 0 || len(red.Pods) != len(s.Pods) || len(red.Events) != len(s.Events) {
			t.Errorf("%s: shape changed: redacted=%v context=%q logs=%d pods %d/%d", filepath.Base(path), red.Redacted, red.Context, len(red.Logs), len(red.Pods), len(s.Pods))
		}
		again, _ := redactWithKey(s, []byte("test-key"))
		if b2, _ := json.Marshal(again); string(b2) != text {
			t.Errorf("%s: redaction is not deterministic for one key", filepath.Base(path))
		}
	}
}

func TestRedactKeepsTokensWhole(t *testing.T) {
	r := &redactor{key: []byte("k"), names: map[string]string{}, images: map[string]string{}, ips: map[string]string{}}
	r.addName("svc", "web")
	r.addName("pod", "web-rs-a")
	r.addName("ns", "shop")
	r.addImage("ghcr.io/acme/web:2.0")
	r.build()
	got := r.text(`pod "web-rs-a" for Service web, webhook web.shop.svc, image ghcr.io/acme/web:2.0 at 10.244.0.7:8080, wget http://api.shop.svc.cluster.local/`)
	for _, gone := range []string{`"web-rs-a"`, "Service web,", "ghcr.io/acme/web", "10.244.0.7", ".shop.svc"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q still in %q", gone, got)
		}
	}
	for _, kept := range []string{"webhook", ":2.0", ":8080", "registry.invalid/image-"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q missing from %q", kept, got)
		}
	}
}

// TestRedactNamesObjectsThatDoNotExist covers the names a snapshot holds only as references: a missing ConfigMap,
// Secret, claim, Service or TLS Secret is named by the diagnosis, so it must be pseudonymised too.
func TestRedactNamesObjectsThatDoNotExist(t *testing.T) {
	var p kube.Pod
	p.Metadata = kube.ObjectMeta{Name: "web-1", Namespace: "shop"}
	p.Spec.Containers = []kube.Container{{Name: "web", Image: "nginx", EnvFrom: []kube.EnvFromSource{{ConfigMapRef: &kube.NameRef{Name: "web-config"}}},
		Env:            []kube.EnvVar{{Name: "DB", ValueFrom: &kube.EnvVarSource{SecretKeyRef: &kube.KeyRef{Name: "db-password", Key: "pw"}}}},
		ReadinessProbe: &kube.Probe{HTTPGet: &kube.HTTPGetAction{Host: "health.corp.acme.example", Port: kube.IntOrString{Int: 8080}}},
		LivenessProbe:  &kube.Probe{TCPSocket: &kube.TCPSocketAction{Host: "192.168.40.12", Port: kube.IntOrString{Int: 8080}}}}}
	p.Status.PodIP = "172.16.9.4"
	p.Spec.Volumes = []kube.Volume{{Name: "data", PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "orders-data"}}}
	projected := kube.ProjectedSource{ConfigMap: &kube.ConfigMapVolumeSource{Name: "feature-flags"}}
	projected.Secret = &struct {
		Name     string           `json:"name"`
		Items    []kube.KeyToPath `json:"items,omitempty"`
		Optional *bool            `json:"optional,omitempty"`
	}{Name: "partner-api-keys"}
	p.Spec.Volumes = append(p.Spec.Volumes, kube.Volume{Name: "bundle", Projected: &kube.ProjectedVolumeSource{Sources: []kube.ProjectedSource{projected}}})
	p.Spec.ImagePullSecrets = []kube.LocalObjectReference{{Name: "regcred"}}
	var ss kube.Workload
	ss.Kind, ss.Metadata = "StatefulSet", kube.ObjectMeta{Name: "db", Namespace: "shop"}
	ss.Spec.ServiceName = "db-headless"
	var ing kube.Ingress
	ing.Metadata = kube.ObjectMeta{Name: "shop", Namespace: "shop"}
	ing.Spec.DefaultBackend = &kube.IngressBackend{Service: &kube.IngressServiceBackend{Name: "storefront"}}
	ing.Spec.TLS = []kube.IngressTLS{{Hosts: []string{"shop.acme.example"}, SecretName: "acme-tls"}}
	var svc kube.Service
	svc.Metadata = kube.ObjectMeta{Name: "web", Namespace: "shop"}
	svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, struct {
		IP       string `json:"ip,omitempty"`
		Hostname string `json:"hostname,omitempty"`
	}{Hostname: "a1b2.elb.acme.example"})
	var job kube.Job
	job.Metadata = kube.ObjectMeta{Name: "nightly-29001", Namespace: "shop", OwnerReferences: []kube.OwnerReference{{Kind: "CronJob", Name: "nightly-export"}}}
	// A volume reserved for a claim that is gone names that claim (KD157), and a Job waiting for Kueue names its queue.
	var pv kube.PersistentVolume
	pv.Metadata.Name = "orders-pv"
	pv.Spec.ClaimRef = &kube.ClaimReference{Namespace: "shop", Name: "orders-data-old"}
	job.Metadata.Labels = map[string]string{"kueue.x-k8s.io/queue-name": "team-payments"}
	var cj kube.CronJob
	cj.Metadata = kube.ObjectMeta{Name: "invoice-sweep", Namespace: "shop"}
	cj.Status.Active = append(cj.Status.Active, struct {
		Name string `json:"name"`
	}{Name: "invoice-sweep-29002"})
	s := &Snapshot{SchemaVersion: SchemaVersion, Namespaces: []string{"shop"}, Pods: []kube.Pod{p}, Workloads: []kube.Workload{ss},
		Ingresses: []kube.Ingress{ing}, Services: []kube.Service{svc}, Jobs: []kube.Job{job}, CronJobs: []kube.CronJob{cj}, PVs: []kube.PersistentVolume{pv}}
	red, err := redactWithKey(s, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(red)
	for _, name := range []string{"web-config", "db-password", "orders-data", "regcred", "db-headless", "storefront", "acme-tls", "shop.acme.example", "a1b2.elb.acme.example", "nightly-export",
		"orders-pv", "orders-data-old", "team-payments", "invoice-sweep", "feature-flags", "partner-api-keys",
		"health.corp.acme.example", "192.168.40.12", "172.16.9.4"} {
		if strings.Contains(string(b), name) {
			t.Errorf("redacted snapshot still contains %q", name)
		}
	}
}

// TestRedactKeepsASliceNamedForItsService covers an EndpointSlice named for its Service: after redaction it is still
// named for the Service's pseudonym, so KD264 can link a slice that lacks its label, and a suffix someone wrote is
// replaced, not kept.
func TestRedactKeepsASliceNamedForItsService(t *testing.T) {
	var svc kube.Service
	svc.Metadata = kube.ObjectMeta{Name: "payments", Namespace: "shop"}
	gen := kube.EndpointSlice{Metadata: kube.ObjectMeta{Name: "payments-1", Namespace: "shop"}}
	wrote := kube.EndpointSlice{Metadata: kube.ObjectMeta{Name: "payments-acme-internal", Namespace: "shop"}}
	other := kube.EndpointSlice{Metadata: kube.ObjectMeta{Name: "paymentsdb", Namespace: "shop"}}
	s := &Snapshot{SchemaVersion: SchemaVersion, Namespaces: []string{"shop"}, Services: []kube.Service{svc}, EndpointSlices: []kube.EndpointSlice{gen, wrote, other}}
	red, err := redactWithKey(s, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	p := red.Services[0].Metadata.Name
	if got := red.EndpointSlices[0].Metadata.Name; got != p+"-1" {
		t.Errorf("slice payments-1 became %q, want %q", got, p+"-1")
	}
	if got := red.EndpointSlices[1].Metadata.Name; !strings.HasPrefix(got, p+"-") || strings.Contains(got, "acme") || strings.Contains(got, "internal") {
		t.Errorf("slice payments-acme-internal became %q", got)
	}
	if got := red.EndpointSlices[2].Metadata.Name; strings.HasPrefix(got, p) || strings.Contains(got, "payments") {
		t.Errorf("slice paymentsdb became %q", got)
	}
}

// TestRedactLeavesLoopbackAddresses covers the addresses that name no machine: an app bound to 127.0.0.1 is a fault a
// diagnosis has to see after redaction, while every other address is still replaced.
func TestRedactLeavesLoopbackAddresses(t *testing.T) {
	r := &redactor{key: []byte("k"), names: map[string]string{}, images: map[string]string{}, ips: map[string]string{}}
	r.build()
	got := r.text("httpd -p 127.0.0.1:8080, uvicorn --host 0.0.0.0, peer 192.168.40.12:443, dial tcp 10.244.0.9:8080")
	for _, kept := range []string{"127.0.0.1:8080", "--host 0.0.0.0"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q missing from %q", kept, got)
		}
	}
	for _, gone := range []string{"192.168.40.12", "10.244.0.9"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q still in %q", gone, got)
		}
	}
}

func TestRedactRenamesEveryNamespaceOfTheCluster(t *testing.T) {
	s := &Snapshot{SchemaVersion: SchemaVersion, Namespaces: []string{"shop"}}
	s.NamespaceObjects = []kube.Namespace{
		{Metadata: kube.ObjectMeta{Name: "shop", Labels: map[string]string{"kubernetes.io/metadata.name": "shop", "team": "storefront"}}},
		{Metadata: kube.ObjectMeta{Name: "payments-prod", Labels: map[string]string{"kubernetes.io/metadata.name": "payments-prod"}}},
	}
	out, err := Redact(s)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	for _, leaked := range []string{"shop", "payments-prod", "storefront"} {
		if strings.Contains(string(b), leaked) {
			t.Errorf("%q survives redaction: %s", leaked, b)
		}
	}
	// A namespace's own name label still equals its name, so a selector on it matches as before.
	for _, n := range out.NamespaceObjects {
		if n.Metadata.Labels["kubernetes.io/metadata.name"] != n.Metadata.Name {
			t.Errorf("name label %q differs from name %q", n.Metadata.Labels["kubernetes.io/metadata.name"], n.Metadata.Name)
		}
	}
	if out.NamespaceObjects[0].Metadata.Name != out.Namespaces[0] {
		t.Errorf("namespace renamed two ways: %q and %q", out.NamespaceObjects[0].Metadata.Name, out.Namespaces[0])
	}
}

func TestRedactRenamesRolesAndKeepsBuiltInClusterRoles(t *testing.T) {
	s := &Snapshot{SchemaVersion: SchemaVersion, Namespaces: []string{"shop"}}
	s.Roles = []kube.Role{{Metadata: kube.ObjectMeta{Name: "billing-reader", Namespace: "shop"}}}
	var own, builtin kube.RoleBinding
	own.Metadata = kube.ObjectMeta{Name: "billing-read", Namespace: "shop"}
	own.RoleRef.Kind, own.RoleRef.Name = "Role", "ledger-reader" // a Role that does not exist is still a name
	own.Subjects = []kube.Subject{{Kind: "ServiceAccount", Name: "invoicer", Namespace: "shop"}, {Kind: "User", Name: "priya@example.com"}}
	builtin.Metadata = kube.ObjectMeta{Name: "viewers", Namespace: "shop"}
	builtin.RoleRef.Kind, builtin.RoleRef.Name = "ClusterRole", "view"
	s.RoleBindings = []kube.RoleBinding{own, builtin}
	s.ClusterRoles = []string{"acme-operator", "system:node", "view"}
	s.Events = []kube.Event{{Message: "the view of the ledger-reader role"}}
	out, err := Redact(s)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	for _, leaked := range []string{"billing-reader", "billing-read", "ledger-reader", "invoicer", "priya@example.com", "acme-operator", "shop"} {
		if strings.Contains(string(b), leaked) {
			t.Errorf("%q survives redaction: %s", leaked, b)
		}
	}
	if out.RoleBindings[1].RoleRef.Name != "view" || out.ClusterRoles[1] != "system:node" || out.ClusterRoles[2] != "view" {
		t.Errorf("built-in ClusterRoles should keep their names: %+v %v", out.RoleBindings[1].RoleRef, out.ClusterRoles)
	}
	// "view" is also a word, and stays one.
	if !strings.HasPrefix(out.Events[0].Message, "the view of the ") {
		t.Errorf("message %q", out.Events[0].Message)
	}
}

func TestRedactRenamesTheGatewayAPIsObjects(t *testing.T) {
	var gw kube.Gateway
	gw.Metadata = kube.ObjectMeta{Name: "acme-public", Namespace: "shop"}
	gw.Spec.GatewayClassName = "acme-envoy"
	gw.Spec.Listeners = []kube.Listener{{Name: "https", Hostname: "*.shop.acme.example", Port: 443, Protocol: "HTTPS"}}
	var class kube.GatewayClass
	class.Metadata.Name = "acme-envoy"
	var rt kube.Route
	rt.Kind, rt.Metadata = "HTTPRoute", kube.ObjectMeta{Name: "checkout-route", Namespace: "shop"}
	rt.Spec.Hostnames = []string{"pay.shop.acme.example"}
	rt.Spec.ParentRefs = []kube.ParentRef{{Name: "acme-public", Namespace: "edge-gateways", SectionName: "https"}}
	rt.Spec.Rules = append(rt.Spec.Rules, kube.RouteRule{BackendRefs: []kube.BackendRef{{Name: "checkout-v2"}}})
	s := &Snapshot{SchemaVersion: SchemaVersion, Namespaces: []string{"shop"}, Gateways: []kube.Gateway{gw}, GatewayClasses: []kube.GatewayClass{class}, Routes: []kube.Route{rt}}
	red, err := redactWithKey(s, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(red)
	for _, name := range []string{"acme-public", "acme-envoy", "shop.acme.example", "checkout-route", "pay.", "acme", "edge-gateways", "checkout-v2"} {
		if strings.Contains(string(b), name) {
			t.Errorf("redacted snapshot still contains %q", name)
		}
	}
	// The wildcard listener still covers the route's hostname, label for label.
	l, h := red.Gateways[0].Spec.Listeners[0].Hostname, red.Routes[0].Spec.Hostnames[0]
	if !strings.HasPrefix(l, "*.") || !strings.HasSuffix(h, l[1:]) || h == l[2:] {
		t.Errorf("listener %q, route %q", l, h)
	}
	// The route still names its Gateway and its listener, so the diagnosis of the redacted snapshot is the same.
	if red.Routes[0].Spec.ParentRefs[0].Name != red.Gateways[0].Metadata.Name || red.Routes[0].Spec.ParentRefs[0].SectionName != "https" || red.Routes[0].Kind != "HTTPRoute" {
		t.Errorf("route %+v, gateway %+v", red.Routes[0].Spec.ParentRefs, red.Gateways[0].Metadata)
	}
}

func TestRedactRenamesDynamicResourceAllocationsObjects(t *testing.T) {
	var p kube.Pod
	p.Metadata = kube.ObjectMeta{Name: "trainer-0", Namespace: "ml"}
	p.Spec.ResourceClaims = []kube.PodResourceClaim{{Name: "gpu", ResourceClaimName: "acme-a100-pair"}, {Name: "nic", ResourceClaimTemplateName: "acme-rdma"}}
	var claim kube.ResourceClaim
	claim.Metadata = kube.ObjectMeta{Name: "acme-a100-pair", Namespace: "ml"}
	claim.Spec.Devices.Requests = []kube.DeviceRequest{{Name: "gpu", Exactly: &kube.ExactDeviceRequest{DeviceClassName: "gpu.nvidia.com", Count: 2}}}
	var sl kube.ResourceSlice
	sl.Metadata.Name = "gpu-node-17-gpu.nvidia.com-x2k9"
	sl.Spec.Driver, sl.Spec.NodeName, sl.Spec.Pool.Name = "gpu.nvidia.com", "gpu-node-17", "gpu-node-17"
	s := &Snapshot{SchemaVersion: SchemaVersion, Namespaces: []string{"ml"}, Pods: []kube.Pod{p}, ResourceAllocationRead: true,
		ResourceClaims: []kube.ResourceClaim{claim}, ResourceSlices: []kube.ResourceSlice{sl}}
	red, err := redactWithKey(s, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(red)
	for _, name := range []string{"acme-a100-pair", "acme-rdma", "gpu-node-17", "trainer-0"} {
		if strings.Contains(string(b), name) {
			t.Errorf("redacted snapshot still contains %q", name)
		}
	}
	// The pod still names its claim, and the claim its class and the slice its driver, so the diagnosis is the same.
	if red.Pods[0].Spec.ResourceClaims[0].ResourceClaimName != red.ResourceClaims[0].Metadata.Name || red.Pods[0].Spec.ResourceClaims[0].Name != "gpu" {
		t.Errorf("pod %+v, claim %+v", red.Pods[0].Spec.ResourceClaims, red.ResourceClaims[0].Metadata)
	}
	if red.ResourceClaims[0].Spec.Devices.Requests[0].Exactly.DeviceClassName != "gpu.nvidia.com" || red.ResourceSlices[0].Spec.Driver != "gpu.nvidia.com" || !red.ResourceAllocationRead {
		t.Errorf("claim %+v, slice %+v", red.ResourceClaims[0].Spec, red.ResourceSlices[0].Spec)
	}
}
