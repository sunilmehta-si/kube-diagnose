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
