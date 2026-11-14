package snapshot

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
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
	r.addImage("ghcr.io/acme/web:2.0")
	r.build()
	got := r.text(`pod "web-rs-a" for Service web, webhook web.shop.svc, image ghcr.io/acme/web:2.0 at 10.244.0.7:8080`)
	for _, gone := range []string{`"web-rs-a"`, "Service web,", "ghcr.io/acme/web", "10.244.0.7"} {
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
