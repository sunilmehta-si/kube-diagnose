package diagnose

import (
	"path/filepath"
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// TestRedactedSnapshotsDiagnoseTheSame holds redaction to its promise on every recorded fault: the redacted snapshot
// yields the same rules, kinds and severities as the original without its logs (redaction removes logs).
func TestRedactedSnapshotsDiagnoseTheSame(t *testing.T) {
	paths, _ := filepath.Glob("../../testdata/faults/*.snapshot.json.gz")
	for _, path := range paths {
		s, err := snapshot.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		red, err := snapshot.Redact(s)
		if err != nil {
			t.Fatal(err)
		}
		s.Logs = nil
		a, b := Diagnose(s), Diagnose(red)
		if len(a.Findings) != len(b.Findings) {
			t.Errorf("%s: %d findings, %d after redaction", filepath.Base(path), len(a.Findings), len(b.Findings))
			continue
		}
		for i := range a.Findings {
			x, y := a.Findings[i], b.Findings[i]
			if x.Rule != y.Rule || x.Object.Kind != y.Object.Kind || x.Severity != y.Severity || len(x.Evidence) != len(y.Evidence) {
				t.Errorf("%s: %s %s became %s %s", filepath.Base(path), x.Rule, x.Object.Kind, y.Rule, y.Object.Kind)
			}
		}
	}
}
