package faults

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/diagnose"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// TestRecordedFaultsAreDiagnosed replays every namespace the fault suite recorded on kind through today's code:
// each fault's first finding must be the expected rule on the expected object and name the cause, and the healthy
// namespace must have no finding. It is the fault suite without a cluster.
func TestRecordedFaultsAreDiagnosed(t *testing.T) {
	ss, err := Load("../../faults")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range ss {
		t.Run(s.Name, func(t *testing.T) {
			path := filepath.Join("../../testdata/faults", s.Namespace+".snapshot.json.gz")
			if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
				t.Skip("no recording yet: a scenario is recorded by the fault suite's next run in CI")
			}
			snap, err := snapshot.Read(path)
			if err != nil {
				t.Fatal(err)
			}
			r := diagnose.Diagnose(snap)
			if s.Healthy() {
				if len(r.Findings) != 0 {
					t.Errorf("false alarms: %+v", r.Findings)
				}
				return
			}
			b, _ := json.Marshal(r)
			items, back, err := KubeDiagnoseItems(b)
			if err != nil {
				t.Fatal(err)
			}
			if o := Judge(s, items); !o.First || !Exact(s, back) {
				var got []string
				for _, it := range items {
					got = append(got, it.Text)
				}
				t.Errorf("want %s on %s naming %v; got:\n%s", s.Rule, s.Object, s.Keywords, strings.Join(got, "\n"))
			}
		})
	}
}

// TestReadmeShowsTheCommittedRun holds the README's results table to the tool outputs committed from that run.
func TestReadmeShowsTheCommittedRun(t *testing.T) {
	ss, err := Load("../../faults")
	if err != nil {
		t.Fatal(err)
	}
	// The committed run covers the scenarios that existed when it ran; newer ones join at the next committed run.
	var inRun []Scenario
	for _, s := range ss {
		if _, err := os.Stat(filepath.Join("../../results/faults/kube-diagnose", s.Namespace+".json")); err == nil {
			inRun = append(inRun, s)
		}
	}
	r, err := Score(inRun, "../../results/faults")
	if err != nil {
		t.Fatal(err)
	}
	if r.Totals["kube-diagnose"].Ran != r.Totals["kube-diagnose"].Faults || r.Totals["k8sgpt"].Ran != r.Totals["k8sgpt"].Faults {
		t.Fatalf("the committed run is incomplete: %+v", r.Totals)
	}
	readme, _ := os.ReadFile("../../README.md")
	if !strings.Contains(string(readme), Markdown(r)) {
		t.Errorf("README's fault-suite table is stale; it should read:\n%s", Markdown(r))
	}
}

// TestReadmeDescribesK8sGPTsOutput checks what the README says k8sgpt reported, against its committed output.
func TestReadmeDescribesK8sGPTsOutput(t *testing.T) {
	text := func(ns string) (string, int) {
		b, err := os.ReadFile(filepath.Join("../../results/faults/k8sgpt", ns+".json"))
		if err != nil {
			t.Fatal(err)
		}
		items, err := K8sGPTItems(b)
		if err != nil {
			t.Fatal(err)
		}
		var all []string
		for _, it := range items {
			all = append(all, it.Text)
		}
		return strings.Join(all, "\n"), len(items)
	}
	if got, _ := text("kd-crashloop-missing-env"); !strings.Contains(got, "termination reason is Error") || strings.Contains(got, "DATABASE_URL") {
		t.Errorf("crash: %s", got)
	}
	// k8sgpt's answer for the liveness probe flips run to run: nothing, or the termination reason. The README says
	// which the committed run gave; it never names the probe.
	readme, _ := os.ReadFile("../../README.md")
	flat := strings.Join(strings.Fields(string(readme)), " ")
	switch got, n := text("kd-liveness-wrong-port"); {
	case strings.Contains(strings.ToLower(got), "probe"):
		t.Errorf("liveness: k8sgpt named the probe, and the README says it never does: %s", got)
	case n == 0 && !strings.Contains(flat, "for the liveness probe on the wrong port it reported nothing this time"):
		t.Error("liveness: k8sgpt reported nothing; the README should say so")
	case n > 0 && (!strings.Contains(got, "the last termination reason is Error") || !strings.Contains(flat, "for the liveness probe on the wrong port it said only that the last termination reason")):
		t.Errorf("liveness: the README should say k8sgpt gave only the termination reason: %s", got)
	}
	sel, _ := text("kd-node-selector")
	if !strings.Contains(sel, "didn't match Pod's node affinity/selector") || strings.Contains(sel, "disktype") {
		t.Errorf("node selector: %s", sel)
	}
	gateway, _ := filepath.Glob("../../results/faults/k8sgpt/kd-gateway-*.json")
	if len(gateway) != 12 {
		t.Errorf("the README says twelve Gateway API scenarios; results hold %d", len(gateway))
	}
	nss := []string{"kd-networkpolicy-deny-all"}
	for _, f := range gateway {
		nss = append(nss, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	for _, ns := range nss {
		if _, n := text(ns); n != 0 {
			t.Errorf("%s: k8sgpt reported %d results; the README says none", ns, n)
		}
	}
}
