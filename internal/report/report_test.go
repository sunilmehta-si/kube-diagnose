package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/diagnose"
	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

func sample() diagnose.Report {
	pod := kube.Ref{Kind: "Pod", Namespace: "shop", Name: "web-7d9c-a"}
	return diagnose.Report{Context: "kind-faults", Namespaces: []string{"shop"}, CollectedAt: "2026-11-13 10:00 UTC",
		Findings: []diagnose.Finding{{
			Rule: "KD110", Title: "Container keeps crashing", Severity: diagnose.Critical,
			Object: kube.Ref{Kind: "Deployment", Namespace: "shop", Name: "web"},
			Cause:  `container web exits with code 1 (the app reported an error); its log says: "error: DATABASE_URL is not set" (Deployment has 0 of 3 replicas ready)`,
			Evidence: []diagnose.Evidence{
				{Object: pod, What: "container web exited with code 1 (Error), restarted 6 times", Command: "kubectl get pod web-7d9c-a -n shop"},
				{Object: pod, What: "last lines of container web's log (run that exited)", Detail: "starting\nerror: DATABASE_URL is not set",
					Command: "kubectl logs web-7d9c-a -n shop -c web --tail=20 --previous"},
				{Object: kube.Ref{Kind: "Node", Name: "*"}, What: "node taints", Command: "kubectl get nodes"},
			},
			Fix:     "Fix what the log reports.",
			Affects: []kube.Ref{pod, {Kind: "Pod", Namespace: "shop", Name: "web-7d9c-b"}, {Kind: "Service", Namespace: "shop", Name: "web"}},
		}, {
			Rule: "KD164", Title: "Service targets a port the pods do not declare", Severity: diagnose.Warning,
			Object: kube.Ref{Kind: "Service", Namespace: "shop", Name: "api"}, Cause: "port | mismatch <80>",
			Evidence: []diagnose.Evidence{{Object: kube.Ref{Kind: "Service", Namespace: "shop", Name: "api"}, What: "targetPort 80", Command: "kubectl get service api -n shop"}},
			Fix:      "Set targetPort.",
		}},
		Gaps:    []snapshot.Gap{{Resource: "nodes", Error: "forbidden"}},
		Checked: diagnose.Checked{Pods: 3, Services: 2},
	}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sample(), Style{Width: 80}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"kube-diagnose · context kind-faults · namespace shop · 2026-11-13 10:00 UTC\n2 problems: 1 critical, 1 warning.\n",
		"1. CRITICAL  Container keeps crashing  KD110\n   Deployment shop/web\n   Cause: container web exits",
		"     [2] Pod shop/web-7d9c-a: last lines of container web's log (run that\n         exited)\n         │ starting\n         │ error: DATABASE_URL is not set\n         $ kubectl logs",
		"     [3] node taints\n",
		"   Affects: Pods web-7d9c-a, web-7d9c-b; Service web\n",
		"2. WARNING  Service targets a port",
		"Could not read (findings that need these may be missing):\n  - nodes: forbidden\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len([]rune(line)) > 80 && !strings.Contains(line, "$ ") && !strings.Contains(line, "│") {
			t.Errorf("prose line over 80 columns: %q", line)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour off")
	}
	b.Reset()
	Text(&b, sample(), Style{Color: true})
	if !strings.Contains(b.String(), "\x1b[31;1mCRITICAL\x1b[0m") || !strings.Contains(b.String(), "\x1b[33;1mWARNING") {
		t.Error("severity colours")
	}
}

func TestTextWithNoFindings(t *testing.T) {
	var b bytes.Buffer
	r := diagnose.Report{Checked: diagnose.Checked{Pods: 12, Services: 1, PVCs: 0, Nodes: 3}}
	Text(&b, r, Style{})
	if !strings.Contains(b.String(), "all namespaces") || !strings.Contains(b.String(), "No problems found in 12 pods, 1 Service, 0 PersistentVolumeClaims and 3 nodes.") {
		t.Errorf("%s", b.String())
	}
}

// TestSummaryCountsInfoAsNotes keeps a note, such as a Job someone suspended, out of the problem count.
func TestSummaryCountsInfoAsNotes(t *testing.T) {
	note := diagnose.Finding{Rule: "KD187", Severity: diagnose.Info}
	r := diagnose.Report{Checked: diagnose.Checked{Pods: 2}, Findings: []diagnose.Finding{note}}
	if got := summary(r); got != "No problems found in 2 pods, 0 Services, 0 PersistentVolumeClaims and 0 nodes. 1 note." {
		t.Errorf("only a note: %q", got)
	}
	r.Findings = append(sample().Findings, note)
	if got := summary(r); got != "2 problems: 1 critical, 1 warning. 1 note." {
		t.Errorf("problems and a note: %q", got)
	}
	if got := summary(sample()); got != "2 problems: 1 critical, 1 warning." {
		t.Errorf("no notes: %q", got)
	}
}

func TestMarkdown(t *testing.T) {
	var b bytes.Buffer
	if err := Markdown(&b, sample()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"## kube-diagnose: context kind-faults · namespace shop",
		"### 1. Container keeps crashing (`KD110`, critical)",
		"**Deployment shop/web**: container web exits",
		"   ```text\n   starting\n   error: DATABASE_URL is not set\n   ```",
		"   ```sh\n   kubectl logs web-7d9c-a -n shop -c web --tail=20 --previous\n   ```",
		`port \| mismatch &lt;80&gt;`,
		"**Could not read**",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q:\n%s", want, out)
		}
	}
}

func TestJSONRoundTrips(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample()); err != nil {
		t.Fatal(err)
	}
	var back diagnose.Report
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Findings[1].Severity != diagnose.Warning || back.Findings[0].Evidence[1].Detail == "" || !strings.Contains(b.String(), `"severity": "critical"`) {
		t.Errorf("%s", b.String())
	}
}
