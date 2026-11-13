package faults

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/diagnose"
)

func TestTheSuiteLoadsAndEveryScenarioIsWellFormed(t *testing.T) {
	ss, err := Load("../../faults")
	if err != nil {
		t.Fatal(err)
	}
	healthy := 0
	pinned := regexp.MustCompile(`image: (\S+)`)
	for _, s := range ss {
		if s.Healthy() {
			healthy++
			continue
		}
		if _, ok := diagnose.RuleByID(s.Rule); !ok {
			t.Errorf("%s: unknown rule %s", s.Name, s.Rule)
		}
		if !strings.Contains(s.Object, "/") {
			t.Errorf("%s: object %q should be Kind/name", s.Name, s.Object)
		}
		m, err := os.ReadFile(filepath.Join("../../faults", s.Name, "manifest.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(m), "namespace: "+s.Namespace) || !strings.Contains(string(m), "name: "+s.Namespace) {
			t.Errorf("%s: manifest does not create and use namespace %s", s.Name, s.Namespace)
		}
		for _, img := range pinned.FindAllStringSubmatch(string(m), -1) {
			// Working images are pinned by digest; a broken reference is the fault itself and names this project.
			if !strings.Contains(img[1], "@sha256:") && !strings.Contains(img[1], "kube-diagnose-missing") {
				t.Errorf("%s: image %s is not pinned by digest", s.Name, img[1])
			}
		}
	}
	if healthy != 1 || len(ss) < 20 {
		t.Errorf("%d scenarios, %d healthy", len(ss), healthy)
	}
}

// TestManifestsUseThePinnedImages holds every working image in the scenarios to the digests in faults/versions.env.
func TestManifestsUseThePinnedImages(t *testing.T) {
	env, err := os.ReadFile("../../faults/versions.env")
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]bool{}
	for _, line := range strings.Split(string(env), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.HasSuffix(k, "_IMAGE") && !strings.HasPrefix(k, "KIND") {
			pins[v] = true
		}
	}
	if len(pins) != 2 {
		t.Fatalf("versions.env image pins: %v", pins)
	}
	paths, _ := filepath.Glob("../../faults/*/manifest.yaml")
	re := regexp.MustCompile(`image: (\S+@sha256:\S+)`)
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			if !pins[m[1]] {
				t.Errorf("%s: image %s is not one of the pinned images", p, m[1])
			}
		}
	}
}

func TestNames(t *testing.T) {
	s := Scenario{Keywords: [][]string{{"liveness"}, {"9090"}}}
	if !s.Names("Container web fails its LIVENESS probe (GET / on port 9090)") {
		t.Error("both groups present, any case")
	}
	if s.Names("Back-off restarting failed container web") {
		t.Error("the symptom alone does not name the cause")
	}
	if (Scenario{}).Names("anything") {
		t.Error("the control names nothing")
	}
}

const kdJSON = `{"findings":[{"rule":"KD112","title":"Liveness probe kills the container","severity":"critical",
 "object":{"kind":"Deployment","namespace":"kd-x","name":"web"},
 "cause":"container web fails its liveness probe (GET / on port 9090, but the container declares port 8080)",
 "evidence":[{"object":{"kind":"Pod","name":"p"},"what":"event","detail":"9090 liveness","command":"kubectl get pods"}]}]}`

const k8sgptJSON = `{"provider":"","errors":null,"status":"ProblemDetected","problems":1,
 "results":[{"kind":"Pod","name":"kd-x/web-1","error":[{"Text":"the last termination reason is Error container=web pod=web-1","KubernetesDoc":"","Sensitive":[]}],"details":"","parentObject":"Deployment/web"}]}`

func TestScore(t *testing.T) {
	dir := t.TempDir()
	write := func(tool, name, body string) {
		os.MkdirAll(filepath.Join(dir, tool), 0o755)
		os.WriteFile(filepath.Join(dir, tool, name), []byte(body), 0o644)
	}
	write("kube-diagnose", "kd-x.json", kdJSON)
	write("k8sgpt", "kd-x.json", k8sgptJSON)
	write("kube-diagnose", "kd-healthy.json", `{"findings":[]}`)
	write("k8sgpt", "kd-healthy.json", k8sgptJSON)
	write("k8sgpt", "kd-y.err", "k8sgpt exited 1")
	ss := []Scenario{
		{Name: "x", Namespace: "kd-x", Description: "wrong liveness port", Rule: "KD112", Object: "Deployment/web", Keywords: [][]string{{"liveness"}, {"9090"}}},
		{Name: "y", Namespace: "kd-y", Description: "another", Rule: "KD101", Object: "Deployment/web", Keywords: [][]string{{"tag"}}},
		{Name: "healthy", Namespace: "kd-healthy", Description: "control"},
	}
	r, err := Score(ss, dir)
	if err != nil {
		t.Fatal(err)
	}
	kd, gpt, holmes := r.Totals["kube-diagnose"], r.Totals["k8sgpt"], r.Totals["holmesgpt"]
	if kd.Named != 1 || kd.First != 1 || kd.Exact != 1 || kd.FalseAlarms != 0 || kd.Faults != 2 || kd.Ran != 1 {
		t.Errorf("kube-diagnose %+v", kd)
	}
	if gpt.Named != 0 || gpt.FalseAlarms != 1 || gpt.Extra != 1 || gpt.Ran != 2 {
		t.Errorf("k8sgpt %+v", gpt)
	}
	if holmes.Ran != 0 {
		t.Errorf("holmesgpt did not run: %+v", holmes)
	}
	md := Markdown(r)
	for _, want := range []string{"| kube-diagnose | 1 of 2 (exact rule and object: 1) | 1 | 0 | 0 |", "| holmesgpt | not run |",
		"| x | wrong liveness port | ✅ | ❌ | – |", "| y | another | – | error | – |", "| healthy | control | ✅ quiet | ⚠️ 1 | – |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	if _, err := Score(ss, "/nonexistent"); err != nil {
		t.Errorf("no output at all is not an error: %v", err)
	}
}

func TestEvidenceDoesNotCountForKubeDiagnose(t *testing.T) {
	items, _, err := KubeDiagnoseItems([]byte(strings.Replace(kdJSON, "fails its liveness probe (GET / on port 9090, but the container declares port 8080)", "keeps crashing", 1)))
	if err != nil {
		t.Fatal(err)
	}
	s := Scenario{Keywords: [][]string{{"9090"}}}
	if Judge(s, items).Named {
		t.Error("a cause that does not name the port must not pass because the evidence quotes it")
	}
}

// TestReadmeDescribesTheSuite holds the README's numbers about the fault suite to the scenarios and the runner.
func TestReadmeDescribesTheSuite(t *testing.T) {
	ss, err := Load("../../faults")
	if err != nil {
		t.Fatal(err)
	}
	broken := 0
	for _, s := range ss {
		if !s.Healthy() {
			broken++
		}
	}
	readme, _ := os.ReadFile("../../README.md")
	for _, want := range []string{fmt.Sprintf("breaks a kind cluster in %d ways", broken), fmt.Sprintf("holds %d broken namespaces and one healthy one", broken),
		"lets them run for two and a half\nminutes"} {
		if !strings.Contains(string(readme), want) {
			t.Errorf("README lacks %q", want)
		}
	}
	runner, _ := os.ReadFile("../../cmd/faultsuite/main.go")
	if !strings.Contains(string(runner), `fs.Duration("settle", 150*time.Second`) {
		t.Error("the README's two and a half minutes is faultsuite's default settle time")
	}
}
