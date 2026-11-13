package diagnose

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var updateDocs = flag.Bool("update-docs", false, "rewrite docs/rules.md from the rule catalogue")

// TestCatalogMatchesTheCode holds the catalogue to the rule IDs the code can emit, both ways.
func TestCatalogMatchesTheCode(t *testing.T) {
	used := map[string]bool{}
	files, _ := os.ReadDir(".")
	re := regexp.MustCompile(`"(KD\d{3})"`)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), "_test.go") || f.Name() == "catalog.go" || !strings.HasSuffix(f.Name(), ".go") {
			continue
		}
		b, _ := os.ReadFile(f.Name())
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			used[m[1]] = true
		}
	}
	listed := map[string]bool{}
	var prev string
	for _, r := range Rules {
		if r.ID <= prev {
			t.Errorf("catalogue out of order or duplicated at %s", r.ID)
		}
		prev = r.ID
		listed[r.ID] = true
		if !used[r.ID] {
			t.Errorf("%s is in the catalogue but no code emits it", r.ID)
		}
		if r.Title == "" || r.Detects == "" || r.Evidence == "" {
			t.Errorf("%s is not fully documented", r.ID)
		}
	}
	for id := range used {
		if !listed[id] {
			t.Errorf("%s is emitted but missing from the catalogue", id)
		}
	}
}

func rulesDoc() string {
	b := &strings.Builder{}
	b.WriteString("# Rules\n\nEvery finding names one of these rules. IDs are stable: a rule is retired, never renumbered. ")
	b.WriteString("`kube-diagnose rules KD101` prints one. This file is generated from `internal/diagnose/catalog.go` ")
	b.WriteString("(`make docs`).\n\n| Rule | Title | Severity | Detects | Evidence |\n|---|---|---|---|---|\n")
	ids := make([]string, 0, len(Rules))
	for _, r := range Rules {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r, _ := RuleByID(id)
		esc := strings.NewReplacer("|", `\|`).Replace
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", r.ID, esc(r.Title), r.Severity, esc(r.Detects), esc(r.Evidence))
	}
	return b.String()
}

func TestRulesDocIsCurrent(t *testing.T) {
	path := "../../docs/rules.md"
	want := rulesDoc()
	if *updateDocs {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("docs/rules.md is stale: run make docs")
	}
}
