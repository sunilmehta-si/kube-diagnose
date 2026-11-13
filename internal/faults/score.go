package faults

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Tools in the order the results table shows them, with the file each run writes per namespace.
var Tools = []struct{ Name, Ext string }{
	{"kube-diagnose", ".json"}, {"k8sgpt", ".json"}, {"holmesgpt", ".txt"},
}

// Row is one scenario's outcomes, by tool name.
type Row struct {
	Scenario Scenario           `json:"scenario"`
	Outcomes map[string]Outcome `json:"outcomes"`
}

// Totals sums one tool's outcomes over the faults (the control is counted apart).
type Totals struct {
	Faults      int `json:"faults"`
	Ran         int `json:"ran"`
	Named       int `json:"named"`
	First       int `json:"first"`
	Exact       int `json:"exact"`
	Extra       int `json:"extraItems"`  // items on faults beyond the one that names the cause
	FalseAlarms int `json:"falseAlarms"` // items on the healthy control
}

// Result is a scored run.
type Result struct {
	Rows   []Row             `json:"rows"`
	Totals map[string]Totals `json:"totals"`
}

// Score reads each tool's output under dir (dir/<tool>/<namespace><ext>) and judges it. A tool with no output
// directory did not run; a namespace with a .err file instead of output is a run that failed.
func Score(scenarios []Scenario, dir string) (Result, error) {
	res := Result{Totals: map[string]Totals{}}
	for _, s := range scenarios {
		row := Row{Scenario: s, Outcomes: map[string]Outcome{}}
		for _, tool := range Tools {
			o, err := scoreOne(s, dir, tool.Name, tool.Ext)
			if err != nil {
				return res, err
			}
			row.Outcomes[tool.Name] = o
			t := res.Totals[tool.Name]
			if s.Healthy() {
				if o.Ran {
					t.FalseAlarms += o.Items
				}
			} else {
				t.Faults++
				if o.Ran {
					t.Ran++
					t.Extra += o.Items
					if o.Named {
						t.Named++
						t.Extra--
					}
				}
				if o.First {
					t.First++
				}
				if o.Exact {
					t.Exact++
				}
			}
			res.Totals[tool.Name] = t
		}
		res.Rows = append(res.Rows, row)
	}
	return res, nil
}

func scoreOne(s Scenario, dir, tool, ext string) (Outcome, error) {
	base := filepath.Join(dir, tool, s.Namespace)
	if msg, err := os.ReadFile(base + ".err"); err == nil {
		return Outcome{Ran: true, Error: strings.TrimSpace(string(msg))}, nil
	}
	b, err := os.ReadFile(base + ext)
	if errors.Is(err, fs.ErrNotExist) {
		return Outcome{}, nil
	}
	if err != nil {
		return Outcome{}, err
	}
	switch tool {
	case "kube-diagnose":
		items, r, err := KubeDiagnoseItems(b)
		if err != nil {
			return Outcome{}, fmt.Errorf("%s: %w", base+ext, err)
		}
		o := Judge(s, items)
		o.Exact = Exact(s, r)
		return o, nil
	case "k8sgpt":
		items, err := K8sGPTItems(b)
		if err != nil {
			return Outcome{}, fmt.Errorf("%s: %w", base+ext, err)
		}
		return Judge(s, items), nil
	}
	return Judge(s, TextItems(b)), nil
}

// Markdown renders the scored run: a summary per tool, then one row per scenario.
func Markdown(r Result) string {
	b := &strings.Builder{}
	b.WriteString("| Tool | Named the root cause | In its first finding | False alarms on the healthy namespace | Other findings on the faults |\n|---|---|---|---|---|\n")
	for _, tool := range Tools {
		t := r.Totals[tool.Name]
		if t.Ran == 0 {
			fmt.Fprintf(b, "| %s | not run | | | |\n", tool.Name)
			continue
		}
		named := fmt.Sprintf("%d of %d", t.Named, t.Faults)
		if tool.Name == "kube-diagnose" {
			named += fmt.Sprintf(" (exact rule and object: %d)", t.Exact)
		}
		fmt.Fprintf(b, "| %s | %s | %d | %d | %d |\n", tool.Name, named, t.First, t.FalseAlarms, t.Extra)
	}
	b.WriteString("\n| Scenario | Fault |")
	for _, tool := range Tools {
		b.WriteString(" " + tool.Name + " |")
	}
	b.WriteString("\n|---|---|" + strings.Repeat("---|", len(Tools)) + "\n")
	for _, row := range r.Rows {
		fmt.Fprintf(b, "| %s | %s |", row.Scenario.Name, row.Scenario.Description)
		for _, tool := range Tools {
			b.WriteString(" " + cell(row.Scenario, row.Outcomes[tool.Name]) + " |")
		}
		b.WriteString("\n")
	}
	b.WriteString("\n✅ named the root cause in its first finding · ☑️ named it, but not first · ❌ did not name it · ⚠️ N: N false alarms · – not run\n")
	return b.String()
}

func cell(s Scenario, o Outcome) string {
	switch {
	case !o.Ran:
		return "–"
	case o.Error != "":
		return "error"
	case s.Healthy() && o.Items == 0:
		return "✅ quiet"
	case s.Healthy():
		return fmt.Sprintf("⚠️ %d", o.Items)
	case o.First:
		return "✅"
	case o.Named:
		return "☑️"
	}
	return "❌"
}
