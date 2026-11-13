// Package faults loads the fault suite's scenarios and scores each tool's output on them. Every tool is judged by
// the same test, fixed before any run: does what it reported for the scenario's namespace name the root cause? The
// words that count are in each scenario's expect.json.
package faults

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/diagnose"
)

// Scenario is one broken (or healthy) namespace.
type Scenario struct {
	Name        string     `json:"-"`
	Namespace   string     `json:"namespace"`
	Description string     `json:"description"`
	Rule        string     `json:"rule"`   // the kube-diagnose rule that is the right answer; empty for the control
	Object      string     `json:"object"` // Kind/name where the fix goes
	Keywords    [][]string `json:"keywords"`
}

// Healthy reports whether the scenario is the control, where every finding is a false alarm.
func (s Scenario) Healthy() bool { return s.Rule == "" }

// Load reads every faults/<name>/expect.json under dir, in name order.
func Load(dir string) ([]Scenario, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*", "expect.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Scenario
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var s Scenario
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		s.Name = filepath.Base(filepath.Dir(p))
		if s.Namespace != "kd-"+s.Name {
			return nil, fmt.Errorf("%s: namespace %q should be kd-%s", p, s.Namespace, s.Name)
		}
		if !s.Healthy() && len(s.Keywords) == 0 {
			return nil, fmt.Errorf("%s: a fault needs keywords that name its cause", p)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no scenarios under %s", dir)
	}
	return out, nil
}

// Names reports whether text names the cause: for every keyword group, it contains at least one of the words,
// ignoring case.
func (s Scenario) Names(text string) bool {
	if len(s.Keywords) == 0 {
		return false
	}
	text = strings.ToLower(text)
	for _, group := range s.Keywords {
		hit := false
		for _, w := range group {
			if strings.Contains(text, strings.ToLower(w)) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// Item is one thing a tool reported, as text to judge.
type Item struct {
	Text string
}

// Outcome is how one tool did on one scenario.
type Outcome struct {
	Ran   bool   `json:"ran"`
	Items int    `json:"items"` // findings or results reported for the namespace
	Named bool   `json:"named"` // some item names the root cause
	First bool   `json:"first"` // the first item names it
	Exact bool   `json:"exact"` // kube-diagnose only: the expected rule on the expected object
	Error string `json:"error,omitempty"`
}

// Judge scores a tool's items for a scenario.
func Judge(s Scenario, items []Item) Outcome {
	o := Outcome{Ran: true, Items: len(items)}
	for i, it := range items {
		if s.Names(it.Text) {
			o.Named = true
			if i == 0 {
				o.First = true
			}
		}
	}
	return o
}

// KubeDiagnoseItems turns a kube-diagnose JSON report into items: each finding's rule, object, title and cause. The
// evidence is left out, since it quotes the cluster's own messages and would let a wrong cause pass.
func KubeDiagnoseItems(b []byte) ([]Item, diagnose.Report, error) {
	var r diagnose.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, r, fmt.Errorf("kube-diagnose output: %w", err)
	}
	var items []Item
	for _, f := range r.Findings {
		items = append(items, Item{Text: fmt.Sprintf("%s %s/%s: %s. %s", f.Rule, f.Object.Kind, f.Object.Name, f.Title, f.Cause)})
	}
	return items, r, nil
}

// Exact reports whether kube-diagnose's first finding is the expected rule on the expected object.
func Exact(s Scenario, r diagnose.Report) bool {
	if len(r.Findings) == 0 || s.Healthy() {
		return false
	}
	f := r.Findings[0]
	return f.Rule == s.Rule && f.Object.Kind+"/"+f.Object.Name == s.Object
}

// K8sGPTItems turns `k8sgpt analyze --output json` into items: each result's kind, name and failure texts.
func K8sGPTItems(b []byte) ([]Item, error) {
	var out struct {
		Results []struct {
			Kind         string `json:"kind"`
			Name         string `json:"name"`
			ParentObject string `json:"parentObject"`
			Details      string `json:"details"`
			Error        []struct {
				Text string `json:"Text"`
			} `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("k8sgpt output: %w", err)
	}
	var items []Item
	for _, r := range out.Results {
		var texts []string
		for _, e := range r.Error {
			texts = append(texts, e.Text)
		}
		items = append(items, Item{Text: fmt.Sprintf("%s %s: %s %s", r.Kind, r.Name, strings.Join(texts, " "), r.Details)})
	}
	return items, nil
}

// TextItems treats a free-text answer (HolmesGPT) as one item.
func TextItems(b []byte) []Item {
	t := strings.TrimSpace(string(b))
	if t == "" {
		return nil
	}
	return []Item{{Text: t}}
}
