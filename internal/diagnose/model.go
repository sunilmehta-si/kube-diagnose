// Package diagnose turns a snapshot into findings. Each finding names one root cause, the object to change to fix
// it, the evidence it rests on with the read-only kubectl command that shows each piece, and what the cause breaks.
// Nothing here talks to a cluster: a diagnosis is a pure function of a snapshot.
package diagnose

import (
	"fmt"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

type Severity int

const (
	Critical Severity = iota // the workload does not run or cannot be reached
	Warning                  // it runs degraded, or will fail on the next change
	Info
)

func (s Severity) String() string {
	return [...]string{"critical", "warning", "info"}[s]
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	for i, name := range [...]string{"critical", "warning", "info"} {
		if string(b) == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", b)
}

// Evidence is one observed fact a finding rests on.
type Evidence struct {
	Object kube.Ref `json:"object"`
	// What was observed, in a sentence.
	What string `json:"what"`
	// Detail is the raw text behind it, as the cluster reported it: an event message, a log tail, a field value.
	Detail string `json:"detail,omitempty"`
	// Command is a read-only kubectl command that shows the same fact.
	Command string `json:"command"`
}

// Finding is one root cause.
type Finding struct {
	Rule     string   `json:"rule"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	// Object is where the fix goes: the Deployment, not its pods, when a controller owns them.
	Object   kube.Ref   `json:"object"`
	Cause    string     `json:"cause"`
	Evidence []Evidence `json:"evidence"`
	Fix      string     `json:"fix"`
	// Affects lists what the cause breaks: the pods, and Services left without endpoints.
	Affects []kube.Ref `json:"affects,omitempty"`
}

// Report is the diagnosis of one snapshot.
type Report struct {
	Context       string         `json:"context,omitempty"`
	ServerVersion string         `json:"serverVersion,omitempty"`
	Namespaces    []string       `json:"namespaces,omitempty"`
	CollectedAt   string         `json:"collectedAt"`
	Findings      []Finding      `json:"findings"`
	Gaps          []snapshot.Gap `json:"gaps,omitempty"`
	Checked       Checked        `json:"checked"`
}

// Checked counts what the diagnosis looked at, so "no problems" says how much was seen.
type Checked struct {
	Pods     int `json:"pods"`
	Services int `json:"services"`
	PVCs     int `json:"persistentVolumeClaims"`
	Nodes    int `json:"nodes"`
}
