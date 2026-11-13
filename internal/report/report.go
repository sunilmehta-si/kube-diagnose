// Package report prints a diagnosis as text for a terminal, Markdown for an issue or pull request, or JSON for tools.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/diagnose"
	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// Style switches ANSI colour on for terminals.
type Style struct {
	Color bool
	Width int // wrap prose at this many columns (default 100)
}

func (s Style) paint(code, text string) string {
	if !s.Color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s Style) width() int {
	if s.Width < 40 {
		return 100
	}
	return s.Width
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r diagnose.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func scope(r diagnose.Report) string {
	parts := []string{}
	if r.Context != "" {
		parts = append(parts, "context "+r.Context)
	}
	switch len(r.Namespaces) {
	case 0:
		parts = append(parts, "all namespaces")
	case 1:
		parts = append(parts, "namespace "+r.Namespaces[0])
	default:
		parts = append(parts, "namespaces "+strings.Join(r.Namespaces, ", "))
	}
	if r.CollectedAt != "" {
		parts = append(parts, r.CollectedAt)
	}
	return strings.Join(parts, " · ")
}

func summary(r diagnose.Report) string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("No problems found in %s, %s, %s and %s.", count(r.Checked.Pods, "pod"),
			count(r.Checked.Services, "Service"), count(r.Checked.PVCs, "PersistentVolumeClaim"), count(r.Checked.Nodes, "node"))
	}
	by := map[diagnose.Severity]int{}
	for _, f := range r.Findings {
		by[f.Severity]++
	}
	var parts []string
	for _, s := range []diagnose.Severity{diagnose.Critical, diagnose.Warning, diagnose.Info} {
		if by[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", by[s], s))
		}
	}
	return fmt.Sprintf("%s: %s.", count(len(r.Findings), "problem"), strings.Join(parts, ", "))
}

func count(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Text writes the report for a terminal.
func Text(w io.Writer, r diagnose.Report, st Style) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "%s\n%s\n", st.paint("1", "kube-diagnose · "+scope(r)), summary(r))
	for i, f := range r.Findings {
		sev := st.paint(sevColor(f.Severity), strings.ToUpper(f.Severity.String()))
		fmt.Fprintf(b, "\n%s %s  %s  %s\n", st.paint("1", fmt.Sprintf("%d.", i+1)), sev, st.paint("1", f.Title), st.paint("2", f.Rule))
		fmt.Fprintf(b, "   %s\n", f.Object)
		wrap(b, "   Cause: ", "          ", f.Cause, st.width())
		b.WriteString("   Evidence:\n")
		for j, e := range f.Evidence {
			wrap(b, fmt.Sprintf("     [%d] ", j+1), "         ", subject(e.Object)+e.What, st.width())
			for _, line := range detailLines(e.Detail) {
				fmt.Fprintf(b, "         %s %s\n", st.paint("2", "│"), line)
			}
			fmt.Fprintf(b, "         %s\n", st.paint("36", "$ "+e.Command))
		}
		wrap(b, "   Fix: ", "        ", f.Fix, st.width())
		if len(f.Affects) > 0 {
			wrap(b, "   Affects: ", "            ", affects(f.Affects), st.width())
		}
	}
	gaps(b, r, "\n", "Could not read")
	_, err := io.WriteString(w, b.String())
	return err
}

func sevColor(s diagnose.Severity) string {
	switch s {
	case diagnose.Critical:
		return "31;1"
	case diagnose.Warning:
		return "33;1"
	}
	return "34"
}

// subject prefixes evidence with the object it was read from, unless that is a wildcard like "every node".
func subject(r kube.Ref) string {
	if r.Name == "*" || r.Name == "" {
		return ""
	}
	return r.String() + ": "
}

func detailLines(d string) []string {
	d = strings.TrimSpace(d)
	if d == "" {
		return nil
	}
	lines := strings.Split(d, "\n")
	if len(lines) > 8 {
		lines = append(lines[:8], fmt.Sprintf("… %d more lines", len(lines)-8))
	}
	for i, l := range lines {
		if len(l) > 240 {
			lines[i] = l[:240] + "…"
		}
	}
	return lines
}

func affects(refs []kube.Ref) string {
	byKind := map[string][]string{}
	var kinds []string
	for _, r := range refs {
		if byKind[r.Kind] == nil {
			kinds = append(kinds, r.Kind)
		}
		byKind[r.Kind] = append(byKind[r.Kind], r.Name)
	}
	var parts []string
	for _, k := range kinds {
		names := byKind[k]
		label := k
		if len(names) > 1 {
			label += "s"
		}
		if len(names) > 6 {
			names = append(names[:6], fmt.Sprintf("and %d more", len(names)-6))
		}
		parts = append(parts, label+" "+strings.Join(names, ", "))
	}
	return strings.Join(parts, "; ")
}

// wrap writes text after a first-line prefix, wrapping at width with a hanging indent.
func wrap(b *strings.Builder, first, rest, text string, width int) {
	line, prefix := "", first
	for _, word := range strings.Fields(text) {
		if line != "" && len(prefix)+len(line)+1+len(word) > width {
			b.WriteString(prefix + line + "\n")
			line, prefix = "", rest
		}
		if line == "" {
			line = word
		} else {
			line += " " + word
		}
	}
	b.WriteString(prefix + line + "\n")
}

func gaps(b *strings.Builder, r diagnose.Report, lead, title string) {
	if len(r.Gaps) == 0 {
		return
	}
	fmt.Fprintf(b, "%s%s (findings that need these may be missing):\n", lead, title)
	for _, g := range r.Gaps {
		where := g.Resource
		if g.Namespace != "" {
			where += " in " + g.Namespace
		}
		fmt.Fprintf(b, "  - %s: %s\n", where, g.Error)
	}
}

// Markdown writes the report for a GitHub issue or pull request.
func Markdown(w io.Writer, r diagnose.Report) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "## kube-diagnose: %s\n\n%s\n", scope(r), summary(r))
	for i, f := range r.Findings {
		fmt.Fprintf(b, "\n### %d. %s (`%s`, %s)\n\n**%s**: %s\n\n", i+1, f.Title, f.Rule, f.Severity, f.Object, mdEscape(f.Cause))
		b.WriteString("Evidence:\n\n")
		for j, e := range f.Evidence {
			fmt.Fprintf(b, "%d. %s%s\n", j+1, subject(e.Object), mdEscape(e.What))
			if d := detailLines(e.Detail); len(d) > 0 {
				fmt.Fprintf(b, "   ```text\n   %s\n   ```\n", strings.Join(d, "\n   "))
			}
			fmt.Fprintf(b, "   ```sh\n   %s\n   ```\n", e.Command)
		}
		fmt.Fprintf(b, "\n**Fix:** %s\n", mdEscape(f.Fix))
		if len(f.Affects) > 0 {
			fmt.Fprintf(b, "\n**Affects:** %s\n", mdEscape(affects(f.Affects)))
		}
	}
	if len(r.Gaps) > 0 {
		gaps(b, r, "\n", "**Could not read**")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;").Replace(s)
}
