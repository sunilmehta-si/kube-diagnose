package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	// reMidCR is a carriage return inside a line: the shell quoting a word that kept the \r of a CRLF line ending.
	// A line that only ends in \r is an app writing CRLF logs, and is no sign.
	reMidCR = regexp.MustCompile(`\r[^\r]|\$'\\r'`)
	// reShellError is what a shell says when a command, an option or a path it read is wrong.
	reShellError = regexp.MustCompile(`(?i)not found|no such file|illegal option|invalid option|syntax error|unexpected|bad substitution|bad interpreter|can't cd`)
)

// windowsLineEndings finds a container that exits because the script it runs was saved with Windows line endings
// (CRLF): the shell keeps each line's carriage return as part of its last word, so a command, an option or a path is
// one character longer than written, and the error quotes it with the \r inside.
func windowsLineEndings(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	bad := ""
	for i := len(lines) - 1; i >= 0 && bad == ""; i-- {
		if reMidCR.MatchString(lines[i]) && reShellError.MatchString(lines[i]) {
			bad = lines[i]
		}
	}
	if bad == "" {
		return nil
	}
	c, _ := containerSpec(p, cs.Name)
	script, what := "", "the script it runs"
	var mount *kube.Mount
	for _, a := range append(append([]string{}, c.Command...), c.Args...) {
		for _, f := range strings.Fields(a) {
			if !strings.HasPrefix(f, "/") && !strings.HasPrefix(f, "./") {
				continue
			}
			if m, ok := p.MountAt(cs.Name, f); ok {
				script, what, mount = f, "script "+f, &m
				break
			}
			if script == "" && (strings.HasSuffix(f, ".sh") || strings.Contains(bad, f)) {
				script, what = f, "script "+f
			}
		}
		if mount != nil {
			break
		}
	}
	cause := fmt.Sprintf("container %s exits because %s has Windows line endings (CRLF): the shell keeps each line's carriage return (\\r) as part of the line's last word, so a command, an option or a path is not the one written; its log says: %q",
		cs.Name, what, clip(bad, 200))
	fix := "Save the script with Unix line endings (dos2unix, or `*.sh text eol=lf` in .gitattributes so a Windows checkout keeps them)"
	if mount != nil && (mount.Volume.ConfigMap != nil || mount.Volume.Secret != nil) {
		cause += fmt.Sprintf("; the script comes from %s", mount.Volume.Source())
		fix += fmt.Sprintf(", then create %s again from the file", mount.Volume.Source())
		ev = append(ev, mountEvidence(p, cs.Name, *mount))
	} else {
		fix += ", then build the image again"
	}
	return newProblem(p, cs.Name, "KD309", "Script has Windows line endings", Critical, cause,
		"crlf|"+script, fix+".", ev...)
}
