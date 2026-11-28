package diagnose

import (
	"fmt"
	"path"
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

var shells = map[string]bool{"sh": true, "bash": true, "ash": true, "zsh": true, "/bin/sh": true, "/bin/bash": true, "/bin/ash": true, "/usr/bin/bash": true}

// interpreters read a program from their input when given none, as a shell reads a script: with no terminal and no
// input, they read end of input and exit 0.
var interpreters = map[string]bool{"python": true, "python3": true, "pypy3": true, "node": true, "ruby": true, "irb": true, "php": true,
	"/usr/local/bin/python": true, "/usr/local/bin/python3": true, "/usr/bin/python3": true, "/usr/local/bin/node": true, "/usr/local/bin/ruby": true}

// programFor is an example command line that gives an interpreter a program to run.
func programFor(run string) string {
	name := path.Base(strings.Fields(run)[0])
	switch {
	case strings.HasPrefix(name, "python"), strings.HasPrefix(name, "pypy"):
		return name + " app.py"
	case name == "node":
		return "node server.js"
	case name == "ruby", name == "irb":
		return "ruby app.rb"
	case name == "php":
		return "php index.php"
	}
	return name + " app"
}

// shellExits finds a container that keeps exiting with code 0 because what it runs is a shell or an interpreter with
// nothing to do: a base image run without a command (its default is sh, bash, python3, node), or command sh or python3
// with no script. Without a terminal and stdin, it reads end of input at once and exits, and the kubelet restarts it.
func shellExits(p kube.Pod, cs kube.ContainerStatus, ev []Evidence) *problem {
	c, _ := containerSpec(p, cs.Name)
	if c.Stdin || c.TTY {
		return nil
	}
	repo := c.Image
	if i := strings.IndexAny(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	base := kube.OfficialBaseImage(repo)
	alone := ""
	switch {
	case len(c.Command) == 1 && len(c.Args) == 0:
		alone = c.Command[0]
	case len(c.Command) == 0 && len(c.Args) == 1:
		alone = c.Args[0]
	}
	var what, kind, run string
	switch {
	case len(c.Command) == 0 && len(c.Args) == 0 && base != "":
		run = kube.BaseImages[base]
		kind = "a shell"
		if !shells[strings.Fields(run)[0]] {
			kind = "an interpreter"
		}
		what = fmt.Sprintf("it sets no command, and image %s's default command is %s (%s)", base, kind, run)
	case shells[alone]:
		kind, run = "a shell", alone
		what = "its command is a shell with no script to run"
	case interpreters[alone]:
		kind, run = "an interpreter", alone
		what = fmt.Sprintf("its command is the interpreter %s with no program to run", alone)
	default:
		return nil
	}
	cause := fmt.Sprintf("container %s exits with code 0 as soon as it starts: %s, and a shell with no terminal and no input has nothing to do, so it exits at once and the kubelet restarts it", cs.Name, what)
	fix := "Give the container the command it is meant to run; to keep a debugging container alive, run sleep infinity (or set stdin: true and tty: true), and use kubectl debug or kubectl run -it for an interactive shell."
	if kind == "an interpreter" {
		cause = fmt.Sprintf("container %s exits with code 0 as soon as it starts: %s, and an interpreter given no program, no terminal and no input reads its program from that input, finds it empty and exits at once, and the kubelet restarts it", cs.Name, what)
		fix = fmt.Sprintf("Give the container its program, the script the image copies in, as its command or args (%s); to keep it alive for debugging, run sleep infinity, and use kubectl debug or kubectl run -it for an interactive session.", programFor(run))
	}
	ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's image, command and args", cs.Name),
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].image}{" "}{.spec.containers[?(@.name=="%s")].command}{" "}{.spec.containers[?(@.name=="%s")].args}`, cs.Name, cs.Name, cs.Name))})
	return newProblem(p, cs.Name, "KD315", "Container runs a shell or interpreter with nothing to do", Critical, cause, "shell|"+cs.Name, fix, ev...)
}
