package diagnose

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

var (
	// reFlagWithValue matches one list item that holds a flag, a space and more: "--port 8080", "-c /etc/app.conf".
	reFlagWithValue = regexp.MustCompile(`^(--?[A-Za-z][A-Za-z0-9_.-]*)\s+(\S.*)$`)
	// reOptionRejected matches how programs say they do not know an option.
	reOptionRejected = regexp.MustCompile(`(?i)unrecogni[sz]ed|unknown|not defined|invalid|illegal|no such option|bad (?:flag|option)|unexpected`)
)

// flagAndValueOneArg finds a container that exits because one item of its command or args holds a flag and its
// value together ("--port 8080"). Each item reaches the program as one argument, with the space inside it, and no
// shell splits it, so the program sees a flag it does not know and says so, quoting the item.
func flagAndValueOneArg(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, ok := containerSpec(p, cs.Name)
	if !ok {
		return nil
	}
	items, field := c.Args, "args"
	if len(c.Command) > 1 {
		items = append(append([]string{}, c.Command[1:]...), c.Args...)
	}
	for _, item := range items {
		m := reFlagWithValue.FindStringSubmatch(item)
		if m == nil {
			continue
		}
		field = "args"
		for _, x := range c.Command {
			if x == item {
				field = "command"
			}
		}
		// Programs quote the item with or without its dashes: "unknown flag: --port 8080", "not defined: -port 8080",
		// "unrecognized option: port 8080".
		bare := strings.TrimLeft(item, "-")
		for i := len(lines) - 1; i >= 0; i-- {
			if !strings.Contains(lines[i], bare) || !reOptionRejected.MatchString(lines[i]) {
				continue
			}
			split := fmt.Sprintf("%q, %q", m[1], m[2])
			joined := ""
			if strings.HasPrefix(m[1], "--") {
				joined = fmt.Sprintf(" (or one item %q)", m[1]+"="+m[2])
			}
			ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's %s holds %q as one item", cs.Name, field, item),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].command}{" "}{.spec.containers[?(@.name=="%s")].args}`, cs.Name, cs.Name))})
			return newProblem(p, cs.Name, "KD221", "Flag and its value are one argument", Critical,
				fmt.Sprintf("container %s exits because its %s holds %q as one item: the program receives the flag and its value as a single argument, space included, and does not know a flag by that name; its log says: %q",
					cs.Name, field, item, clip(lines[i], 200)),
				"flagvalue|"+item,
				fmt.Sprintf("Write the flag and its value as two items: %s%s. Each item of command and args is passed to the program as one argument, and no shell splits it at spaces.", split, joined), ev...)
		}
	}
	return nil
}

// reExecNoFile matches what the runtime prints when the kernel refuses to run a command it has just found: the
// file is there, and what does not exist is the program the file needs to run.
var reExecNoFile = regexp.MustCompile(`^exec (/\S+): no such file or directory$`)

// interpreterMissing finds a container whose command exists and still fails with "no such file or directory" the
// moment it is run. The runtime checks that the command is there before it starts the container, so the missing
// file is the one the kernel loads to run it: the interpreter on a script's "#!" line (bash in an image that has
// only sh, or any name followed by a Windows line ending), or the dynamic loader of a binary built for another C
// library (a glibc binary on Alpine, or any dynamically linked binary on scratch or a static distroless image).
func interpreterMissing(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	path, line := "", ""
	for _, l := range lines {
		if m := reExecNoFile.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			path, line = m[1], strings.TrimSpace(l)
		}
	}
	if path == "" {
		return nil
	}
	ns := p.Metadata.Namespace
	m, mounted := p.MountAt(cs.Name, path)
	if mounted {
		if _, _, missing := missingVolumeFile(ix, p, cs.Name, path); missing {
			return nil // the file itself is not in the volume: KD230
		}
	}
	if mounted && m.Volume.AlwaysReadOnly() {
		kind, name, _, _ := ix.volumeFiles(ns, m.Volume)
		src := m.Volume.Source()
		if kind != "" && name != "" {
			src = kind + " " + name
		}
		key := strings.SplitN(m.Rel, "/", 2)[0]
		return newProblem(p, cs.Name, "KD222", "Command's interpreter is not in the image", Critical,
			fmt.Sprintf("container %s cannot run %s, though the file is there (key %s of %s): the kernel reports \"no such file or directory\" for the interpreter named on the script's first line (#!), which image %s does not have; its log says: %q",
				cs.Name, path, key, src, imageOf(p, cs), line),
			"interpreter|"+path,
			fmt.Sprintf("Read the first line of %s in %s. Name an interpreter the image has (#!/bin/sh where there is no bash), or use an image that has it; and save the file with Unix line endings, since a Windows line ending makes the kernel look for an interpreter whose name ends in a carriage return.", key, src),
			append(ev, mountEvidence(p, cs.Name, m), Evidence{Object: kube.Ref{Kind: kind, Namespace: ns, Name: name}, What: fmt.Sprintf("the first line of %s names the interpreter", key),
				Command: cmdGet(strings.ToLower(kind), ns, name, "{.data}")})...)
	}
	return newProblem(p, cs.Name, "KD222", "Command's interpreter is not in the image", Critical,
		fmt.Sprintf("container %s cannot run %s, though the file is there: the kernel reports \"no such file or directory\" for the program the file needs in order to run, which image %s does not have: the interpreter on a script's first line (#!), or the dynamic loader of a binary built for another C library; its log says: %q",
			cs.Name, path, imageOf(p, cs), line),
		"interpreter|"+path,
		"If it is a script, name an interpreter the image has on its first line (#!/bin/sh where there is no bash) and save it with Unix line endings. If it is a binary, build it for the image's C library or link it statically (for Go, CGO_ENABLED=0): a binary linked against glibc does not run on Alpine, scratch or a static distroless image.",
		ev...)
}

// shellOperator names what a shell would do with a word that stands alone in a command line.
var shellOperator = map[string]string{
	"&&": "run the next command if the first succeeds", "||": "run the next command if the first fails", ";": "run the next command",
	"|": "pipe the output into the next command", ">": "write the output to a file", ">>": "append the output to a file",
	"<": "read the input from a file", "2>&1": "send errors where the output goes", "&": "run the command in the background",
}

// shellOperators finds a container whose command or args carry a shell operator (&&, |, > and so on) as an item of
// its own while no shell runs the command. Kubernetes starts the first item as the program and hands it every other
// item as an argument, the operator included, so what was meant to come after the operator never runs: echo prints
// "&&", and a server meant to start after a setup step never starts.
func shellOperators(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, ok := containerSpec(p, cs.Name)
	if !ok || runsShell(c) {
		return nil
	}
	words := append(append([]string{}, c.Command...), c.Args...)
	for i, w := range words {
		does, isOp := shellOperator[w]
		if !isOp || i == 0 {
			continue
		}
		whole := strings.Join(words, " ")
		quoted := ""
		for j := len(lines) - 1; j >= 0 && quoted == ""; j-- {
			if strings.Contains(lines[j], " "+w+" ") || strings.HasSuffix(lines[j], " "+w) {
				quoted = fmt.Sprintf("; its log shows the operator as text: %q", clip(lines[j], 200))
			}
		}
		ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's command and args are a list with %q as one item, and no shell", cs.Name, w),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].command}{" "}{.spec.containers[?(@.name=="%s")].args}`, cs.Name, cs.Name))})
		return newProblem(p, cs.Name, "KD226", "Command uses a shell operator with no shell", Critical,
			fmt.Sprintf("container %s runs %s with no shell: %s is a shell operator (%s), and without a shell it is one more argument to %s, so what follows it never runs as a command%s",
				cs.Name, clip(whole, 160), w, does, words[0], quoted),
			"shellop|"+w,
			fmt.Sprintf("Run the line through a shell: command: [\"sh\", \"-c\", %s] (if the image has a shell), or run one program only and move the other step into an init container or the image.", strconv.Quote(clip(whole, 160))), ev...)
	}
	return nil
}
