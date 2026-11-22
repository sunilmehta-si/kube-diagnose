package diagnose

import (
	"fmt"
	"regexp"
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
