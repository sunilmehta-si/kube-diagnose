package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// capabilityFor maps what a failing line is doing to the Linux capability that operation needs. The first match
// wins, so the specific operations come before the general ones.
var capabilityFor = []struct {
	re   *regexp.Regexp
	name string
	what string
}{
	{regexp.MustCompile(`(?i)\bl?chown\b|changing ownership`), "CHOWN", "changing a file's owner"},
	{regexp.MustCompile(`(?i)\bf?chmod\b|changing permissions`), "FOWNER", "changing the mode of a file another user owns"},
	{regexp.MustCompile(`(?i)setgroups|setgid|initgroups`), "SETGID", "switching group"},
	{regexp.MustCompile(`(?i)setuid|\bsu(?:-exec)?:|gosu|setpriv`), "SETUID", "switching user"},
	{regexp.MustCompile(`(?i)\bbind\b`), "NET_BIND_SERVICE", "binding a port below 1024"},
	{regexp.MustCompile(`(?i)\bping\b|raw socket|SOCK_RAW`), "NET_RAW", "opening a raw socket"},
	{regexp.MustCompile(`(?i)iptables|nftables|RTNETLINK|netlink|\bip (?:link|addr|route|rule)\b`), "NET_ADMIN", "changing network settings"},
	{regexp.MustCompile(`(?i)\bchroot\b`), "SYS_CHROOT", "chroot"},
	{regexp.MustCompile(`(?i)\bmknod\b`), "MKNOD", "creating a device node"},
	{regexp.MustCompile(`(?i)\bu?mount\b`), "SYS_ADMIN", "mounting a filesystem"},
	{regexp.MustCompile(`(?i)settimeofday|clock_settime|can't set date|cannot set date`), "SYS_TIME", "setting the clock"},
	{regexp.MustCompile(`(?i)\bptrace\b`), "SYS_PTRACE", "tracing a process"},
	{regexp.MustCompile(`(?i)\bkill\b`), "KILL", "signalling another user's process"},
}

func hasCapability(list []string, name string) bool {
	for _, c := range list {
		if c = strings.TrimPrefix(strings.ToUpper(c), "CAP_"); c == name || c == "ALL" {
			return true
		}
	}
	return false
}

// capabilityDropped finds a container that exits with "Operation not permitted" on something a Linux capability
// guards, in a container whose securityContext drops that capability (or ALL, as the restricted Pod Security
// standard asks). Root without the capability is refused just as any other user is.
func capabilityDropped(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	c, ok := containerSpec(p, cs.Name)
	if !ok || c.SecurityContext == nil || c.SecurityContext.Capabilities == nil || len(c.SecurityContext.Capabilities.Drop) == 0 {
		return nil
	}
	caps := c.SecurityContext.Capabilities
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.Contains(strings.ToLower(lines[i]), "operation not permitted") {
			continue
		}
		for _, k := range capabilityFor {
			if !k.re.MatchString(lines[i]) {
				continue
			}
			if !hasCapability(caps.Drop, k.name) || hasCapability(caps.Add, k.name) {
				return nil
			}
			dropped := "drops " + k.name
			keep := "next to the capabilities it drops"
			if hasCapability(caps.Drop, "ALL") {
				dropped, keep = "drops ALL capabilities", "keeping drop: [ALL]"
			}
			ev = append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s's securityContext %s", cs.Name, dropped),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].securityContext.capabilities}`, cs.Name))})
			return newProblem(p, cs.Name, "KD219", "Container lacks a Linux capability it uses", Critical,
				fmt.Sprintf("container %s exits on an operation that is not permitted: its securityContext %s, and %s needs %s, which root too must hold; its log says: %q",
					cs.Name, dropped, k.what, k.name, clip(lines[i], 200)),
				"capability|"+k.name,
				fmt.Sprintf("Add %s under securityContext.capabilities.add, %s, or change the image or its start script so it no longer needs it (ownership and modes can be set when the image is built, or by fsGroup for volumes).", k.name, keep), ev...)
		}
		return nil
	}
	return nil
}

// reUnknownUser is a program looking up the user it runs as and finding no entry in /etc/passwd: busybox and
// coreutils whoami, Python's pwd module, Go's os/user, OpenSSH and git, Node's os.userInfo, and bash's prompt.
var reUnknownUser = regexp.MustCompile(`(?i)unknown uid (\d+)|getpwuid\(\): uid not found: (\d+)|unknown userid (\d+)|no user exists for uid (\d+)|cannot find name for user id (\d+)|uv_os_get_passwd returned ENOENT|I have no name!`)

// unknownUser finds a container that exits because the app looks up the user it runs as, and the user ID that
// runAsUser sets has no entry in the image's /etc/passwd: a program asking for its home directory or user name gets
// nothing back.
func unknownUser(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	uid, set := p.RunAsUser(cs.Name)
	if !set || uid == 0 {
		return nil
	}
	for i := len(lines) - 1; i >= 0; i-- {
		m := reUnknownUser.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		if n := strings.Join(m[1:], ""); n != "" && n != fmt.Sprint(uid) {
			continue
		}
		where := "the pod's securityContext"
		if c, _ := containerSpec(p, cs.Name); c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
			where = "the container's securityContext"
		}
		cause := fmt.Sprintf("container %s exits because it runs as user ID %d (runAsUser, in %s), which has no entry in the image's /etc/passwd, and the app looks up the user it runs as; its log says: %q",
			cs.Name, uid, where, clip(lines[i], 200))
		fix := fmt.Sprintf("Run as a user the image defines (its USER, or a user ID listed in its /etc/passwd), or add user %d to the image's /etc/passwd when building it.", uid)
		return newProblem(p, cs.Name, "KD312", "Container runs as a user ID the image does not define", Critical, cause,
			fmt.Sprintf("nouser|%d", uid), fix, append(ev, Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s runs as user %d", cs.Name, uid),
				Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.securityContext.runAsUser}{" "}{.spec.containers[?(@.name=="%s")].securityContext.runAsUser}`, cs.Name))})...)
	}
	return nil
}
