package diagnose

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// Problems a container meets on the volumes it mounts, read from the line its log ends with: a file it may not
// write, a volume it writes that is read-only, a file a ConfigMap does not have. Each names the mount and the volume
// behind it, since that is where the fix goes.

var rePath = regexp.MustCompile(`(?:^|[\s'"(=\[])(/[^\s'":,()\[\]]+)`)

// mountedPath finds the first absolute path in a log line that lies under one of the container's volume mounts.
func mountedPath(p kube.Pod, container, line string) (string, kube.Mount, bool) {
	for _, m := range rePath.FindAllStringSubmatch(line, -1) {
		if mt, ok := p.MountAt(container, m[1]); ok {
			return m[1], mt, true
		}
	}
	return "", kube.Mount{}, false
}

func mountEvidence(p kube.Pod, container string, m kube.Mount) Evidence {
	what := fmt.Sprintf("container %s mounts volume %s (%s) at %s", container, m.Name, m.Volume.Source(), m.MountPath)
	if m.ReadOnly {
		what += " with readOnly: true"
	}
	return Evidence{Object: p.Ref(), What: what,
		Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.volumes[?(@.name=="%s")]}`, m.Name))}
}

// readOnlyVolume finds a container that exits because it writes to a volume mounted read-only: a ConfigMap, Secret,
// projected or downward API volume, which the kubelet always mounts read-only, or a mount with readOnly: true.
func readOnlyVolume(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.Contains(strings.ToLower(lines[i]), "read-only file system") {
			continue
		}
		path, m, ok := mountedPath(p, cs.Name, lines[i])
		if !ok || !m.ReadOnly && !m.Volume.AlwaysReadOnly() {
			continue
		}
		why := fmt.Sprintf("the mount of volume %s at %s sets readOnly: true", m.Name, m.MountPath)
		fix := fmt.Sprintf("Remove readOnly: true from the mount of volume %s at %s if the container is meant to write there, or point the app at a writable volume.", m.Name, m.MountPath)
		if m.Volume.AlwaysReadOnly() {
			why = fmt.Sprintf("%s is mounted at %s, and the kubelet always mounts a %s read-only", m.Volume.Source(), m.MountPath, kindOfVolume(m.Volume))
			fix = fmt.Sprintf("Write to a writable volume instead: mount an emptyDir for the files the app changes, and copy what it needs from %s into it with an init container.", m.Volume.Source())
		}
		cause := fmt.Sprintf("container %s exits because it writes to %s, which is read-only: %s; its log says: %q", cs.Name, path, why, clip(lines[i], 160))
		return newProblem(p, cs.Name, "KD138", "Container writes to a read-only volume", Critical, cause, "rovol|"+m.Name, fix,
			append(ev, mountEvidence(p, cs.Name, m))...)
	}
	return nil
}

func kindOfVolume(v kube.Volume) string {
	switch {
	case v.ConfigMap != nil:
		return "ConfigMap volume"
	case v.Secret != nil:
		return "Secret volume"
	case v.Projected != nil:
		return "projected volume"
	case v.DownwardAPI != nil:
		return "downward API volume"
	}
	return "volume"
}

// volumeDenied finds a container that exits because it may not use a file on a mounted volume: the volume's files
// belong to another user than the one the container runs as.
func volumeDenied(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.Contains(strings.ToLower(lines[i]), "permission denied") {
			continue
		}
		path, m, ok := mountedPath(p, cs.Name, lines[i])
		if !ok {
			continue
		}
		user := "the image's user"
		if uid, ok := p.RunAsUser(cs.Name); ok {
			user = fmt.Sprintf("user %d", uid)
		}
		cause := fmt.Sprintf("container %s runs as %s and is denied access to %s on volume %s (%s): %q", cs.Name, user, path, m.Name, m.Volume.Source(), clip(lines[i], 160))
		fsGroup := p.Spec.SecurityContext != nil && p.Spec.SecurityContext.FSGroup != nil
		var fix string
		switch {
		case m.Volume.HostPath != nil:
			cause += fmt.Sprintf("; hostPath %s belongs to the node, and fsGroup does not change its owner", m.Volume.HostPath.Path)
			fix = fmt.Sprintf("Give %s on the node to %s, or chown it from an init container that runs as root, or run the container as the directory's owner. fsGroup does not apply to hostPath volumes.", m.Volume.HostPath.Path, user)
		case m.Volume.AlwaysReadOnly():
			fix = fmt.Sprintf("Let the container read the files: set fsGroup in the pod's securityContext and a defaultMode that gives the group read access (0440), or a mode readable by everyone (0444), on %s.", m.Volume.Source())
		case fsGroup:
			cause += fmt.Sprintf("; the pod sets fsGroup %d, which the volume's driver may not apply", *p.Spec.SecurityContext.FSGroup)
			fix = "Check that the volume's CSI driver supports fsGroup (its fsGroupPolicy), or chown the directory from an init container that runs as root."
		default:
			cause += "; the pod sets no fsGroup"
			fix = "Set securityContext.fsGroup on the pod to the group the container runs as, so the kubelet gives that group access to the volume, or chown the directory from an init container that runs as root."
		}
		return newProblem(p, cs.Name, "KD137", "Container is denied access to a mounted volume", Critical, cause, "denied|"+m.Name, fix,
			append(ev, mountEvidence(p, cs.Name, m))...)
	}
	return nil
}
