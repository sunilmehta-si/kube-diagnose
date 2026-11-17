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
			if mode, from, ok := fileMode(m); ok {
				cause += fmt.Sprintf("; the volume's files have mode %04o (%s) and belong to root", mode, from)
				if !fsGroup {
					cause += ", and the pod sets no fsGroup"
				}
			}
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

// volumeFiles lists the files a ConfigMap or Secret volume puts at its mount point: the items it projects, or every
// key. known is false when the object's keys could not be read.
func (ix *index) volumeFiles(ns string, v kube.Volume) (kind, name string, files []string, known bool) {
	var items []kube.KeyToPath
	switch {
	case v.ConfigMap != nil:
		kind, name, items = "ConfigMap", v.ConfigMap.Name, v.ConfigMap.Items
	case v.Secret != nil:
		kind, name, items = "Secret", v.Secret.SecretName, v.Secret.Items
	default:
		return "", "", nil, false
	}
	if len(items) > 0 {
		for _, it := range items {
			files = append(files, it.Path)
		}
		return kind, name, files, true
	}
	ks, exists, read := ix.keySet(strings.ToLower(kind), ns, name)
	if !exists || !read {
		return kind, name, nil, false
	}
	return kind, name, ks.Keys, true
}

// missingVolumeFile finds a path a container fails to open, or to run, because the ConfigMap or Secret volume it
// lies under has no such file.
func missingVolumeFile(ix *index, p kube.Pod, container, path string) (kube.Mount, string, bool) {
	m, ok := p.MountAt(container, path)
	if !ok || m.SubPath != "" || m.Rel == "" {
		return m, "", false
	}
	kind, name, files, known := ix.volumeFiles(p.Metadata.Namespace, m.Volume)
	if !known {
		return m, "", false
	}
	first := strings.SplitN(m.Rel, "/", 2)[0]
	for _, f := range files {
		if f == first || strings.HasPrefix(f, first+"/") {
			return m, "", false
		}
	}
	have := "no keys"
	if len(files) > 0 {
		have = strings.Join(files, ", ")
	}
	what := fmt.Sprintf("%s %s, mounted at %s, has no key %s (it has %s)", kind, name, m.MountPath, first, have)
	if (m.Volume.ConfigMap != nil && len(m.Volume.ConfigMap.Items) > 0) || (m.Volume.Secret != nil && len(m.Volume.Secret.Items) > 0) {
		what = fmt.Sprintf("the volume of %s %s, mounted at %s, projects only the items %s, not %s", kind, name, m.MountPath, have, first)
	}
	return m, what, true
}

var reNoSuchFile = regexp.MustCompile(`(?i)no such file or directory`)

// fileNotInVolume finds a container that exits because a file it opens is not in the ConfigMap or Secret volume it
// expects it in: usually a key named differently from the file the app reads.
func fileNotInVolume(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	for i := len(lines) - 1; i >= 0; i-- {
		if !reNoSuchFile.MatchString(lines[i]) {
			continue
		}
		for _, pm := range rePath.FindAllStringSubmatch(lines[i], -1) {
			if m, what, ok := missingVolumeFile(ix, p, cs.Name, pm[1]); ok {
				cause := fmt.Sprintf("container %s exits because %s does not exist: %s; its log says: %q", cs.Name, pm[1], what, clip(lines[i], 160))
				return volumeFileProblem(p, cs.Name, m, cause, ev)
			}
		}
	}
	return nil
}

func volumeFileProblem(p kube.Pod, container string, m kube.Mount, cause string, ev []Evidence) *problem {
	first := strings.SplitN(m.Rel, "/", 2)[0]
	src := m.Volume.Source()
	fix := fmt.Sprintf("Add key %s to %s, or point the app at a file the volume has.", first, src)
	if (m.Volume.ConfigMap != nil && len(m.Volume.ConfigMap.Items) > 0) || (m.Volume.Secret != nil && len(m.Volume.Secret.Items) > 0) {
		fix = fmt.Sprintf("Add %s to the volume's items (and the key to %s), or point the app at a file the volume projects.", first, src)
	}
	return newProblem(p, container, "KD230", "File is missing from a ConfigMap or Secret volume", Critical, cause,
		"volfile|"+m.Name+"|"+first, fix, append(ev, mountEvidence(p, container, m))...)
}

// fileMode is the mode the kubelet gives a file of a ConfigMap, Secret or projected volume: the item's mode, else
// the volume's defaultMode, else 0644.
func fileMode(m kube.Mount) (int32, string, bool) {
	first := strings.SplitN(m.Rel, "/", 2)[0]
	var items []kube.KeyToPath
	var def *int32
	switch v := m.Volume; {
	case v.ConfigMap != nil:
		items, def = v.ConfigMap.Items, v.ConfigMap.DefaultMode
	case v.Secret != nil:
		items, def = v.Secret.Items, v.Secret.DefaultMode
	case v.Projected != nil:
		def = v.Projected.DefaultMode
	default:
		return 0, "", false
	}
	for _, it := range items {
		if it.Path == first && it.Mode != nil {
			return *it.Mode, "the item's mode", true
		}
	}
	if def != nil {
		return *def, "defaultMode", true
	}
	return 0o644, "the default mode, as no defaultMode is set", true
}

var reExecDenied = regexp.MustCompile(`exec: "([^"]+)": permission denied`)

// notExecutable explains a command the runtime may not execute. When it comes from a ConfigMap, Secret or projected
// volume, the volume's file mode is why: those files are 0644 unless the volume says otherwise.
func notExecutable(p kube.Pod, container, path, detail string, ev []Evidence) *problem {
	cause := fmt.Sprintf("container %s's command %s is not executable (permission denied)", container, path)
	fix := fmt.Sprintf("Make %s executable in the image (chmod +x when building it), or run it through its interpreter, for example command: [\"sh\", %q].", path, path)
	key := "noexecbit|" + path
	if m, ok := p.MountAt(container, path); ok {
		if mode, from, ok := fileMode(m); ok && mode&0o111 == 0 {
			cause = fmt.Sprintf("container %s runs %s from %s, whose files have mode %04o (%s), so it is not executable", container, path, m.Volume.Source(), mode, from)
			fix = fmt.Sprintf("Set defaultMode: 0755 on volume %s (or mode: 0755 on its item), or run the script through its interpreter, for example command: [\"sh\", %q].", m.Name, path)
			ev = append(ev, mountEvidence(p, container, m))
		}
	}
	if detail != "" {
		cause += fmt.Sprintf("; %q", clip(detail, 160))
	}
	return newProblem(p, container, "KD200", "Command is not executable", Critical, cause, key, fix, ev...)
}

// deniedScript finds a script a shell could not run (exit code 126, permission denied) under a volume mount.
func deniedScript(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.Contains(strings.ToLower(lines[i]), "permission denied") {
			continue
		}
		if path, _, ok := mountedPath(p, cs.Name, lines[i]); ok {
			return notExecutable(p, cs.Name, path, lines[i], ev)
		}
	}
	return nil
}
