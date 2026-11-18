package diagnose

import (
	"fmt"
	"regexp"
	"slices"
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
	case v.Projected != nil:
		return ix.projectedFiles(ns, *v.Projected)
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
	if m.Volume.Projected != nil {
		fix = fmt.Sprintf("Add key %s to one of the ConfigMaps or Secrets the projected volume draws from, or point the app at a file the volume has.", first)
	}
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
		for _, src := range v.Projected.Sources {
			if src.ConfigMap != nil {
				items = append(items, src.ConfigMap.Items...)
			}
			if src.Secret != nil {
				items = append(items, src.Secret.Items...)
			}
		}
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

// projectedFiles lists the files of a projected volume made only of ConfigMaps and Secrets. Other sources (a
// ServiceAccount token, the downward API) add files whose names are not all in the spec, so the list is not known.
func (ix *index) projectedFiles(ns string, v kube.ProjectedVolumeSource) (kind, name string, files []string, known bool) {
	var names []string
	for _, src := range v.Sources {
		var items []kube.KeyToPath
		var srcKind, srcName string
		switch {
		case src.ConfigMap != nil:
			srcKind, srcName, items = "configmap", src.ConfigMap.Name, src.ConfigMap.Items
		case src.Secret != nil:
			srcKind, srcName, items = "secret", src.Secret.Name, src.Secret.Items
		default:
			return "", "", nil, false
		}
		names = append(names, kindName(srcKind)+" "+srcName)
		if len(items) > 0 {
			for _, it := range items {
				files = append(files, it.Path)
			}
			continue
		}
		ks, exists, read := ix.keySet(srcKind, ns, srcName)
		if !exists || !read {
			return "", "", nil, false
		}
		files = append(files, ks.Keys...)
	}
	return "projected volume of", strings.Join(names, " and "), files, true
}

// subPathMissing finds a mount of the container whose subPath names a file its ConfigMap or Secret volume does not
// have. The kubelet then makes an empty directory in its place, so the container finds a directory where it expects a
// file, or the runtime cannot mount that directory over a file the image already has. at, when set, is the mount path.
func subPathMissing(ix *index, p kube.Pod, container, at string) (vm kube.VolumeMount, kind, name string, files []string, ok bool) {
	c, _ := containerSpec(p, container)
	for _, vm := range c.VolumeMounts {
		if vm.SubPath == "" || (at != "" && strings.TrimRight(vm.MountPath, "/") != strings.TrimRight(at, "/")) {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.Name != vm.Name {
				continue
			}
			kind, name, files, known := ix.volumeFiles(p.Metadata.Namespace, v)
			if !known || slices.Contains(files, vm.SubPath) {
				continue
			}
			// A subPath under a projected directory (items with dir/file paths) is not a missing file.
			under := false
			for _, f := range files {
				if strings.HasPrefix(f, vm.SubPath+"/") {
					under = true
				}
			}
			if !under {
				return vm, kind, name, files, true
			}
		}
	}
	return kube.VolumeMount{}, "", "", nil, false
}

// subPathProblem reports a subPath that names a file the volume does not have, with what happened as a result.
func subPathProblem(ix *index, p kube.Pod, container, at, result string, ev []Evidence) *problem {
	vm, kind, name, files, ok := subPathMissing(ix, p, container, at)
	if !ok {
		return nil
	}
	have := "no keys"
	if len(files) > 0 {
		have = strings.Join(files, ", ")
	}
	ev = append(ev, Evidence{Object: kube.Ref{Kind: kind, Namespace: p.Metadata.Namespace, Name: name},
		What:    fmt.Sprintf("%s %s has %s, not %s", kind, name, have, vm.SubPath),
		Command: cmdGet(strings.ToLower(kind), p.Metadata.Namespace, name, "{.data}")},
		Evidence{Object: p.Ref(), What: fmt.Sprintf("container %s mounts volume %s at %s with subPath %s", container, vm.Name, vm.MountPath, vm.SubPath),
			Command: cmdGet("pod", p.Metadata.Namespace, p.Metadata.Name, fmt.Sprintf(`{.spec.containers[?(@.name=="%s")].volumeMounts}`, container))})
	return newProblem(p, container, "KD234", "subPath names a file the volume does not have", Critical,
		fmt.Sprintf("container %s mounts %s with subPath %s, but %s %s has no such key (it has %s), so the kubelet made an empty directory in its place: %s", container, vm.MountPath, vm.SubPath, kind, name, have, result),
		"subpath|"+vm.Name+"|"+vm.SubPath,
		fmt.Sprintf("Make subPath name a key %s %s has, or add key %s to it; then delete the pod, because the directory the kubelet made stays until the pod is replaced (and a subPath mount never sees later updates to the %s).", kind, name, vm.SubPath, kind), ev...)
}

var reMountOntoFile = regexp.MustCompile(`to rootfs at "([^"]+)"[^\n]*(?:not a directory|Are you trying to mount a directory onto a file)`)

// subPathOntoFile finds a container that cannot start because the runtime may not mount a directory, the one the
// kubelet made for a missing subPath, over a file the image has.
func subPathOntoFile(ix *index, p kube.Pod, container, msg string, ev []Evidence) *problem {
	m := reMountOntoFile.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	return subPathProblem(ix, p, container, m[1], fmt.Sprintf("the runtime cannot mount that directory over the file %s in the image, so the container never starts", m[1]), ev)
}

var reIsADirectory = regexp.MustCompile(`(?i)is a directory`)

// subPathIsADirectory finds a container that exits because the file it reads at a subPath mount is a directory.
func subPathIsADirectory(ix *index, p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	for i := len(lines) - 1; i >= 0; i-- {
		if !reIsADirectory.MatchString(lines[i]) {
			continue
		}
		c, _ := containerSpec(p, cs.Name)
		for _, vm := range c.VolumeMounts {
			if vm.SubPath != "" && strings.Contains(lines[i], vm.MountPath) {
				if pr := subPathProblem(ix, p, cs.Name, vm.MountPath, fmt.Sprintf("the container finds a directory at %s and exits; its log says: %q", vm.MountPath, clip(lines[i], 200)), ev); pr != nil {
					return pr
				}
			}
		}
		// Tools such as cat do not name the path ("cat: read error: Is a directory"): a missing subPath is the one
		// directory the container did not ask for.
		if vm, _, _, _, ok := subPathMissing(ix, p, cs.Name, ""); ok {
			return subPathProblem(ix, p, cs.Name, vm.MountPath, fmt.Sprintf("the container finds a directory at %s and exits; its log says: %q", vm.MountPath, clip(lines[i], 200)), ev)
		}
		return nil
	}
	return nil
}
