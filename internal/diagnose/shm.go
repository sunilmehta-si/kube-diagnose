package diagnose

import (
	"fmt"
	"regexp"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// reShmFull matches what an app says when shared memory runs out: a write to /dev/shm that finds no space,
// PyTorch's DataLoader workers dying of a bus error, NCCL failing to make its segments, PostgreSQL failing to grow
// its own.
var reShmFull = regexp.MustCompile(`(?i)/dev/shm\S*:? .*no space left on device|no space left on device.*/dev/shm|insufficient shared memory|bus error.*\bshm\b|NCCL.*(?:shared memory|/dev/shm)|could not resize shared memory segment`)

// shmTooSmall finds a container that exits because /dev/shm is full. The container runtime gives each pod a 64 MiB
// /dev/shm unless a memory-backed emptyDir is mounted there; data loaders, NCCL, browsers and databases need more.
func shmTooSmall(p kube.Pod, cs kube.ContainerStatus, lines []string, ev []Evidence) *problem {
	bad := ""
	for i := len(lines) - 1; i >= 0 && bad == ""; i-- {
		if reShmFull.MatchString(lines[i]) {
			bad = lines[i]
		}
	}
	if bad == "" {
		return nil
	}
	m, mounted := p.MountAt(cs.Name, "/dev/shm")
	if mounted && (m.MountPath != "/dev/shm" && m.MountPath != "/dev/shm/" || m.Volume.EmptyDir == nil) {
		mounted = false
	}
	cause := fmt.Sprintf("container %s exits because shared memory (/dev/shm) is full: nothing is mounted at /dev/shm, so it is the container runtime's 64 MiB; its log says: %q", cs.Name, clip(bad, 200))
	fix := "Mount an emptyDir with medium: Memory at /dev/shm, with a sizeLimit for what the app needs (it counts toward the container's memory limit), or have the app use less shared memory (fewer DataLoader workers, for one)."
	if mounted {
		size := "no sizeLimit, so it may grow to the pod's memory limit"
		if m.Volume.EmptyDir.SizeLimit != "" {
			size = "sizeLimit " + m.Volume.EmptyDir.SizeLimit
		}
		cause = fmt.Sprintf("container %s exits because shared memory (/dev/shm) is full: volume %s is mounted there with %s; its log says: %q", cs.Name, m.Name, size, clip(bad, 200))
		fix = fmt.Sprintf("Raise volume %s's sizeLimit (and the memory limit, which the volume counts toward), or have the app use less shared memory.", m.Name)
		ev = append(ev, mountEvidence(p, cs.Name, m))
	}
	return newProblem(p, cs.Name, "KD313", "Shared memory (/dev/shm) is too small", Critical, cause, "shm|"+cs.Name, fix, ev...)
}
