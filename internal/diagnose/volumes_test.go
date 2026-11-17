package diagnose

import (
	"strings"
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

func uid(n int64) *int64 { return &n }

// volumePod is a crash-looping pod of Deployment web that mounts volume data at mountPath, with the given log.
func volumePod(s *snapshot.Snapshot, v kube.Volume, mountPath string, readOnly bool, log ...string) *kube.Pod {
	deployment(s, "web", 1, 0)
	p := pod("web-rs-a", "web")
	v.Name = "data"
	p.Spec.Volumes = []kube.Volume{v}
	p.Spec.Containers[0].VolumeMounts = []kube.VolumeMount{{Name: "data", MountPath: mountPath, ReadOnly: readOnly}}
	crashed(&p, 1, "Error", 4)
	s.Pods = []kube.Pod{p}
	s.Logs = []snapshot.Log{{Pod: p.Ref(), Container: "web", Previous: true, Lines: log}}
	return &s.Pods[0]
}

func TestVolumeAccessDenied(t *testing.T) {
	s := snap()
	p := volumePod(s, kube.Volume{HostPath: &kube.HostPathVolumeSource{Path: "/var/lib/app", Type: "DirectoryOrCreate"}}, "/data", false,
		"starting", "touch: /data/ready: Permission denied")
	p.Spec.SecurityContext = &kube.PodSecurityContext{RunAsUser: uid(1000), FSGroup: uid(1000)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD137", "Deployment shop/web", "runs as user 1000", "/data/ready", "hostPath /var/lib/app", "fsGroup does not change its owner")
	if !strings.Contains(f.Fix, "init container") || !strings.Contains(f.Evidence[len(f.Evidence)-1].What, "mounts volume data (hostPath /var/lib/app) at /data") {
		t.Errorf("fix %q evidence %+v", f.Fix, f.Evidence)
	}

	s = snap()
	volumePod(s, kube.Volume{PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "db"}}, "/var/lib/db", false,
		`level=fatal msg="open /var/lib/db/LOCK: permission denied"`)
	f = only(t, Diagnose(s))
	expect(t, f, "KD137", "Deployment shop/web", "the image's user", "PersistentVolumeClaim db", "sets no fsGroup")
	if !strings.Contains(f.Fix, "fsGroup") {
		t.Errorf("fix should set fsGroup: %q", f.Fix)
	}

	s = snap()
	p = volumePod(s, kube.Volume{PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "db"}}, "/var/lib/db", false,
		`PermissionError: [Errno 13] Permission denied: '/var/lib/db/data'`)
	p.Spec.SecurityContext = &kube.PodSecurityContext{FSGroup: uid(2000)}
	expect(t, only(t, Diagnose(s)), "KD137", "Deployment shop/web", "/var/lib/db/data", "fsGroup 2000")

	s = snap()
	volumePod(s, kube.Volume{Secret: &kube.SecretVolumeSource{SecretName: "tls"}}, "/etc/tls", false,
		"cat: can't open '/etc/tls/tls.key': Permission denied")
	f = only(t, Diagnose(s))
	expect(t, f, "KD137", "Deployment shop/web", "/etc/tls/tls.key", "Secret tls")
	if !strings.Contains(f.Fix, "defaultMode") {
		t.Errorf("a Secret's fix is its mode: %q", f.Fix)
	}

	// A path outside every mount is not a volume problem.
	s = snap()
	volumePod(s, kube.Volume{EmptyDir: &kube.EmptyDirVolumeSource{}}, "/data", false, "open /etc/shadow: permission denied")
	expect(t, only(t, Diagnose(s)), "KD110", "Deployment shop/web")
}

func TestWritesToAReadOnlyVolume(t *testing.T) {
	s := snap()
	volumePod(s, kube.Volume{ConfigMap: &kube.ConfigMapVolumeSource{Name: "app"}}, "/etc/app", false,
		"sh: can't create /etc/app/app.conf: Read-only file system")
	f := only(t, Diagnose(s))
	expect(t, f, "KD138", "Deployment shop/web", "/etc/app/app.conf", "always mounts a ConfigMap volume read-only")
	if !strings.Contains(f.Fix, "emptyDir") {
		t.Errorf("fix %q", f.Fix)
	}

	s = snap()
	volumePod(s, kube.Volume{PersistentVolumeClaim: &kube.PVCVolumeSource{ClaimName: "reports"}}, "/data", true,
		"OSError: [Errno 30] Read-only file system: '/data/out.csv'")
	f = only(t, Diagnose(s))
	expect(t, f, "KD138", "Deployment shop/web", "/data/out.csv", "sets readOnly: true")
	if !strings.Contains(f.Fix, "Remove readOnly: true") {
		t.Errorf("fix %q", f.Fix)
	}

	// A write outside the mounts, with a read-only root filesystem, is still KD118.
	s = snap()
	p := volumePod(s, kube.Volume{ConfigMap: &kube.ConfigMapVolumeSource{Name: "app"}}, "/etc/app", false,
		"touch: /tmp/x: Read-only file system")
	p.Spec.Containers[0].SecurityContext = &kube.SecurityContext{ReadOnlyRootFilesystem: yes()}
	expect(t, only(t, Diagnose(s)), "KD118", "Deployment shop/web")
}

func TestFileMissingFromAConfigMapVolume(t *testing.T) {
	s := snap()
	volumePod(s, kube.Volume{ConfigMap: &kube.ConfigMapVolumeSource{Name: "app"}}, "/etc/app", false,
		"cat: can't open '/etc/app/config.yaml': No such file or directory")
	s.ConfigMaps = []kube.KeySet{keys("shop", "app", "config.yml")}
	f := only(t, Diagnose(s))
	expect(t, f, "KD230", "Deployment shop/web", "/etc/app/config.yaml does not exist", "ConfigMap app, mounted at /etc/app, has no key config.yaml (it has config.yml)")
	if !strings.Contains(f.Fix, "Add key config.yaml to ConfigMap app") {
		t.Errorf("fix %q", f.Fix)
	}

	// Items project only some keys.
	s = snap()
	volumePod(s, kube.Volume{Secret: &kube.SecretVolumeSource{SecretName: "tls", Items: []kube.KeyToPath{{Key: "tls.crt", Path: "cert.pem"}}}},
		"/etc/tls", false, "open /etc/tls/key.pem: no such file or directory")
	s.Secrets = []kube.KeySet{keys("shop", "tls", "tls.crt", "tls.key")}
	f = only(t, Diagnose(s))
	expect(t, f, "KD230", "Deployment shop/web", "projects only the items cert.pem, not key.pem")
	if !strings.Contains(f.Fix, "items") {
		t.Errorf("fix %q", f.Fix)
	}

	// The file is there: something else is wrong, so this is no volume finding.
	s = snap()
	volumePod(s, kube.Volume{ConfigMap: &kube.ConfigMapVolumeSource{Name: "app"}}, "/etc/app", false,
		"open /etc/app/config.yaml/extra: no such file or directory")
	s.ConfigMaps = []kube.KeySet{keys("shop", "app", "config.yaml")}
	expect(t, only(t, Diagnose(s)), "KD110", "Deployment shop/web")

	// Keys not read: no claim about what the ConfigMap lacks.
	s = snap()
	volumePod(s, kube.Volume{ConfigMap: &kube.ConfigMapVolumeSource{Name: "app"}}, "/etc/app", false,
		"cat: can't open '/etc/app/config.yaml': No such file or directory")
	s.Gaps = []snapshot.Gap{{Resource: "configmaps", Namespace: "shop", Error: "forbidden"}}
	expect(t, only(t, Diagnose(s)), "KD110", "Deployment shop/web")
}

func TestCommandMissingFromAConfigMapVolume(t *testing.T) {
	s := snap()
	p := volumePod(s, kube.Volume{ConfigMap: &kube.ConfigMapVolumeSource{Name: "scripts"}}, "/scripts", false)
	p.Spec.Containers[0].Command = []string{"/scripts/start.sh"}
	p.Status.ContainerStatuses[0].LastTerminationState.Terminated = &kube.ContainerStateTerminated{ExitCode: 128, Reason: "StartError",
		Message: `failed to create containerd task: failed to create shim task: OCI runtime create failed: runc create failed: unable to start container process: error during container init: exec: "/scripts/start.sh": stat /scripts/start.sh: no such file or directory: unknown`}
	s.ConfigMaps = []kube.KeySet{keys("shop", "scripts", "run.sh")}
	expect(t, only(t, Diagnose(s)), "KD230", "Deployment shop/web", "runs /scripts/start.sh, which does not exist", "has no key start.sh (it has run.sh)")
}
