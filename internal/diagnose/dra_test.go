package diagnose

import (
	"strings"
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// draSnapshot is a Deployment trainer whose pod runs with one GPU claimed through ResourceClaim train-gpu, of class
// gpu.example.com, which a driver of that name publishes two devices for on node-1.
func draSnapshot() *snapshot.Snapshot {
	s := snap()
	deployment(s, "trainer", 1, 1)
	p := pod("trainer-1", "trainer")
	p.Spec.ResourceClaims = []kube.PodResourceClaim{{Name: "gpu", ResourceClaimName: "train-gpu"}}
	s.Pods = []kube.Pod{p}
	s.ResourceAllocationRead = true
	var class kube.DeviceClass
	class.Metadata.Name = "gpu.example.com"
	class.Spec.Selectors = []kube.DeviceSelector{celSelector(`device.driver == "gpu.example.com"`)}
	s.DeviceClasses = []kube.DeviceClass{class}
	var claim kube.ResourceClaim
	claim.Metadata = kube.ObjectMeta{Name: "train-gpu", Namespace: "shop"}
	claim.Spec.Devices.Requests = []kube.DeviceRequest{{Name: "gpu", Exactly: &kube.ExactDeviceRequest{DeviceClassName: "gpu.example.com"}}}
	s.ResourceClaims = []kube.ResourceClaim{claim}
	var sl kube.ResourceSlice
	sl.Metadata.Name = "node-1-gpu"
	sl.Spec.Driver, sl.Spec.NodeName, sl.Spec.Pool.Name = "gpu.example.com", "node-1", "node-1"
	sl.Spec.Devices = append(sl.Spec.Devices, struct {
		Name string `json:"name"`
	}{"gpu-0"}, struct {
		Name string `json:"name"`
	}{"gpu-1"})
	s.ResourceSlices = []kube.ResourceSlice{sl}
	return s
}

func celSelector(expr string) kube.DeviceSelector {
	var sel kube.DeviceSelector
	sel.CEL = &struct {
		Expression string `json:"expression"`
	}{expr}
	return sel
}

// unscheduledPod turns the snapshot's pod into one the scheduler has not placed, with no condition at all.
func unscheduledPod(s *snapshot.Snapshot) {
	p := &s.Pods[0]
	p.Spec.NodeName = ""
	p.Status = kube.PodStatus{Phase: "Pending"}
	s.Workloads[0].Status.ReadyReplicas, s.Workloads[1].Status.ReadyReplicas = 0, 0
}

func TestAPodWithItsDevicesIsQuiet(t *testing.T) {
	if r := Diagnose(draSnapshot()); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestPodsResourceClaimDoesNotExist(t *testing.T) {
	s := draSnapshot()
	unscheduledPod(s)
	s.ResourceClaims = nil
	f := only(t, Diagnose(s))
	expect(t, f, "KD320", "Deployment shop/trainer", "names ResourceClaim train-gpu, which does not exist in namespace shop", "no condition and no event")
	if !strings.Contains(f.Fix, "Create ResourceClaim train-gpu") || !strings.Contains(f.Fix, "resourceClaimTemplateName") {
		t.Errorf("fix: %s", f.Fix)
	}
	// Claims were not read, or the snapshot is older than 0.15.0: nothing is known about them.
	s.Gaps = []snapshot.Gap{{Resource: "resourceclaims.resource.k8s.io"}}
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD320" {
			t.Errorf("claims unread: %s", f.Cause)
		}
	}
	s.Gaps, s.ResourceAllocationRead = nil, false
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD320" {
			t.Errorf("old snapshot: %s", f.Cause)
		}
	}
}
