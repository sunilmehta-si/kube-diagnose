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

func TestPodsResourceClaimTemplateDoesNotExist(t *testing.T) {
	s := draSnapshot()
	unscheduledPod(s)
	s.Pods[0].Spec.ResourceClaims = []kube.PodResourceClaim{{Name: "gpu", ResourceClaimTemplateName: "one-gpu"}}
	s.ResourceClaims = nil
	s.Events = []kube.Event{event("Pod", "trainer-1", "FailedResourceClaimCreation", `PodResourceClaim gpu: resource claim template "one-gpu": resourceclaimtemplate.resource.k8s.io "one-gpu" not found`, 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD321", "Deployment shop/trainer", "names ResourceClaimTemplate one-gpu, which does not exist in namespace shop", "no claim is made for the pod")
	if len(f.Evidence) != 3 || !strings.Contains(f.Evidence[1].Detail+f.Evidence[1].What, "not found") {
		t.Errorf("evidence %+v", f.Evidence)
	}
	// With the template there, its claim made: nothing to report.
	var tpl kube.ResourceClaimTemplate
	tpl.Metadata = kube.ObjectMeta{Name: "one-gpu", Namespace: "shop"}
	tpl.Spec.Spec.Devices.Requests = []kube.DeviceRequest{{Name: "gpu", Exactly: &kube.ExactDeviceRequest{DeviceClassName: "gpu.example.com"}}}
	s = draSnapshot()
	s.Pods[0].Spec.ResourceClaims = []kube.PodResourceClaim{{Name: "gpu", ResourceClaimTemplateName: "one-gpu"}}
	s.Pods[0].Status.ResourceClaimStatuses = append(s.Pods[0].Status.ResourceClaimStatuses, struct {
		Name              string `json:"name"`
		ResourceClaimName string `json:"resourceClaimName,omitempty"`
	}{"gpu", "train-gpu"})
	s.ResourceClaimTemplates = []kube.ResourceClaimTemplate{tpl}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

func TestClaimAsksForADeviceClassThatDoesNotExist(t *testing.T) {
	s := draSnapshot()
	unscheduledPod(s)
	s.ResourceClaims[0].Spec.Devices.Requests[0].Exactly.DeviceClassName = "gpu.nvidia.com"
	s.Events = []kube.Event{event("Pod", "trainer-1", "FailedScheduling", "0/1 nodes are available: request gpu: device class gpu.nvidia.com does not exist. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.", 0)}
	f := only(t, Diagnose(s))
	expect(t, f, "KD322", "Deployment shop/trainer", "request gpu of ResourceClaim train-gpu asks for devices of DeviceClass gpu.nvidia.com, which does not exist", "the cluster's classes: gpu.example.com")
	if len(f.Evidence) != 3 || !strings.Contains(f.Fix, "install the DRA driver that provides class gpu.nvidia.com") {
		t.Errorf("evidence %+v fix %s", f.Evidence, f.Fix)
	}
	// No class at all: no driver is installed.
	s.DeviceClasses = nil
	expect(t, only(t, Diagnose(s)), "KD322", "Deployment shop/trainer", "no DRA driver is installed")
	// A firstAvailable request with one class that exists can still be met.
	s = draSnapshot()
	unscheduledPod(s)
	req := &s.ResourceClaims[0].Spec.Devices.Requests[0]
	req.Exactly = nil
	req.FirstAvailable = append(req.FirstAvailable, struct {
		Name string `json:"name"`
		kube.ExactDeviceRequest
	}{"big", kube.ExactDeviceRequest{DeviceClassName: "gpu.nvidia.com"}}, struct {
		Name string `json:"name"`
		kube.ExactDeviceRequest
	}{"small", kube.ExactDeviceRequest{DeviceClassName: "gpu.example.com"}})
	for _, f := range Diagnose(s).Findings {
		if f.Rule == "KD322" {
			t.Errorf("one choice exists: %s", f.Cause)
		}
	}
}

func TestNoDriverOffersADeviceOfTheClaimedClass(t *testing.T) {
	s := draSnapshot()
	unscheduledPod(s)
	s.Events = []kube.Event{event("Pod", "trainer-1", "FailedScheduling", "0/1 nodes are available: 1 cannot allocate all claims. preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling.", 0)}
	s.ResourceSlices[0].Spec.Driver = "nic.example.com"
	f := only(t, Diagnose(s))
	expect(t, f, "KD323", "Deployment shop/trainer", "asks for devices of DeviceClass gpu.example.com", "no ResourceSlice offers a device from driver gpu.example.com", "cannot allocate the claim on any node")
	if f.Evidence[len(f.Evidence)-1].Command != "kubectl get resourceslices --field-selector spec.driver=gpu.example.com" {
		t.Errorf("evidence %+v", f.Evidence)
	}
	// No slices at all: no driver runs.
	s.ResourceSlices = nil
	expect(t, only(t, Diagnose(s)), "KD323", "Deployment shop/trainer", "the cluster has no ResourceSlices")
	// The scheduler has not tried the pod yet: too early to say.
	s.Events = nil
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}
