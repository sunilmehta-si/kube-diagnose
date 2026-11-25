package diagnose

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// Dynamic resource allocation: a pod asks for devices (a GPU, a NIC) through ResourceClaims, made by hand or from a
// ResourceClaimTemplate; each request of a claim names a DeviceClass, and the scheduler picks devices of that class
// from those drivers publish in ResourceSlices, then the node's driver prepares them before the containers start.

// podClaimRef is one entry of a pod's resourceClaims, resolved: the claim it uses (nil when there is none yet) and,
// for a template, the template it is made from.
type podClaimRef struct {
	entry    kube.PodResourceClaim
	claim    *kube.ResourceClaim
	template *kube.ResourceClaimTemplate
	name     string // the claim's name: given, or generated from the template; "" when not generated yet
}

// spec is what the claim asks for: the claim's own spec, or its template's when the claim is not made yet.
func (r podClaimRef) spec() *kube.ResourceClaimSpec {
	if r.claim != nil {
		return &r.claim.Spec
	}
	if r.template != nil {
		return &r.template.Spec.Spec
	}
	return nil
}

func (ix *index) podClaims(p kube.Pod) []podClaimRef {
	ns := p.Metadata.Namespace
	var out []podClaimRef
	for _, e := range p.Spec.ResourceClaims {
		r := podClaimRef{entry: e, name: e.ResourceClaimName}
		if e.ResourceClaimTemplateName != "" {
			r.name = ""
			for _, st := range p.Status.ResourceClaimStatuses {
				if st.Name == e.Name {
					r.name = st.ResourceClaimName
				}
			}
			r.template = ix.claimTemplate(ns, e.ResourceClaimTemplateName)
		}
		if r.name != "" {
			r.claim = ix.resourceClaim(ns, r.name)
		}
		out = append(out, r)
	}
	return out
}

func (ix *index) resourceClaim(ns, name string) *kube.ResourceClaim {
	for i := range ix.s.ResourceClaims {
		if c := &ix.s.ResourceClaims[i]; c.Metadata.Namespace == ns && c.Metadata.Name == name {
			return c
		}
	}
	return nil
}

func (ix *index) claimTemplate(ns, name string) *kube.ResourceClaimTemplate {
	for i := range ix.s.ResourceClaimTemplates {
		if t := &ix.s.ResourceClaimTemplates[i]; t.Metadata.Namespace == ns && t.Metadata.Name == name {
			return t
		}
	}
	return nil
}

// draRead reports whether dynamic resource allocation's objects of this kind were read: the cluster serves the
// API, the snapshot is recent enough to hold them, and the list was not refused.
func (ix *index) draRead(resource string) bool {
	return ix.s.ResourceAllocationRead && ix.read(resource+".resource.k8s.io")
}

// draProblem finds a pod held back by the devices it claims. It runs before the scheduler's message is read: the
// scheduler does not even try a pod whose claim does not exist, so such a pod has no PodScheduled condition and no
// event, and nothing else says why it waits.
func draProblem(ix *index, p kube.Pod) *problem {
	if len(p.Spec.ResourceClaims) == 0 || p.Status.Phase != "Pending" || !ix.s.ResourceAllocationRead {
		return nil
	}
	refs := ix.podClaims(p)
	for _, r := range refs {
		if pr := claimMissing(ix, p, r); pr != nil {
			return pr
		}
		if pr := claimTemplateMissing(ix, p, r); pr != nil {
			return pr
		}
		if pr := deviceClassMissing(ix, p, r); pr != nil {
			return pr
		}
	}
	for _, r := range refs {
		if pr := deviceShortage(ix, p, r); pr != nil {
			return pr
		}
	}
	return nil
}

// claimMissing finds a pod that names a ResourceClaim which does not exist. The scheduler leaves such a pod out of
// its queue until the claim is created, so it waits with no condition and no event.
func claimMissing(ix *index, p kube.Pod, r podClaimRef) *problem {
	if r.entry.ResourceClaimName == "" || r.claim != nil || p.Spec.NodeName != "" || !ix.draRead("resourceclaims") {
		return nil
	}
	ns, name := p.Metadata.Namespace, r.entry.ResourceClaimName
	cause := fmt.Sprintf("the pod's resourceClaims entry %s names ResourceClaim %s, which does not exist in namespace %s: the scheduler does not try a pod until each claim it names exists, so the pod waits with no condition and no event",
		r.entry.Name, name, ns)
	fix := fmt.Sprintf("Create ResourceClaim %s in namespace %s, or correct the name in the pod template. For a claim of each pod's own, use resourceClaimTemplateName with a ResourceClaimTemplate instead.", name, ns)
	return newProblem(p, "", "KD320", "Pod's ResourceClaim does not exist", Critical, cause, "noclaim|"+name, fix,
		Evidence{Object: p.Ref(), What: fmt.Sprintf("pod claims %s through ResourceClaim %s", r.entry.Name, name),
			Command: cmdGet("pod", ns, p.Metadata.Name, `{.spec.resourceClaims}`)},
		Evidence{Object: kube.Ref{Kind: "ResourceClaim", Namespace: ns, Name: name}, What: fmt.Sprintf("there is no ResourceClaim %s in namespace %s", name, ns),
			Command: cmdGet("resourceclaim", ns, name, "")})
}

// claimTemplateMissing finds a pod whose resourceClaims names a ResourceClaimTemplate that does not exist: the
// resource claim controller cannot make the pod's claim, and the scheduler waits for that claim.
func claimTemplateMissing(ix *index, p kube.Pod, r podClaimRef) *problem {
	if r.entry.ResourceClaimTemplateName == "" || r.template != nil || r.claim != nil || p.Spec.NodeName != "" || !ix.draRead("resourceclaimtemplates") {
		return nil
	}
	ns, name := p.Metadata.Namespace, r.entry.ResourceClaimTemplateName
	cause := fmt.Sprintf("the pod's resourceClaims entry %s names ResourceClaimTemplate %s, which does not exist in namespace %s: no claim is made for the pod, and the scheduler waits for one",
		r.entry.Name, name, ns)
	ev := []Evidence{{Object: p.Ref(), What: fmt.Sprintf("pod claims %s through ResourceClaimTemplate %s", r.entry.Name, name),
		Command: cmdGet("pod", ns, p.Metadata.Name, `{.spec.resourceClaims}{"\n"}{.status.resourceClaimStatuses}`)}}
	if evs := ix.eventsFor(p.Ref(), "FailedResourceClaimCreation"); len(evs) > 0 {
		ev = append(ev, eventEvidence(p.Ref(), evs[0]))
	}
	ev = append(ev, Evidence{Object: kube.Ref{Kind: "ResourceClaimTemplate", Namespace: ns, Name: name},
		What: fmt.Sprintf("there is no ResourceClaimTemplate %s in namespace %s", name, ns), Command: cmdGet("resourceclaimtemplate", ns, name, "")})
	fix := fmt.Sprintf("Create ResourceClaimTemplate %s in namespace %s (a template lives in the namespace of the pods that use it), or correct the name in the pod template.", name, ns)
	return newProblem(p, "", "KD321", "Pod's ResourceClaimTemplate does not exist", Critical, cause, "noclaimtpl|"+name, fix, ev...)
}

// source names the object that holds what the claim asks for: the claim, or the template it is still to be made
// from.
func (r podClaimRef) source() kube.Ref {
	if r.claim != nil {
		return r.claim.Ref()
	}
	return r.template.Ref()
}

func (r podClaimRef) allocated() bool {
	return r.claim != nil && r.claim.Status.Allocation != nil
}

func requestsEvidence(r podClaimRef) Evidence {
	src := r.source()
	return Evidence{Object: src, What: fmt.Sprintf("%s %s's device requests", src.Kind, src.Name),
		Command: cmdGet(strings.ToLower(src.Kind), src.Namespace, src.Name, map[string]string{
			"ResourceClaim": `{.spec.devices.requests}`, "ResourceClaimTemplate": `{.spec.spec.devices.requests}`}[src.Kind])}
}

func (ix *index) deviceClass(name string) *kube.DeviceClass {
	for i := range ix.s.DeviceClasses {
		if c := &ix.s.DeviceClasses[i]; c.Metadata.Name == name {
			return c
		}
	}
	return nil
}

// schedulerEvent returns the newest FailedScheduling event of the pod whose message has the text.
func schedulerEvent(ix *index, p kube.Pod, text string) (kube.Event, bool) {
	for _, e := range ix.eventsFor(p.Ref(), "FailedScheduling") {
		if strings.Contains(e.Message, text) {
			return e, true
		}
	}
	return kube.Event{}, false
}

// deviceClassMissing finds a claim with a request whose DeviceClass does not exist (each of its choices, for a
// firstAvailable request). The scheduler cannot pick devices for it, and says so in its event.
func deviceClassMissing(ix *index, p kube.Pod, r podClaimRef) *problem {
	spec := r.spec()
	if spec == nil || r.allocated() || p.Spec.NodeName != "" || !ix.draRead("deviceclasses") {
		return nil
	}
	for _, req := range spec.Devices.Requests {
		var missing []string
		alts := req.Alternatives()
		for _, a := range alts {
			if a.DeviceClassName != "" && ix.deviceClass(a.DeviceClassName) == nil {
				missing = append(missing, a.DeviceClassName)
			}
		}
		if len(missing) == 0 || len(missing) < len(alts) {
			continue
		}
		src := r.source()
		classes := strings.Join(missing, ", ")
		var names []string
		for _, c := range ix.s.DeviceClasses {
			names = append(names, c.Metadata.Name)
		}
		cause := fmt.Sprintf("request %s of %s %s asks for devices of DeviceClass %s, which does not exist, so the scheduler cannot pick devices for it", req.Name, src.Kind, src.Name, classes)
		if len(names) > 0 {
			cause += fmt.Sprintf(" (the cluster's classes: %s)", strings.Join(names, ", "))
		} else {
			cause += "; the cluster has no DeviceClass at all, so no DRA driver is installed"
		}
		ev := []Evidence{requestsEvidence(r)}
		if e, ok := schedulerEvent(ix, p, "does not exist"); ok {
			ev = append(ev, eventEvidence(p.Ref(), e))
		}
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "DeviceClass", Name: missing[0]}, What: "DeviceClasses of the cluster",
			Command: "kubectl get deviceclasses"})
		fix := fmt.Sprintf("Name a DeviceClass the cluster has in request %s of %s %s, or install the DRA driver that provides class %s (a driver's Helm chart usually creates its classes).", req.Name, src.Kind, src.Name, classes)
		return newProblem(p, "", "KD322", "Claim asks for a DeviceClass that does not exist", Critical, cause, "noclass|"+classes, fix, ev...)
	}
	return nil
}

// reDriverSelector matches the usual way a DeviceClass picks its devices: by the driver that publishes them.
var reDriverSelector = regexp.MustCompile(`device\.driver\s*==\s*["']([^"']+)["']`)

// drivers returns the drivers whose devices a request can be given, as its class's selectors (and its own) name
// them; none when they do not say.
func (ix *index) drivers(a kube.ExactDeviceRequest) []string {
	var out []string
	sels := append([]kube.DeviceSelector(nil), a.Selectors...)
	if c := ix.deviceClass(a.DeviceClassName); c != nil {
		sels = append(sels, c.Spec.Selectors...)
	}
	for _, s := range sels {
		if s.CEL == nil {
			continue
		}
		for _, m := range reDriverSelector.FindAllStringSubmatch(s.CEL.Expression, -1) {
			if !slices.Contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// offered counts the devices the drivers publish (any driver's when none is named): in all, and at most on one node.
// A slice for every node, or for the nodes a selector picks, counts toward each node.
func (ix *index) offered(drivers []string) (total, most int) {
	perNode := map[string]int{}
	everywhere := 0
	for _, sl := range ix.s.ResourceSlices {
		if len(drivers) > 0 && !slices.Contains(drivers, sl.Spec.Driver) {
			continue
		}
		n := len(sl.Spec.Devices)
		total += n
		if sl.Spec.NodeName != "" {
			perNode[sl.Spec.NodeName] += n
		} else {
			everywhere += n
		}
	}
	most = everywhere
	for _, n := range perNode {
		most = max(most, n+everywhere)
	}
	return total, most
}

// waitsForDevices reports whether the scheduler has tried the pod and failed: it has a PodScheduled condition
// that is False, or a FailedScheduling event.
func waitsForDevices(ix *index, p kube.Pod) bool {
	if c, ok := kube.FindCondition(p.Status.Conditions, "PodScheduled"); ok && c.Status == "False" && c.Reason != "SchedulingGated" {
		return true
	}
	return len(ix.eventsFor(p.Ref(), "FailedScheduling")) > 0
}

// deviceShortage finds a claim the scheduler cannot allocate because of the devices on offer: none of its class at
// all, when no driver publishes them.
func deviceShortage(ix *index, p kube.Pod, r podClaimRef) *problem {
	spec := r.spec()
	if spec == nil || r.allocated() || p.Spec.NodeName != "" || !waitsForDevices(ix, p) || !ix.draRead("resourceslices") || !ix.draRead("deviceclasses") {
		return nil
	}
	for _, req := range spec.Devices.Requests {
		alts := req.Alternatives()
		if len(alts) != 1 || ix.deviceClass(alts[0].DeviceClassName) == nil {
			continue
		}
		a := alts[0]
		drivers := ix.drivers(a)
		total, _ := ix.offered(drivers)
		src := r.source()
		ev := []Evidence{requestsEvidence(r),
			{Object: kube.Ref{Kind: "DeviceClass", Name: a.DeviceClassName}, What: fmt.Sprintf("DeviceClass %s's selectors", a.DeviceClassName),
				Command: cmdGet("deviceclass", "", a.DeviceClassName, `{.spec.selectors}`)}}
		sliceCmd := "kubectl get resourceslices"
		if len(drivers) == 1 {
			sliceCmd += " --field-selector spec.driver=" + drivers[0]
		}
		if e, ok := schedulerEvent(ix, p, "claim"); ok {
			ev = append(ev, eventEvidence(p.Ref(), e))
		}
		if total == 0 && (len(drivers) > 0 || len(ix.s.ResourceSlices) == 0) {
			who := "no DRA driver publishes any device: the cluster has no ResourceSlices"
			if len(drivers) > 0 && len(ix.s.ResourceSlices) > 0 {
				who = fmt.Sprintf("no ResourceSlice offers a device from driver %s, which the class's selectors pick: the driver is not running, or it has found no device on any node", strings.Join(drivers, ", "))
			}
			cause := fmt.Sprintf("request %s of %s %s asks for devices of DeviceClass %s, and %s, so the scheduler cannot allocate the claim on any node", req.Name, src.Kind, src.Name, a.DeviceClassName, who)
			ev = append(ev, Evidence{Object: kube.Ref{Kind: "ResourceSlice", Name: "*"}, What: "the devices drivers publish", Command: sliceCmd})
			fix := "Install or start the DRA driver for this class (its kubelet plugin runs as a DaemonSet on the nodes with the devices), and check its pods' logs for why it publishes nothing."
			return newProblem(p, "", "KD323", "No driver offers a device of the claimed class", Critical, cause, "nodevices|"+a.DeviceClassName, fix, ev...)
		}
	}
	return nil
}
