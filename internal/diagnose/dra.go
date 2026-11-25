package diagnose

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

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
		if pr := claimDeleting(ix, p, r); pr != nil {
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
	return driverNotRegistered(ix, p, refs)
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
		total, most := ix.offered(drivers)
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
		count := max(a.Count, 1)
		if a.AllocationMode != "All" && total > 0 && count > int64(most) {
			from := "drivers publish"
			if len(drivers) > 0 {
				from = "driver " + strings.Join(drivers, ", ") + " publishes"
			}
			cause := fmt.Sprintf("request %s of %s %s asks for %d devices of DeviceClass %s, and no node has that many: the most %s on one node is %d (%d in all), and a claim's devices must all be usable on the node the pod runs on",
				req.Name, src.Kind, src.Name, count, a.DeviceClassName, from, most, total)
			ev = append(ev, Evidence{Object: kube.Ref{Kind: "ResourceSlice", Name: "*"}, What: fmt.Sprintf("%d devices in all, at most %d on one node", total, most), Command: sliceCmd})
			fix := fmt.Sprintf("Ask for at most %d devices in request %s, or split the work over more pods that each claim fewer devices.", most, req.Name)
			return newProblem(p, "", "KD324", "Claim asks for more devices than any node has", Critical, cause, "toomany|"+a.DeviceClassName, fix, ev...)
		}
		e, failed := schedulerEvent(ix, p, "cannot allocate all claims")
		if holders := ix.deviceHolders(drivers, r.claim); failed && total > 0 && total-len(holders) < int(count) {
			names := make([]string, 0, len(holders))
			for _, h := range holders {
				if !slices.Contains(names, h) {
					names = append(names, h)
				}
			}
			cause := fmt.Sprintf("request %s of %s %s asks for %d %s of DeviceClass %s, and %d of the %d on offer are allocated to other claims (%s), so the scheduler cannot allocate it until they are released",
				req.Name, src.Kind, src.Name, count, map[bool]string{true: "device", false: "devices"}[count == 1], a.DeviceClassName, len(holders), total, strings.Join(names, ", "))
			ev = append(ev, Evidence{Object: kube.Ref{Kind: "ResourceClaim", Namespace: p.Metadata.Namespace, Name: "*"}, What: "the claims and the devices allocated to them",
				Command: "kubectl get resourceclaims -A -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,DEVICES:.status.allocation.devices.results[*].device,USERS:.status.reservedFor[*].name"})
			fix := "Wait for the pods holding the devices to finish (a claim made from a template is released with its pod), delete a claim nothing needs any more (an allocated claim keeps its devices while it exists), or add capacity."
			return newProblem(p, "", "KD327", "Every device of the class is allocated to other claims", Warning, cause, "inuse|"+a.DeviceClassName, fix, ev...)
		}
		filters := ix.attributeSelectors(a)
		if total > 0 && len(filters) > 0 && failed && total-len(ix.deviceHolders(drivers, r.claim)) >= int(count) {
			cause := fmt.Sprintf("request %s of %s %s asks for devices of DeviceClass %s that satisfy the selector %s, and the scheduler finds none it can allocate among the %d devices on offer, most of them free: the selectors match no device the driver publishes (an attribute name or value that differs, or a domain the attribute is not under)",
				req.Name, src.Kind, src.Name, a.DeviceClassName, quoteAll(filters), total)
			ev = append(ev[:len(ev)-1], eventEvidence(p.Ref(), e), Evidence{Object: kube.Ref{Kind: "ResourceSlice", Name: "*"},
				What: "the devices on offer and their attributes", Command: sliceCmd + " -o yaml"})
			fix := "Compare the selectors with the attributes in the driver's ResourceSlices (kubectl get resourceslices -o yaml) and correct the expression; a driver's attributes are under its own domain, as device.attributes[\"<driver>\"].<name>."
			return newProblem(p, "", "KD325", "Claim's selectors match no device on offer", Critical, cause, "noselected|"+a.DeviceClassName, fix, ev...)
		}
	}
	return nil
}

var reDriverOnly = regexp.MustCompile(`^\s*device\.driver\s*==\s*["'][^"']+["']\s*$`)

// attributeSelectors returns the request's and its class's CEL expressions that pick devices by more than their
// driver.
func (ix *index) attributeSelectors(a kube.ExactDeviceRequest) []string {
	sels := append([]kube.DeviceSelector(nil), a.Selectors...)
	if c := ix.deviceClass(a.DeviceClassName); c != nil {
		sels = append(sels, c.Spec.Selectors...)
	}
	var out []string
	for _, s := range sels {
		if s.CEL != nil && !reDriverOnly.MatchString(s.CEL.Expression) {
			out = append(out, strings.TrimSpace(s.CEL.Expression))
		}
	}
	return out
}

func quoteAll(l []string) string {
	return strings.Join(l, " and the selector ")
}

var reDriverNotRegistered = regexp.MustCompile(`DRA driver (\S+) is not registered`)

// driverNotRegistered finds a pod placed on a node, its devices allocated, whose containers cannot start because
// the node's kubelet has no plugin for the driver of those devices: the driver's ResourceSlices say it has devices
// there, but its kubelet plugin is not running on the node (or never registered), so nothing prepares them.
func driverNotRegistered(ix *index, p kube.Pod, refs []podClaimRef) *problem {
	if p.Spec.NodeName == "" {
		return nil
	}
	for _, e := range ix.eventsFor(p.Ref(), "FailedPrepareDynamicResources") {
		m := reDriverNotRegistered.FindStringSubmatch(e.Message)
		if m == nil {
			continue
		}
		driver := m[1]
		var claims []string
		var ev []Evidence
		for _, r := range refs {
			if !r.allocated() {
				continue
			}
			for _, res := range r.claim.Status.Allocation.Devices.Results {
				if res.Driver == driver {
					claims = append(claims, r.claim.Metadata.Name)
					ev = append(ev, Evidence{Object: r.claim.Ref(), What: fmt.Sprintf("ResourceClaim %s is allocated device %s of pool %s from driver %s", r.claim.Metadata.Name, res.Device, res.Pool, driver),
						Command: cmdGet("resourceclaim", r.claim.Metadata.Namespace, r.claim.Metadata.Name, `{.status.allocation.devices.results}`)})
					break
				}
			}
		}
		node := p.Spec.NodeName
		cause := fmt.Sprintf("the pod is on node %s with its devices allocated, but the node's kubelet has no plugin for DRA driver %s, so it cannot prepare them and the containers never start", node, driver)
		if len(claims) > 0 {
			cause = fmt.Sprintf("the pod is on node %s and ResourceClaim %s is allocated devices from DRA driver %s, but the node's kubelet has no plugin for that driver registered, so it cannot prepare them and the containers never start", node, strings.Join(claims, ", "), driver)
		}
		ev = append([]Evidence{eventEvidence(p.Ref(), e)}, ev...)
		ev = append(ev, Evidence{Object: kube.Ref{Kind: "ResourceSlice", Name: "*"}, What: fmt.Sprintf("driver %s's slices, which offered the devices", driver),
			Command: "kubectl get resourceslices --field-selector spec.driver=" + driver})
		fix := fmt.Sprintf("Run driver %s's kubelet plugin on node %s (it is usually a DaemonSet: check that it has a pod there, and its logs for why it did not register). A ResourceSlice that offers devices on nodes without the plugin (allNodes, or a node selector) lets the scheduler place pods where nothing can prepare them.", driver, node)
		return newProblem(p, "", "KD326", "Node's kubelet has no plugin for the claim's driver", Critical, cause, "notregistered|"+driver, fix, ev...)
	}
	return nil
}

// deviceHolders returns, for each device of the drivers that a claim other than this one holds, that claim's name.
func (ix *index) deviceHolders(drivers []string, self *kube.ResourceClaim) []string {
	var out []string
	for i := range ix.s.ResourceClaims {
		c := &ix.s.ResourceClaims[i]
		if c == self || c.Status.Allocation == nil {
			continue
		}
		for _, res := range c.Status.Allocation.Devices.Results {
			if len(drivers) == 0 || slices.Contains(drivers, res.Driver) {
				out = append(out, c.Metadata.Namespace+"/"+c.Metadata.Name)
			}
		}
	}
	return out
}

// claimDeleting finds a pod that is not yet placed and uses a ResourceClaim that is being deleted: the scheduler
// leaves it out of its queue, as for a claim that does not exist, and the claim stays until the pods it is reserved
// for release it.
func claimDeleting(ix *index, p kube.Pod, r podClaimRef) *problem {
	if r.claim == nil || r.claim.Metadata.DeletionTimestamp == nil || p.Spec.NodeName != "" {
		return nil
	}
	c := r.claim
	ns, name := c.Metadata.Namespace, c.Metadata.Name
	var users []string
	for _, u := range c.Status.ReservedFor {
		if u.Name != p.Metadata.Name {
			users = append(users, u.Name)
		}
	}
	ago := ix.s.CollectedAt.Sub(*c.Metadata.DeletionTimestamp).Round(time.Minute)
	cause := fmt.Sprintf("the pod uses ResourceClaim %s, which was deleted %s ago: the scheduler does not try a pod whose claim is being deleted, so the pod waits with no event", name, ago)
	if len(users) > 0 {
		cause += fmt.Sprintf("; the claim stays until %s, which it is reserved for, %s", strings.Join(users, ", "), map[bool]string{true: "stops", false: "stop"}[len(users) == 1])
	}
	fix := fmt.Sprintf("Create a new claim for the pod (a ResourceClaimTemplate gives each pod its own) once %s is gone, or recreate the pod after it is: a deleted claim cannot be taken back.", name)
	return newProblem(p, "", "KD328", "Pod's ResourceClaim is being deleted", Critical, cause, "claimdeleting|"+name, fix,
		Evidence{Object: c.Ref(), What: fmt.Sprintf("ResourceClaim %s has a deletionTimestamp (%s) and finalizers %s", name, c.Metadata.DeletionTimestamp.UTC().Format(time.RFC3339), strings.Join(c.Metadata.Finalizers, ", ")),
			Command: cmdGet("resourceclaim", ns, name, `{.metadata.deletionTimestamp}{" "}{.metadata.finalizers}{" "}{.status.reservedFor}`)})
}
