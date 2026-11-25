package diagnose

import (
	"fmt"

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
