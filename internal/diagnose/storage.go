package diagnose

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// storageFindings checks claims that are not bound: a StorageClass that does not exist, no default class, or a
// provisioner that fails or never answers.
func storageFindings(ix *index) []Finding {
	var out []Finding
	for _, pvc := range ix.s.PVCs {
		if pvc.Status.Phase != "Pending" {
			continue
		}
		if f := pendingClaim(ix, pvc); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func pendingClaim(ix *index, pvc kube.PersistentVolumeClaim) *Finding {
	ns, name := pvc.Metadata.Namespace, pvc.Metadata.Name
	ref := pvc.Ref()
	state := Evidence{Object: ref, What: "PersistentVolumeClaim is Pending", Command: cmdGet("pvc", ns, name, "{.status.phase}")}
	classesKnown := ix.read("storageclasses.storage.k8s.io")
	switch {
	case pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != "":
		class := *pvc.Spec.StorageClassName
		sc, ok := ix.classes[class]
		if !ok && classesKnown {
			names := classNames(ix)
			have := "there are no StorageClasses"
			if len(names) > 0 {
				have = "the cluster has " + strings.Join(names, ", ")
			}
			return &Finding{Rule: "KD150", Title: "StorageClass does not exist", Severity: Critical, Object: ref,
				Cause: fmt.Sprintf("PersistentVolumeClaim %s asks for StorageClass %s, which does not exist (%s)", name, class, have),
				Evidence: []Evidence{state,
					{Object: ref, What: "claim asks for storageClassName " + class, Command: cmdGet("pvc", ns, name, "{.spec.storageClassName}")},
					{Object: kube.Ref{Kind: "StorageClass", Name: class}, What: "no StorageClass is named " + class + "; " + have,
						Command: "kubectl get storageclasses"}},
				Fix: "Set storageClassName to a class that exists, or create StorageClass " + class + ". A claim's class cannot be changed: recreate the claim."}
		}
		if ok && sc.VolumeBindingMode == "WaitForFirstConsumer" && !claimUsed(ix, pvc) {
			return nil // binds when a pod uses it; nothing is wrong yet
		}
	case pvc.Spec.StorageClassName == nil && classesKnown && defaultClass(ix) == "":
		names := classNames(ix)
		have := "there are no StorageClasses"
		if len(names) > 0 {
			have = "the cluster has " + strings.Join(names, ", ") + ", none marked default"
		}
		if staticMatch(ix, pvc) {
			return nil
		}
		return &Finding{Rule: "KD151", Title: "No default StorageClass", Severity: Critical, Object: ref,
			Cause:    fmt.Sprintf("PersistentVolumeClaim %s names no StorageClass and the cluster has no default one, so nothing provisions a volume (%s)", name, have),
			Evidence: []Evidence{state, {Object: kube.Ref{Kind: "StorageClass", Name: "*"}, What: have, Command: "kubectl get storageclasses"}},
			Fix:      "Set storageClassName on the claim, or mark a StorageClass as default (annotation storageclass.kubernetes.io/is-default-class=true)."}
	}
	evs := ix.eventsFor(ref, "ProvisioningFailed", "ExternalProvisioning", "FailedBinding")
	if len(evs) == 0 {
		return nil
	}
	e := evs[0]
	cause := fmt.Sprintf("PersistentVolumeClaim %s is not bound: %s", name, e.Message)
	if e.Reason == "ExternalProvisioning" {
		cause = fmt.Sprintf("PersistentVolumeClaim %s waits for its provisioner to create a volume, and none has been created", name)
	}
	return &Finding{Rule: "KD152", Title: "Volume is not provisioned", Severity: Critical, Object: ref, Cause: cause,
		Evidence: []Evidence{state, eventEvidence(ref, e)},
		Fix:      "Check that the StorageClass's provisioner runs in the cluster and read its logs; for static volumes, create a PersistentVolume that matches the claim."}
}

func classNames(ix *index) []string {
	var out []string
	for _, c := range ix.s.StorageClasses {
		n := c.Metadata.Name
		if c.IsDefault() {
			n += " (default)"
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func defaultClass(ix *index) string {
	for _, c := range ix.s.StorageClasses {
		if c.IsDefault() {
			return c.Metadata.Name
		}
	}
	return ""
}

func claimUsed(ix *index, pvc kube.PersistentVolumeClaim) bool {
	for _, p := range ix.s.Pods {
		if p.Metadata.Namespace != pvc.Metadata.Namespace {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == pvc.Metadata.Name {
				return true
			}
		}
	}
	return false
}

// staticMatch reports whether an Available PersistentVolume without a class could bind the claim.
func staticMatch(ix *index, pvc kube.PersistentVolumeClaim) bool {
	for _, pv := range ix.s.PVs {
		if pv.Status.Phase == "Available" && pv.Spec.StorageClassName == "" {
			return true
		}
	}
	return false
}
