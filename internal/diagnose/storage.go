package diagnose

import (
	"fmt"
	"regexp"
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
	if pvc.Spec.VolumeName != "" {
		if f := namedVolume(ix, pvc, state); f != nil {
			return f
		}
	}
	switch {
	case pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != "":
		class := *pvc.Spec.StorageClassName
		sc, ok := ix.classes[class]
		if !ok && classesKnown && !pvOfClass(ix, class) {
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
	for _, e := range evs {
		if e.Reason != "ProvisioningFailed" || !reAccessMode.MatchString(e.Message) {
			continue
		}
		class := "its StorageClass"
		if pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != "" {
			class = "StorageClass " + *pvc.Spec.StorageClassName
		} else if d := defaultClass(ix); d != "" {
			class = "the default StorageClass " + d
		}
		modes := strings.Join(pvc.Spec.AccessModes, ", ")
		return &Finding{Rule: "KD156", Title: "StorageClass cannot provide the access mode", Severity: Critical, Object: ref,
			Cause:    fmt.Sprintf("PersistentVolumeClaim %s asks for access mode %s, which the provisioner of %s cannot provide: %s", name, modes, class, clip(e.Message, 200)),
			Evidence: []Evidence{state, {Object: ref, What: "claim asks for access modes " + modes, Command: cmdGet("pvc", ns, name, "{.spec.accessModes}")}, eventEvidence(ref, e)},
			Fix:      "Ask for an access mode the class supports (usually ReadWriteOnce), or use a StorageClass whose storage can be shared (NFS, CephFS, a cloud file store) for ReadWriteMany. A claim's access modes cannot be changed: recreate it."}
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

var reAccessMode = regexp.MustCompile(`(?i)access ?modes?\b|ReadWriteMany|ReadOnlyMany|ReadWriteOncePod`)

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

// pvOfClass reports whether a PersistentVolume carries the class name: static volumes may use a class name that no
// StorageClass object has, as a label that pairs them with their claims.
func pvOfClass(ix *index, class string) bool {
	for _, pv := range ix.s.PVs {
		if pv.Spec.StorageClassName == class {
			return true
		}
	}
	return false
}

// namedVolume explains a pending claim that names its PersistentVolume (spec.volumeName) and cannot bind to it. The
// PersistentVolume controller writes no event for most of these: the claim just stays Pending.
func namedVolume(ix *index, pvc kube.PersistentVolumeClaim, state Evidence) *Finding {
	if !ix.read("persistentvolumes") {
		return nil
	}
	ns, name, vol := pvc.Metadata.Namespace, pvc.Metadata.Name, pvc.Spec.VolumeName
	var pv *kube.PersistentVolume
	for i := range ix.s.PVs {
		if ix.s.PVs[i].Metadata.Name == vol {
			pv = &ix.s.PVs[i]
		}
	}
	f := &Finding{Rule: "KD157", Title: "Claim names a volume it cannot bind to", Severity: Critical, Object: pvc.Ref(),
		Evidence: []Evidence{state, {Object: pvc.Ref(), What: "claim names PersistentVolume " + vol, Command: cmdGet("pvc", ns, name, "{.spec.volumeName}")}}}
	pvEv := func(what, path string) Evidence {
		return Evidence{Object: kube.Ref{Kind: "PersistentVolume", Name: vol}, What: what, Command: cmdGet("pv", "", vol, path)}
	}
	if pv == nil {
		f.Cause = fmt.Sprintf("PersistentVolumeClaim %s names PersistentVolume %s, which does not exist, so it waits for it", name, vol)
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "PersistentVolume", Name: vol}, What: "there is no PersistentVolume " + vol, Command: "kubectl get pv"})
		f.Fix = fmt.Sprintf("Create PersistentVolume %s, or recreate the claim without volumeName so its StorageClass provisions one.", vol)
		return f
	}
	cr := pv.Spec.ClaimRef
	switch {
	case cr != nil && (cr.Namespace != ns || cr.Name != name):
		f.Cause = fmt.Sprintf("PersistentVolumeClaim %s names PersistentVolume %s, which is reserved for claim %s/%s (%s), so it cannot bind", name, vol, cr.Namespace, cr.Name, pv.Status.Phase)
		f.Evidence = append(f.Evidence, pvEv(fmt.Sprintf("PersistentVolume %s is %s with claimRef %s/%s", vol, pv.Status.Phase, cr.Namespace, cr.Name), "{.status.phase} {.spec.claimRef}"))
		f.Fix = fmt.Sprintf("If %s/%s is gone and its data is meant for this claim, clear the volume's claimRef (kubectl patch pv %s --type=json -p '[{\"op\":\"remove\",\"path\":\"/spec/claimRef\"}]'); otherwise point the claim at a free volume.", cr.Namespace, cr.Name, vol)
	case cr != nil && pv.Status.Phase == "Released" && cr.UID != "" && cr.UID != pvc.Metadata.UID:
		f.Cause = fmt.Sprintf("PersistentVolumeClaim %s names PersistentVolume %s, which is Released: it still holds the UID of the deleted claim of the same name, so the new claim cannot bind", name, vol)
		f.Evidence = append(f.Evidence, pvEv(fmt.Sprintf("PersistentVolume %s is Released, its claimRef UID %s is not the claim's", vol, cr.UID), "{.status.phase} {.spec.claimRef.uid}"))
		f.Fix = fmt.Sprintf("Remove the old UID so the volume binds to the new claim, keeping its data: kubectl patch pv %s --type=json -p '[{\"op\":\"remove\",\"path\":\"/spec/claimRef/uid\"}]'.", vol)
	case pvc.Spec.StorageClassName != nil && *pvc.Spec.StorageClassName != pv.Spec.StorageClassName:
		f.Cause = fmt.Sprintf("PersistentVolumeClaim %s names PersistentVolume %s, but asks for StorageClass %q and the volume has %q, so it cannot bind", name, vol, *pvc.Spec.StorageClassName, pv.Spec.StorageClassName)
		f.Evidence = append(f.Evidence, pvEv("PersistentVolume's storageClassName is "+fmt.Sprintf("%q", pv.Spec.StorageClassName), "{.spec.storageClassName}"))
		f.Fix = "Give the claim the volume's storageClassName (an empty string for none). A claim's class cannot be changed: recreate it."
	default:
		if want, have := pvc.Spec.Resources.Requests["storage"], pv.Spec.Capacity["storage"]; want != "" && have != "" {
			w, errw := kube.ParseQuantity(want)
			h, errh := kube.ParseQuantity(have)
			if errw == nil && errh == nil && h < w {
				f.Cause = fmt.Sprintf("PersistentVolumeClaim %s names PersistentVolume %s, which holds %s, less than the %s the claim asks for, so it cannot bind", name, vol, have, want)
				f.Evidence = append(f.Evidence, pvEv("PersistentVolume's capacity is "+have, "{.spec.capacity.storage}"))
				f.Fix = fmt.Sprintf("Ask for at most %s in the claim, or point it at a larger volume.", have)
				return f
			}
		}
		return nil
	}
	return f
}
