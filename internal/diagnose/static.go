package diagnose

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// staticClass is the class name a claim's volume must carry when only an existing PersistentVolume can satisfy the
// claim: storageClassName "" (which turns dynamic provisioning off), or a name no StorageClass has while
// PersistentVolumes carry it, the usual way to pair hand-made volumes with their claims.
func staticClass(ix *index, pvc kube.PersistentVolumeClaim) (string, bool) {
	if pvc.Spec.StorageClassName == nil || !ix.read("persistentvolumes") {
		return "", false
	}
	class := *pvc.Spec.StorageClassName
	if class == "" {
		return "", true
	}
	if _, ok := ix.classes[class]; ok || !ix.read("storageclasses.storage.k8s.io") || !pvOfClass(ix, class) {
		return "", false
	}
	return class, true
}

func volumeModeOf(m string) string {
	if m == "" {
		return "Filesystem"
	}
	return m
}

// misfits lists why a PersistentVolume cannot bind a claim, and whether the only reason is that it is Released.
func misfits(pvc kube.PersistentVolumeClaim, pv kube.PersistentVolume) (why []string, releasedOnly bool) {
	if want, have := pvc.Spec.Resources.Requests["storage"], pv.Spec.Capacity["storage"]; want != "" && have != "" {
		w, errw := kube.ParseQuantity(want)
		h, errh := kube.ParseQuantity(have)
		if errw == nil && errh == nil && h < w {
			why = append(why, fmt.Sprintf("holds %s, less than the %s the claim asks for", have, want))
		}
	}
	var lacking []string
	for _, m := range pvc.Spec.AccessModes {
		found := false
		for _, have := range pv.Spec.AccessModes {
			found = found || have == m
		}
		if !found {
			lacking = append(lacking, m)
		}
	}
	if len(lacking) > 0 {
		why = append(why, fmt.Sprintf("offers access mode %s, not the %s the claim asks for", strings.Join(pv.Spec.AccessModes, ", "), strings.Join(lacking, ", ")))
	}
	if a, b := volumeModeOf(pvc.Spec.VolumeMode), volumeModeOf(pv.Spec.VolumeMode); a != b {
		why = append(why, fmt.Sprintf("has volumeMode %s, and the claim asks for %s", b, a))
	}
	if sel := pvc.Spec.Selector; sel != nil && !sel.Matches(pv.Metadata.Labels) {
		have := "no labels"
		if len(pv.Metadata.Labels) > 0 {
			have = "labels " + kube.FormatMap(pv.Metadata.Labels)
		}
		why = append(why, fmt.Sprintf("has %s, which the claim's selector (%s) does not match", have, selectorString(*sel)))
	}
	cr := pv.Spec.ClaimRef
	taken := cr != nil && (cr.Namespace != pvc.Metadata.Namespace || cr.Name != pvc.Metadata.Name || (cr.UID != "" && cr.UID != pvc.Metadata.UID))
	switch {
	case pv.Status.Phase == "Released" && cr != nil:
		releasedOnly = len(why) == 0
		why = append(why, fmt.Sprintf("is Released: it still carries the reference to its deleted claim %s/%s", cr.Namespace, cr.Name))
	case pv.Status.Phase == "Bound" && taken:
		why = append(why, fmt.Sprintf("is bound to claim %s/%s", cr.Namespace, cr.Name))
	case pv.Status.Phase == "Bound" && cr == nil:
		why = append(why, "is bound to another claim")
	case taken:
		why = append(why, fmt.Sprintf("is reserved for claim %s/%s", cr.Namespace, cr.Name))
	case pv.Status.Phase == "Failed":
		why = append(why, "is in phase Failed")
	}
	return why, releasedOnly
}

// noVolumeFits explains a pending claim that only an existing PersistentVolume can satisfy when none can: the
// nearest volume is too small, offers other access modes, has another volume mode or other labels, is taken, or is
// Released. The controller says only "no persistent volumes available for this claim", or, for a class name with
// no StorageClass, that the StorageClass is not found. static is false when the claim is provisioned dynamically.
func noVolumeFits(ix *index, pvc kube.PersistentVolumeClaim, state Evidence) (f *Finding, static bool) {
	class, static := staticClass(ix, pvc)
	if !static {
		return nil, false
	}
	ns, name := pvc.Metadata.Namespace, pvc.Metadata.Name
	asks := []string{}
	if q := pvc.Spec.Resources.Requests["storage"]; q != "" {
		asks = append(asks, q)
	}
	if len(pvc.Spec.AccessModes) > 0 {
		asks = append(asks, strings.Join(pvc.Spec.AccessModes, ", "))
	}
	classText := `storageClassName "", which turns dynamic provisioning off`
	ofClass := "without a class"
	if class != "" {
		classText = fmt.Sprintf("storageClassName %q, a name no StorageClass has", class)
		ofClass = "of class " + class
	}
	asks = append(asks, classText)
	type candidate struct {
		pv       kube.PersistentVolume
		why      []string
		released bool
	}
	var cands []candidate
	for _, pv := range ix.s.PVs {
		if pv.Spec.StorageClassName != class {
			continue
		}
		why, released := misfits(pvc, pv)
		if len(why) == 0 {
			return nil, true // a volume fits: the claim is binding
		}
		cands = append(cands, candidate{pv, why, released})
	}
	claimEv := Evidence{Object: pvc.Ref(), What: "claim asks for " + strings.Join(asks, "; "),
		Command: cmdGet("pvc", ns, name, `{.spec.resources.requests.storage}{" "}{.spec.accessModes}{" "}{.spec.storageClassName}{" "}{.spec.volumeMode}{" "}{.spec.selector}`)}
	f = &Finding{Rule: "KD250", Title: "No PersistentVolume fits the claim", Severity: Critical, Object: pvc.Ref(), Evidence: []Evidence{state, claimEv}}
	if len(cands) == 0 {
		f.Cause = fmt.Sprintf("PersistentVolumeClaim %s stays Pending: it asks for %s, so only an existing PersistentVolume can satisfy it, and there is no PersistentVolume %s", name, classText, ofClass)
		f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "PersistentVolume", Name: "*"}, What: "no PersistentVolume is " + ofClass, Command: "kubectl get pv"})
		f.Fix = fmt.Sprintf("Create a PersistentVolume %s that fits the claim, or recreate the claim with a StorageClass that provisions volumes (leave storageClassName out to use the default class).", ofClass)
		return f, true
	}
	// The nearest volume is the one with the fewest reasons against it; a free volume before a taken one.
	sort.SliceStable(cands, func(i, j int) bool {
		if len(cands[i].why) != len(cands[j].why) {
			return len(cands[i].why) < len(cands[j].why)
		}
		if cands[i].released != cands[j].released {
			return cands[i].released // a volume that fits but for its old reference is the one to act on
		}
		return cands[i].pv.Metadata.Name < cands[j].pv.Metadata.Name
	})
	near := cands[0]
	vol := near.pv.Metadata.Name
	others := ""
	if n := len(cands) - 1; n == 1 {
		others = fmt.Sprintf("; the other volume %s, %s, does not fit either", ofClass, cands[1].pv.Metadata.Name)
	} else if n > 1 {
		others = fmt.Sprintf("; the %d other volumes %s do not fit either", n, ofClass)
	}
	f.Evidence = append(f.Evidence, Evidence{Object: kube.Ref{Kind: "PersistentVolume", Name: vol},
		What:    fmt.Sprintf("PersistentVolume %s %s", vol, strings.Join(near.why, ", and ")),
		Command: cmdGet("pv", "", vol, `{.status.phase}{" "}{.spec.capacity.storage}{" "}{.spec.accessModes}{" "}{.spec.volumeMode}{" "}{.spec.claimRef.namespace}{"/"}{.spec.claimRef.name}`)})
	if near.released {
		cr := near.pv.Spec.ClaimRef
		policy := near.pv.Spec.PersistentVolumeReclaimPolicy
		if policy == "" {
			policy = "Retain"
		}
		f.Rule, f.Title = "KD251", "PersistentVolume is Released and does not bind again"
		f.Cause = fmt.Sprintf("PersistentVolumeClaim %s stays Pending: PersistentVolume %s fits it, but is Released: it still carries the reference to claim %s/%s, which was deleted, and a Released volume is bound to no other claim until that reference is cleared (reclaim policy %s keeps the volume and its data for that decision)%s",
			name, vol, cr.Namespace, cr.Name, policy, others)
		f.Fix = fmt.Sprintf("If the data on %s may go to the new claim, or does not matter, clear the reference so that the volume is Available again: kubectl patch pv %s --type=json -p '[{\"op\":\"remove\",\"path\":\"/spec/claimRef\"}]'. Otherwise create a new PersistentVolume for the claim.", vol, vol)
		return f, true
	}
	f.Cause = fmt.Sprintf("PersistentVolumeClaim %s stays Pending: it asks for %s, so only an existing PersistentVolume can satisfy it, and none fits: the nearest, %s, %s%s",
		name, strings.Join(asks, "; "), vol, strings.Join(near.why, ", and "), others)
	f.Fix = "Recreate the claim so that it fits an existing volume (a claim's size, access modes and class cannot be edited), or create a PersistentVolume that fits the claim: at least its size, every access mode it asks for, the same volumeMode and storageClassName, and not bound or reserved."
	return f, true
}
