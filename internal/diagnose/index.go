package diagnose

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// index answers the lookups the rules make: an object by name, the events about an object, the owner of a pod.
type index struct {
	s          *snapshot.Snapshot
	workloads  map[kube.Ref]*kube.Workload
	jobs       map[kube.Ref]*kube.Job
	events     map[kube.Ref][]kube.Event
	configMaps map[nsName]kube.KeySet
	secrets    map[nsName]kube.KeySet
	sas        map[nsName]bool
	pvcs       map[nsName]*kube.PersistentVolumeClaim
	classes    map[string]*kube.StorageClass
	logs       map[logKey]snapshot.Log
	slices     map[nsName][]kube.EndpointSlice
	gaps       map[string]bool
}

type nsName struct{ ns, name string }

type logKey struct {
	ns, pod, container string
}

func newIndex(s *snapshot.Snapshot) *index {
	ix := &index{
		s: s, workloads: map[kube.Ref]*kube.Workload{}, jobs: map[kube.Ref]*kube.Job{}, events: map[kube.Ref][]kube.Event{},
		configMaps: map[nsName]kube.KeySet{}, secrets: map[nsName]kube.KeySet{}, sas: map[nsName]bool{},
		pvcs: map[nsName]*kube.PersistentVolumeClaim{}, classes: map[string]*kube.StorageClass{},
		logs: map[logKey]snapshot.Log{}, slices: map[nsName][]kube.EndpointSlice{}, gaps: map[string]bool{},
	}
	for i := range s.Workloads {
		ix.workloads[s.Workloads[i].Ref()] = &s.Workloads[i]
	}
	for i := range s.Jobs {
		ix.jobs[s.Jobs[i].Ref()] = &s.Jobs[i]
	}
	for _, e := range s.Events {
		r := kube.Ref{Kind: e.InvolvedObject.Kind, Namespace: e.InvolvedObject.Namespace, Name: e.InvolvedObject.Name}
		ix.events[r] = append(ix.events[r], e)
	}
	for r := range ix.events {
		evs := ix.events[r]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Last().After(evs[j].Last()) }) // newest first
	}
	for _, c := range s.ConfigMaps {
		ix.configMaps[nsName{c.Namespace, c.Name}] = c
	}
	for _, c := range s.Secrets {
		ix.secrets[nsName{c.Namespace, c.Name}] = c
	}
	for _, sa := range s.ServiceAccounts {
		ix.sas[nsName{sa.Metadata.Namespace, sa.Metadata.Name}] = true
	}
	for i := range s.PVCs {
		ix.pvcs[nsName{s.PVCs[i].Metadata.Namespace, s.PVCs[i].Metadata.Name}] = &s.PVCs[i]
	}
	for i := range s.StorageClasses {
		ix.classes[s.StorageClasses[i].Metadata.Name] = &s.StorageClasses[i]
	}
	for _, l := range s.Logs {
		if len(l.Lines) > 0 && strings.HasPrefix(l.Lines[0], "unable to retrieve container logs") {
			continue // the kubelet's note that the log is gone, not something the app printed
		}
		k := logKey{l.Pod.Namespace, l.Pod.Name, l.Container}
		if old, ok := ix.logs[k]; !ok || (l.Previous && !old.Previous) {
			ix.logs[k] = l
		}
	}
	for _, e := range s.EndpointSlices {
		k := nsName{e.Metadata.Namespace, e.ServiceName()}
		ix.slices[k] = append(ix.slices[k], e)
	}
	for _, g := range s.Gaps {
		ix.gaps[g.Resource] = true
	}
	return ix
}

// read reports whether the collector could read the resource; a rule that relies on the absence of an object must
// not fire when the list was never read.
func (ix *index) read(resource string) bool { return !ix.gaps[resource] }

// eventsFor returns the events about an object, newest first, optionally only those with one of the reasons.
func (ix *index) eventsFor(r kube.Ref, reasons ...string) []kube.Event {
	evs := ix.events[r]
	if len(reasons) == 0 {
		return evs
	}
	var out []kube.Event
	for _, e := range evs {
		for _, reason := range reasons {
			if e.Reason == reason {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// owner walks a pod's controller chain to the object a person edits: ReplicaSet to Deployment, Job to CronJob. A
// bare pod is its own owner.
func (ix *index) owner(p kube.Pod) kube.Ref {
	o, ok := p.Metadata.Controller()
	if !ok {
		return p.Ref()
	}
	ref := kube.Ref{Kind: o.Kind, Namespace: p.Metadata.Namespace, Name: o.Name}
	if o.Kind == "Job" {
		if j, ok := ix.jobs[ref]; ok {
			if c, ok := j.Metadata.Controller(); ok && c.Kind == "CronJob" {
				return kube.Ref{Kind: "CronJob", Namespace: p.Metadata.Namespace, Name: c.Name}
			}
		}
	}
	if o.Kind == "ReplicaSet" {
		if rs, ok := ix.workloads[ref]; ok {
			if d, ok := rs.Metadata.Controller(); ok && d.Kind == "Deployment" {
				return kube.Ref{Kind: "Deployment", Namespace: p.Metadata.Namespace, Name: d.Name}
			}
		}
	}
	return ref
}

// containerSpec finds a container or init container by name.
func containerSpec(p kube.Pod, name string) (kube.Container, bool) {
	for _, c := range append(append([]kube.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
		if c.Name == name {
			return c, true
		}
	}
	return kube.Container{}, false
}

func isInit(p kube.Pod, name string) bool {
	for _, c := range p.Spec.InitContainers {
		if c.Name == name {
			return true
		}
	}
	return false
}

// isSidecar reports whether the container is a sidecar: an init container with restartPolicy Always, which starts
// before the app containers and keeps running beside them instead of finishing.
func isSidecar(p kube.Pod, name string) bool {
	for _, c := range p.Spec.InitContainers {
		if c.Name == name {
			return c.RestartPolicy == "Always"
		}
	}
	return false
}

// ---- kubectl commands that show each kind of evidence ----

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func nsFlag(ns string) string {
	if ns == "" {
		return ""
	}
	return " -n " + ns
}

func cmdEvents(r kube.Ref) string {
	return fmt.Sprintf("kubectl get events%s --field-selector involvedObject.kind=%s,involvedObject.name=%s", nsFlag(r.Namespace), r.Kind, r.Name)
}

func cmdContainerState(p kube.Pod, container, field string) string {
	list := "containerStatuses"
	if isInit(p, container) {
		list = "initContainerStatuses"
	}
	return fmt.Sprintf("kubectl get pod %s -n %s -o jsonpath=%s", p.Metadata.Name, p.Metadata.Namespace,
		shq(fmt.Sprintf(`{.status.%s[?(@.name=="%s")].%s}`, list, container, field)))
}

func cmdLogs(p kube.Pod, container string, previous bool) string {
	c := fmt.Sprintf("kubectl logs %s -n %s -c %s --tail=20", p.Metadata.Name, p.Metadata.Namespace, container)
	if previous {
		c += " --previous"
	}
	return c
}

func cmdGet(kind, ns, name, jsonpath string) string {
	c := fmt.Sprintf("kubectl get %s %s%s", strings.ToLower(kind), name, nsFlag(ns))
	if jsonpath != "" {
		c += " -o jsonpath=" + shq(jsonpath)
	}
	return c
}
