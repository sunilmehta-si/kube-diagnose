package diagnose

import (
	"strings"
	"testing"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

func cronJob(name, policy string) kube.CronJob {
	var cj kube.CronJob
	cj.Metadata = kube.ObjectMeta{Name: name, Namespace: "shop", CreationTimestamp: t0.Add(-24 * time.Hour)}
	cj.Spec.Schedule, cj.Spec.ConcurrencyPolicy = "*/5 * * * *", policy
	return cj
}

func TestCronJobSkipsRunsWhileOneIsRunning(t *testing.T) {
	s := snap()
	cj := cronJob("report", "Forbid")
	cj.Status.Active = append(cj.Status.Active, struct {
		Name string `json:"name"`
	}{Name: "report-29001"})
	s.CronJobs = []kube.CronJob{cj}
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "report-29001", Namespace: "shop", OwnerReferences: []kube.OwnerReference{{Kind: "CronJob", Name: "report", Controller: yes()}}}
	start := t0.Add(-47 * time.Minute)
	j.Status.StartTime, j.Status.Active = &start, 1
	s.Jobs = []kube.Job{j}
	p := pod("report-29001-x", "")
	p.Metadata.OwnerReferences = []kube.OwnerReference{{Kind: "Job", Name: "report-29001", Controller: yes()}}
	s.Pods = []kube.Pod{p}
	e := event("CronJob", "report", "JobAlreadyActive", "Not starting job because prior execution is running and concurrency policy is Forbid", time.Minute)
	e.Type, e.Count = "Normal", 9
	s.Events = []kube.Event{e}
	f := only(t, Diagnose(s))
	expect(t, f, "KD188", "CronJob shop/report", "skipped 9 runs", "Job report-29001 is still running (for 47m0s)", "concurrencyPolicy Forbid")
	if f.Severity != Warning || !strings.Contains(f.Fix, "activeDeadlineSeconds") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// Without the controller's event, a running Job is just a running Job.
	s.Events = nil
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("no JobAlreadyActive event: %+v", r.Findings)
	}
	// A Job whose pod crashes is explained by that pod's finding, not by the skipped runs.
	s.Events = []kube.Event{e}
	crashed(&s.Pods[0], 1, "Error", 3)
	expect(t, only(t, Diagnose(s)), "KD110", "CronJob shop/report")
}

func TestCronJobSuspended(t *testing.T) {
	s := snap()
	cj := cronJob("report", "Allow")
	cj.Spec.Suspend = yes()
	last := t0.Add(-3 * time.Hour)
	cj.Status.LastScheduleTime = &last
	s.CronJobs = []kube.CronJob{cj}
	f := only(t, Diagnose(s))
	expect(t, f, "KD189", "CronJob shop/report", "is suspended", "last started one 3h0m0s ago")
	if f.Severity != Info {
		t.Errorf("severity %s", f.Severity)
	}
	s.CronJobs[0].Metadata.CreationTimestamp = t0.Add(-time.Minute)
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a CronJob created suspended a minute ago: %+v", r.Findings)
	}
}

func TestCronJobReplacesEachRunBeforeItFinishes(t *testing.T) {
	s := snap()
	cj := cronJob("sync", "Replace")
	cj.Spec.Schedule = "* * * * *"
	cj.Status.Active = append(cj.Status.Active, struct {
		Name string `json:"name"`
	}{Name: "sync-29003"})
	s.CronJobs = []kube.CronJob{cj}
	s.Events = []kube.Event{
		event("CronJob", "sync", "SuccessfulDelete", "Deleted job sync-29002", time.Minute),
		event("CronJob", "sync", "SuccessfulDelete", "Deleted job sync-29001", 2*time.Minute),
		event("CronJob", "sync", "SuccessfulCreate", "Created job sync-29003", time.Minute),
	}
	for i := range s.Events {
		s.Events[i].Type = "Normal"
	}
	f := only(t, Diagnose(s))
	expect(t, f, "KD280", "CronJob shop/sync", "concurrencyPolicy Replace", `schedule "* * * * *"`, "deleted 2 Jobs (sync-29001, sync-29002)", "never completed a run")
	if f.Severity != Warning || !strings.Contains(f.Fix, "Forbid") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// Jobs deleted by the history limits after they completed are not replaced runs.
	s.Events = append(s.Events, event("CronJob", "sync", "SawCompletedJob", "Saw completed job: sync-29000, condition: Complete", 3*time.Minute))
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a CronJob whose runs complete is fine: %+v", r.Findings)
	}
}
