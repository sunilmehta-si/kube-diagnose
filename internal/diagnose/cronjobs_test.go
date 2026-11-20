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

func TestCronJobScheduleNeverComesDue(t *testing.T) {
	s := snap()
	cj := cronJob("billing", "Allow")
	cj.Spec.Schedule = "0 0 30 2 *"
	s.CronJobs = []kube.CronJob{cj}
	e := event("CronJob", "billing", "InvalidSchedule", "invalid schedule: 0 0 30 2 * : time difference between two schedules is less than 1 second", 3*time.Minute)
	s.Events = []kube.Event{e}
	f := only(t, Diagnose(s))
	expect(t, f, "KD284", "CronJob shop/billing", `schedule "0 0 30 2 *" never comes due`, "day 30 of month 2 does not exist", "InvalidSchedule")
	if f.Severity != Critical || len(f.Evidence) != 2 {
		t.Errorf("severity %s, %d evidence", f.Severity, len(f.Evidence))
	}

	// The event has expired: the schedule alone shows it.
	s.Events = nil
	expect(t, only(t, Diagnose(s)), "KD284", "CronJob shop/billing", "day 30 of month 2 does not exist")

	for sched, never := range map[string]bool{
		"0 0 31 4,6,9,11 *": true,
		"0 0 30,31 feb *":   true,
		"0 0 31 apr-jun *":  false, // May has 31 days
		"0 0 29 2 *":        false, // leap years
		"0 0 31 * *":        false,
		"0 0 31 2 1":        false, // a weekday too: cron runs it every Monday in February
		"0 0 */31 2 *":      false, // a step it does not read: no claim
		"*/5 * * * *":       false,
		"@monthly":          false,
	} {
		if _, got := impossibleDate(sched); got != never {
			t.Errorf("impossibleDate(%q) = %v, want %v", sched, got, never)
		}
	}
}

func TestCronJobMissesItsStarts(t *testing.T) {
	s := snap()
	cj := cronJob("sync", "Allow")
	zero := int64(0)
	cj.Spec.StartingDeadlineSeconds = &zero
	s.CronJobs = []kube.CronJob{cj}
	e := event("CronJob", "sync", "MissSchedule", "Missed scheduled time to start a job: Thu, 19 Nov 2026 06:05:00 +0000", time.Minute)
	e.Count = 6
	s.Events = []kube.Event{e}
	f := only(t, Diagnose(s))
	expect(t, f, "KD285", "CronJob shop/sync", "missed 6 runs (MissSchedule)", "startingDeadlineSeconds is 0", "never started a Job")
	if f.Severity != Critical || !strings.Contains(f.Fix, "startingDeadlineSeconds") || len(f.Evidence) != 2 {
		t.Errorf("severity %s fix %q, %d evidence", f.Severity, f.Fix, len(f.Evidence))
	}

	// No miss yet: a warning about the deadline.
	s.Events = nil
	f = only(t, Diagnose(s))
	expect(t, f, "KD285", "CronJob shop/sync", "less than the few seconds")
	if f.Severity != Warning {
		t.Errorf("severity %s", f.Severity)
	}

	// 10 seconds or more, or no deadline: nothing to say.
	ten := int64(10)
	cj.Spec.StartingDeadlineSeconds = &ten
	s.CronJobs = []kube.CronJob{cj}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("a 10 s deadline: %v", r.Findings)
	}
}

func TestCronJobRunsPileUp(t *testing.T) {
	s := snap()
	cj := cronJob("report", "")
	for _, n := range []string{"report-29001", "report-29002", "report-29003"} {
		cj.Status.Active = append(cj.Status.Active, struct {
			Name string `json:"name"`
		}{Name: n})
	}
	s.CronJobs = []kube.CronJob{cj}
	var j kube.Job
	j.Metadata = kube.ObjectMeta{Name: "report-29001", Namespace: "shop", OwnerReferences: []kube.OwnerReference{{Kind: "CronJob", Name: "report", Controller: yes()}}}
	start := t0.Add(-14 * time.Minute)
	j.Status.StartTime, j.Status.Active = &start, 1
	s.Jobs = []kube.Job{j}
	f := only(t, Diagnose(s))
	expect(t, f, "KD286", "CronJob shop/report", "3 Jobs running at once", "concurrencyPolicy is Allow", "the oldest, report-29001, has run for 14m0s")
	if f.Severity != Warning || !strings.Contains(f.Fix, "Forbid") {
		t.Errorf("severity %s fix %q", f.Severity, f.Fix)
	}

	// One run at a time, or Forbid: not this rule.
	cj.Status.Active = cj.Status.Active[:1]
	s.CronJobs = []kube.CronJob{cj}
	if r := Diagnose(s); len(r.Findings) != 0 {
		t.Errorf("one active run: %v", r.Findings)
	}
}
