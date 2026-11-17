package diagnose

import (
	"fmt"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// cronJobFindings covers CronJobs that start no Jobs although nothing is wrong with the Jobs' pods: a run that is
// still going holds the next one back (concurrencyPolicy Forbid), or the CronJob is suspended. A CronJob whose pods
// fail is explained by the pods' finding.
func cronJobFindings(ix *index, explained map[kube.Ref]bool) []Finding {
	var out []Finding
	for _, cj := range ix.s.CronJobs {
		if explained[cj.Ref()] {
			continue
		}
		if f := cronJobSkips(ix, cj); f != nil {
			out = append(out, *f)
		} else if f := suspendedCronJob(ix, cj); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// cronJobSkips finds a CronJob whose next run is held back because the last one is still running and its
// concurrencyPolicy is Forbid: the controller says so with a JobAlreadyActive event each time it skips.
func cronJobSkips(ix *index, cj kube.CronJob) *Finding {
	if cj.Spec.ConcurrencyPolicy != "Forbid" || len(cj.Status.Active) == 0 {
		return nil
	}
	evs := ix.eventsFor(cj.Ref(), "JobAlreadyActive")
	if len(evs) == 0 {
		return nil
	}
	e := evs[len(evs)-1]
	ns, name, job := cj.Metadata.Namespace, cj.Metadata.Name, cj.Status.Active[0].Name
	running := ""
	if j, ok := ix.jobs[kube.Ref{Kind: "Job", Namespace: ns, Name: job}]; ok {
		start := j.Metadata.CreationTimestamp
		if j.Status.StartTime != nil {
			start = *j.Status.StartTime
		}
		if !start.IsZero() {
			running = fmt.Sprintf(" (for %s)", ix.s.CollectedAt.Sub(start).Round(time.Second))
		}
	}
	skipped := "a run"
	if e.Count > 1 {
		skipped = fmt.Sprintf("%d runs", e.Count)
	}
	ev := []Evidence{
		eventEvidence(cj.Ref(), e),
		{Object: cj.Ref(), What: fmt.Sprintf("CronJob %s has concurrencyPolicy Forbid and schedule %q, and Job %s is active", name, cj.Spec.Schedule, job),
			Command: cmdGet("cronjob", ns, name, `{.spec.schedule}{" "}{.spec.concurrencyPolicy}{" "}{.status.active}`)},
		{Object: kube.Ref{Kind: "Job", Namespace: ns, Name: job}, What: "the run that is still going", Command: cmdGet("job", ns, job, "{.status}")},
	}
	return &Finding{Rule: "KD188", Title: "CronJob skips runs while the last one is still running", Severity: Warning, Object: cj.Ref(),
		Cause: fmt.Sprintf("CronJob %s skipped %s: Job %s is still running%s, and concurrencyPolicy Forbid starts no new Job until it ends", name, skipped, job, running),
		Fix: fmt.Sprintf("Find why Job %s runs longer than the schedule allows (its pods' logs); set activeDeadlineSeconds in the jobTemplate so a stuck run ends, "+
			"or use concurrencyPolicy Replace if a new run should take over from it.", job),
		Evidence: ev}
}

// suspendedCronJob reports a CronJob with spec.suspend: true, which schedules nothing until it is resumed.
func suspendedCronJob(ix *index, cj kube.CronJob) *Finding {
	if cj.Spec.Suspend == nil || !*cj.Spec.Suspend || ix.s.CollectedAt.Sub(cj.Metadata.CreationTimestamp) < suspendedAfter {
		return nil
	}
	ns, name := cj.Metadata.Namespace, cj.Metadata.Name
	cause := fmt.Sprintf("CronJob %s is suspended (spec.suspend: true), so its schedule %q starts no Jobs", name, cj.Spec.Schedule)
	if t := cj.Status.LastScheduleTime; t != nil {
		cause += fmt.Sprintf("; it last started one %s ago", ix.s.CollectedAt.Sub(*t).Round(time.Minute))
	} else {
		cause += "; it has never started one"
	}
	return &Finding{Rule: "KD189", Title: "CronJob is suspended", Severity: Info, Object: cj.Ref(), Cause: cause,
		Evidence: []Evidence{{Object: cj.Ref(), What: "CronJob has spec.suspend: true", Command: cmdGet("cronjob", ns, name, `{.spec.suspend}{" "}{.status.lastScheduleTime}`)}},
		Fix:      fmt.Sprintf("Resume it if it should run: kubectl patch cronjob %s -n %s --type=merge -p '{\"spec\":{\"suspend\":false}}'. Runs missed while it was suspended are not started, unless startingDeadlineSeconds still covers them.", name, ns)}
}
