package diagnose

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// cronJobFindings covers CronJobs that start no Jobs although nothing is wrong with the Jobs' pods: a schedule that
// names a date that never comes, a run that is still going holds the next one back (concurrencyPolicy Forbid), or the
// CronJob is suspended. A CronJob whose pods
// fail is explained by the pods' finding.
func cronJobFindings(ix *index, explained map[kube.Ref]bool) []Finding {
	var out []Finding
	for _, cj := range ix.s.CronJobs {
		if explained[cj.Ref()] {
			continue
		}
		if f := cronJobNeverFires(ix, cj); f != nil {
			out = append(out, *f)
		} else if f := cronJobMissesStarts(ix, cj); f != nil {
			out = append(out, *f)
		} else if f := cronJobSkips(ix, cj); f != nil {
			out = append(out, *f)
		} else if f := cronJobPilesUp(ix, cj); f != nil {
			out = append(out, *f)
		} else if f := cronJobReplaces(ix, cj); f != nil {
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

// cronJobReplaces finds a CronJob with concurrencyPolicy Replace whose runs take longer than its schedule allows: each
// start deletes the Job still going (the controller says so with a SuccessfulDelete event, "Deleted job ..."), so no
// run ever finishes, and nothing fails.
func cronJobReplaces(ix *index, cj kube.CronJob) *Finding {
	if cj.Spec.ConcurrencyPolicy != "Replace" || len(cj.Status.Active) == 0 {
		return nil
	}
	var deleted []string
	var last kube.Event
	for _, e := range ix.eventsFor(cj.Ref(), "SuccessfulDelete") {
		if job, ok := strings.CutPrefix(e.Message, "Deleted job "); ok {
			deleted = append(deleted, job)
			if last.Message == "" {
				last = e
			}
		}
	}
	if len(deleted) == 0 || len(ix.eventsFor(cj.Ref(), "SawCompletedJob")) > 0 {
		return nil // a Job that finished was deleted by the history limits, not replaced
	}
	if t := cj.Status.LastSuccessfulTime; t != nil && t.After(last.Last()) {
		return nil
	}
	ns, name := cj.Metadata.Namespace, cj.Metadata.Name
	done := "it has never completed a run"
	if t := cj.Status.LastSuccessfulTime; t != nil {
		done = fmt.Sprintf("its last run that completed ended %s ago", ix.s.CollectedAt.Sub(*t).Round(time.Minute))
	}
	slices.Reverse(deleted) // oldest first
	runs := fmt.Sprintf("it deleted Job %s", deleted[0])
	if len(deleted) > 1 {
		runs = fmt.Sprintf("it deleted %d Jobs (%s)", len(deleted), strings.Join(deleted, ", "))
	}
	return &Finding{Rule: "KD280", Title: "CronJob replaces each run before it finishes", Severity: Warning, Object: cj.Ref(),
		Cause: fmt.Sprintf("CronJob %s has concurrencyPolicy Replace and schedule %q, and its runs take longer than that: each new run deletes the one still going, so none finishes; %s, and %s",
			name, cj.Spec.Schedule, runs, done),
		Evidence: []Evidence{eventEvidence(cj.Ref(), last),
			{Object: cj.Ref(), What: fmt.Sprintf("CronJob %s has concurrencyPolicy Replace and schedule %q, and Job %s is active", name, cj.Spec.Schedule, cj.Status.Active[0].Name),
				Command: cmdGet("cronjob", ns, name, `{.spec.schedule}{" "}{.spec.concurrencyPolicy}{" "}{.status}`)}},
		Fix: "Make a run finish within the schedule's interval (its pods' logs show where the time goes), or space the schedule out beyond how long a run takes; " +
			"concurrencyPolicy Forbid lets a run finish and skips the starts that overlap it."}
}

// cronJobNeverFires finds a CronJob whose schedule is valid cron but names a date that never comes, such as
// "0 0 30 2 *" (30 February). The API accepts it; the controller finds no next run, says so once with an
// InvalidSchedule event, and never starts a Job. Without the event (events expire), the schedule itself is checked.
func cronJobNeverFires(ix *index, cj kube.CronJob) *Finding {
	ns, name, sched := cj.Metadata.Namespace, cj.Metadata.Name, cj.Spec.Schedule
	ev := []Evidence{{Object: cj.Ref(), What: fmt.Sprintf("CronJob %s has schedule %q", name, sched),
		Command: cmdGet("cronjob", ns, name, `{.spec.schedule}{" "}{.status.lastScheduleTime}`)}}
	why, never := impossibleDate(sched)
	evs := ix.eventsFor(cj.Ref(), "InvalidSchedule")
	if len(evs) > 0 {
		ev = append([]Evidence{eventEvidence(cj.Ref(), evs[0])}, ev...)
	} else if !never {
		return nil
	}
	cause := fmt.Sprintf("CronJob %s's schedule %q never comes due", name, sched)
	if never {
		cause += ": " + why
	}
	cause += ", so the controller finds no next run and starts no Job"
	if len(evs) > 0 {
		cause += " (InvalidSchedule)"
	}
	return &Finding{Rule: "KD284", Title: "CronJob's schedule never comes due", Severity: Critical, Object: cj.Ref(), Cause: cause,
		Evidence: ev,
		Fix:      "Write a schedule for a day the intended months have: day 28 or earlier runs every month. For the last day of the month, schedule days 28-31 and have the job exit unless tomorrow is the 1st; Kubernetes cron has no L for last day."}
}

var monthDays = [13]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

var monthNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}

// impossibleDate reports whether a five-field cron schedule restricts the day of the month to days none of its months
// has, such as 30 or 31 in February, or 31 in April. A restricted day of the week makes the schedule fire on those
// days instead (cron ORs the two), so only a * or ? there can leave it never due. Fields it cannot read with
// certainty (steps, names it does not know) count as possible.
func impossibleDate(sched string) (string, bool) {
	f := strings.Fields(sched)
	if len(f) != 5 || (f[4] != "*" && f[4] != "?") {
		return "", false
	}
	days, ok := cronSet(f[2], nil)
	if !ok {
		return "", false
	}
	months, ok := cronSet(f[3], monthNames)
	if !ok {
		months = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		if f[3] != "*" && f[3] != "?" {
			return "", false
		}
	}
	for _, m := range months {
		if m < 1 || m > 12 {
			return "", false
		}
		for _, d := range days {
			if d >= 1 && d <= monthDays[m] {
				return "", false
			}
		}
	}
	return fmt.Sprintf("day %s of month %s does not exist", f[2], f[3]), true
}

// cronSet reads a cron field made of numbers, ranges and (with names) month names, separated by commas. A * or ?, a
// step, or anything else it does not know returns false.
func cronSet(field string, names map[string]int) ([]int, bool) {
	num := func(s string) (int, bool) {
		if n, ok := names[strings.ToLower(s)]; ok {
			return n, true
		}
		n := 0
		for _, r := range s {
			if r < '0' || r > '9' {
				return 0, false
			}
			n = n*10 + int(r-'0')
		}
		return n, s != ""
	}
	var out []int
	for _, part := range strings.Split(field, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, ok := num(lo)
		if !ok {
			return nil, false
		}
		b := a
		if isRange {
			if b, ok = num(hi); !ok || b < a {
				return nil, false
			}
		}
		for n := a; n <= b; n++ {
			out = append(out, n)
		}
	}
	return out, true
}

// cronJobMissesStarts finds a CronJob whose startingDeadlineSeconds is shorter than the controller's own delay: the
// controller wakes at each scheduled time a little late, finds the deadline already past, and skips the run with a
// MissSchedule event ("Missed scheduled time to start a job"). Kubernetes warns that a deadline under 10 seconds may
// miss runs; 0 misses every one. With no event yet, a deadline under 10 seconds is a warning.
func cronJobMissesStarts(ix *index, cj kube.CronJob) *Finding {
	d := cj.Spec.StartingDeadlineSeconds
	if d == nil || *d >= 10 || (cj.Spec.Suspend != nil && *cj.Spec.Suspend) {
		return nil
	}
	ns, name := cj.Metadata.Namespace, cj.Metadata.Name
	ev := []Evidence{{Object: cj.Ref(), What: fmt.Sprintf("CronJob %s has startingDeadlineSeconds %d and schedule %q", name, *d, cj.Spec.Schedule),
		Command: cmdGet("cronjob", ns, name, `{.spec.startingDeadlineSeconds}{" "}{.spec.schedule}{" "}{.status.lastScheduleTime}`)}}
	evs := ix.eventsFor(cj.Ref(), "MissSchedule")
	sev, cause := Warning, fmt.Sprintf("CronJob %s's startingDeadlineSeconds is %d, less than the few seconds the controller can take to wake at a scheduled time, so runs it starts late count as missed and are skipped", name, *d)
	if len(evs) > 0 {
		e := evs[0]
		missed := "a run"
		if n := e.Times(); n > 1 {
			missed = fmt.Sprintf("%d runs", n)
		}
		started := "it has never started a Job"
		if t := cj.Status.LastScheduleTime; t != nil {
			started = fmt.Sprintf("it last started one %s ago", ix.s.CollectedAt.Sub(*t).Round(time.Minute))
		}
		sev = Critical
		cause = fmt.Sprintf("CronJob %s has missed %s (MissSchedule): its startingDeadlineSeconds is %d, so by the time the controller acts on a scheduled time the deadline has passed, and %s", name, missed, *d, started)
		ev = append([]Evidence{eventEvidence(cj.Ref(), e)}, ev...)
	}
	return &Finding{Rule: "KD285", Title: "CronJob misses its starts: startingDeadlineSeconds is too short", Severity: sev, Object: cj.Ref(), Cause: cause, Evidence: ev,
		Fix: fmt.Sprintf("Raise startingDeadlineSeconds to at least 10, or remove it (no deadline): kubectl patch cronjob %s -n %s --type=merge -p '{\"spec\":{\"startingDeadlineSeconds\":60}}'.", name, ns)}
}

// cronJobPilesUp finds a CronJob whose concurrencyPolicy is Allow (the default) with two or more of its Jobs running
// at once: each run takes longer than the schedule's interval, so a new one starts while the last is still going and
// they accumulate, each holding its pods' resources, until the work or the cluster gives way.
func cronJobPilesUp(ix *index, cj kube.CronJob) *Finding {
	policy := cj.Spec.ConcurrencyPolicy
	if (policy != "" && policy != "Allow") || len(cj.Status.Active) < 2 {
		return nil
	}
	ns, name := cj.Metadata.Namespace, cj.Metadata.Name
	var jobs []string
	oldest := ""
	var oldestStart time.Time
	for _, a := range cj.Status.Active {
		jobs = append(jobs, a.Name)
		if j, ok := ix.jobs[kube.Ref{Kind: "Job", Namespace: ns, Name: a.Name}]; ok {
			start := j.Metadata.CreationTimestamp
			if j.Status.StartTime != nil {
				start = *j.Status.StartTime
			}
			if oldest == "" || start.Before(oldestStart) {
				oldest, oldestStart = a.Name, start
			}
		}
	}
	running := ""
	if oldest != "" && !oldestStart.IsZero() {
		running = fmt.Sprintf("; the oldest, %s, has run for %s", oldest, ix.s.CollectedAt.Sub(oldestStart).Round(time.Second))
	}
	return &Finding{Rule: "KD286", Title: "CronJob runs pile up", Severity: Warning, Object: cj.Ref(),
		Cause: fmt.Sprintf("CronJob %s has %d Jobs running at once (%s): its concurrencyPolicy is Allow, and each run takes longer than the schedule %q leaves, so every new run starts beside the ones still going%s",
			name, len(jobs), strings.Join(jobs, ", "), cj.Spec.Schedule, running),
		Evidence: []Evidence{{Object: cj.Ref(), What: fmt.Sprintf("CronJob %s has concurrencyPolicy Allow and %d active Jobs", name, len(jobs)),
			Command: cmdGet("cronjob", ns, name, `{.spec.schedule}{" "}{.spec.concurrencyPolicy}{" "}{.status.active[*].name}`)}},
		Fix: "Set concurrencyPolicy: Forbid (skip a run while one is going) or Replace (stop the old run), and give the Job an activeDeadlineSeconds; or schedule it less often than a run takes."}
}
