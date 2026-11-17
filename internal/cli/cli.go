// Package cli is the kube-diagnose command line.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/collect"
	"github.com/sunilmehta-si/kube-diagnose/internal/diagnose"
	"github.com/sunilmehta-si/kube-diagnose/internal/report"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// validNamespace is the API's rule for namespace names (an RFC 1123 label).
var validNamespace = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// version is set at build time with -ldflags "-X ...cli.version=v1.2.3".
var version = "dev"

// Env is what the command line needs from the outside world, replaced in tests.
type Env struct {
	Stdout, Stderr io.Writer
	// Kubectl returns the runner for a kubectl context ("" for the current one).
	Kubectl func(context string) collect.Runner
	IsTTY   bool
	Getenv  func(string) string
	Now     func() time.Time
}

// DefaultEnv talks to the real kubectl and the process's terminal.
func DefaultEnv() Env {
	tty := false
	if fi, err := os.Stdout.Stat(); err == nil {
		tty = fi.Mode()&os.ModeCharDevice != 0
	}
	return Env{Stdout: os.Stdout, Stderr: os.Stderr, IsTTY: tty, Getenv: os.Getenv, Now: time.Now,
		Kubectl: func(c string) collect.Runner { return collect.Kubectl{Context: c} }}
}

const usage = `kube-diagnose finds why Kubernetes workloads are broken, and shows the evidence for each cause.
It only reads: every kubectl command it runs is get, logs or version.

Usage:
  kube-diagnose [flags]                   diagnose the current namespace
  kube-diagnose -n shop                   diagnose one namespace
  kube-diagnose -A                        diagnose every namespace
  kube-diagnose --snapshot s.json.gz      diagnose a recorded snapshot instead of a cluster
  kube-diagnose record -n shop -o s.json.gz   save what it reads, to diagnose later or elsewhere
  kube-diagnose record -n shop --redact -o s.json.gz   the same with names replaced, to share in an issue
  kube-diagnose rules [KD101 | KD14 | words]   list the rules, explain one, list a range, or find those that mention words
  kube-diagnose version

Flags:
`

// Run executes the command line and returns the exit code: 0 when it ran (and found nothing at or above
// --fail-on), 1 when --fail-on is met, 2 for usage errors or when the cluster cannot be read.
func Run(args []string, env Env) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version":
			fmt.Fprintf(env.Stdout, "kube-diagnose %s\n", version)
			return 0
		case "rules":
			return rules(args[1:], env)
		case "record":
			return record(args[1:], env)
		case "scan":
			args = args[1:]
		}
	}
	return scan(args, env)
}

type scopeFlags struct {
	namespace     string
	allNamespaces bool
	context       string
	logLines      int
	maxLogs       int
}

func (s *scopeFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.namespace, "namespace", "", "namespace to diagnose (default: the current context's namespace)")
	fs.StringVar(&s.namespace, "n", "", "shorthand for --namespace")
	fs.BoolVar(&s.allNamespaces, "all-namespaces", false, "diagnose every namespace")
	fs.BoolVar(&s.allNamespaces, "A", false, "shorthand for --all-namespaces")
	fs.StringVar(&s.context, "context", "", "kubectl context (default: the current context)")
	fs.IntVar(&s.logLines, "log-lines", 20, "lines of log to read from each crashed container")
	fs.IntVar(&s.maxLogs, "max-logs", 40, "most containers to read logs from")
}

// collectSnapshot reads the cluster, resolving the namespace from the kubectl context when none is given.
func (s *scopeFlags) collect(env Env) (*snapshot.Snapshot, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	r := env.Kubectl(s.context)
	ns := s.namespace
	if ns == "" && !s.allNamespaces {
		out, err := r.Run(ctx, strings.Fields(collect.CurrentNamespace)...)
		ns = strings.TrimSpace(string(out))
		if err != nil || !validNamespace.MatchString(ns) {
			ns = "default"
		}
	}
	return collect.Collect(ctx, r, collect.Options{Namespace: ns, AllNamespaces: s.allNamespaces, Context: s.context,
		LogLines: s.logLines, MaxLogs: s.maxLogs, Tool: "kube-diagnose " + version, Now: env.Now})
}

func newFlagSet(name string, env Env, extra string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		fmt.Fprint(env.Stderr, extra)
		fs.PrintDefaults()
	}
	return fs
}

func scan(args []string, env Env) int {
	var sf scopeFlags
	fs := newFlagSet("kube-diagnose", env, usage)
	sf.register(fs)
	snap := fs.String("snapshot", "", "diagnose this snapshot file (from kube-diagnose record) instead of a cluster")
	output := fs.String("output", "text", "text, markdown or json")
	fs.StringVar(output, "o", "text", "shorthand for --output")
	failOn := fs.String("fail-on", "", "exit 1 when a finding is at least this severe: critical or warning")
	color := fs.String("color", "auto", "auto, always or never (NO_COLOR is honoured)")
	ignore := fs.String("ignore", "", "comma-separated rule IDs whose findings are left out, such as KD168 on a cluster without load balancers")
	if err := fs.Parse(args); err != nil {
		return parseExit(err)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "kube-diagnose: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	ignored := map[string]bool{}
	for _, id := range strings.Split(*ignore, ",") {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if _, ok := diagnose.RuleByID(id); !ok {
			fmt.Fprintf(env.Stderr, "kube-diagnose: --ignore: no rule %s (kube-diagnose rules lists them)\n", id)
			return 2
		}
		ignored[id] = true
	}
	threshold, ok := map[string]int{"": -1, "critical": int(diagnose.Critical), "warning": int(diagnose.Warning)}[*failOn]
	if !ok {
		fmt.Fprintf(env.Stderr, "kube-diagnose: --fail-on must be critical or warning, not %q\n", *failOn)
		return 2
	}
	var s *snapshot.Snapshot
	var err error
	if *snap != "" {
		if sf.namespace != "" || sf.allNamespaces || sf.context != "" {
			fmt.Fprintln(env.Stderr, "kube-diagnose: --snapshot reads a file; -n, -A and --context do not apply")
			return 2
		}
		s, err = snapshot.Read(*snap)
	} else {
		s, err = sf.collect(env)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "kube-diagnose: %v\n", err)
		return 2
	}
	r := diagnose.Diagnose(s)
	if len(ignored) > 0 {
		kept, left := r.Findings[:0], 0
		for _, f := range r.Findings {
			if ignored[f.Rule] {
				left++
				continue
			}
			kept = append(kept, f)
		}
		r.Findings = kept
		if left > 0 {
			fmt.Fprintf(env.Stderr, "kube-diagnose: %d findings of ignored rules left out\n", left)
		}
	}
	switch *output {
	case "text":
		useColor := *color == "always" || (*color == "auto" && env.IsTTY && env.Getenv("NO_COLOR") == "")
		err = report.Text(env.Stdout, r, report.Style{Color: useColor})
	case "markdown", "md":
		err = report.Markdown(env.Stdout, r)
	case "json":
		err = report.JSON(env.Stdout, r)
	default:
		fmt.Fprintf(env.Stderr, "kube-diagnose: --output must be text, markdown or json, not %q\n", *output)
		return 2
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "kube-diagnose: %v\n", err)
		return 2
	}
	for _, f := range r.Findings {
		if threshold >= 0 && int(f.Severity) <= threshold {
			return 1
		}
	}
	return 0
}

func record(args []string, env Env) int {
	var sf scopeFlags
	fs := newFlagSet("kube-diagnose record", env, "Usage: kube-diagnose record [-n NAMESPACE | -A] -o FILE[.gz]\n\n"+
		"Saves everything kube-diagnose reads (object specs and status, events, ConfigMap and Secret key names but never\n"+
		"their values, and the log tails of crashed containers) to one file, readable by you only.\n\nFlags:\n")
	sf.register(fs)
	out := fs.String("output", "", "file to write; a name ending in .gz is gzipped")
	fs.StringVar(out, "o", "", "shorthand for --output")
	redact := fs.Bool("redact", false, "replace names, images and IP addresses with pseudonyms and drop logs, for sharing")
	if err := fs.Parse(args); err != nil {
		return parseExit(err)
	}
	if *out == "" || fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	s, err := sf.collect(env)
	if err == nil && *redact {
		s, err = snapshot.Redact(s)
	}
	if err == nil {
		err = snapshot.Write(*out, s)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "kube-diagnose: %v\n", err)
		return 2
	}
	fmt.Fprintf(env.Stderr, "kube-diagnose: wrote %d pods, %d events and %d logs to %s\n", len(s.Pods), len(s.Events), len(s.Logs), *out)
	return 0
}

var (
	reRuleID     = regexp.MustCompile(`(?i)^KD\d{3}$`)
	reRulePrefix = regexp.MustCompile(`(?i)^KD\d{1,2}$`)
)

func rules(args []string, env Env) int {
	if len(args) == 0 {
		for _, r := range diagnose.Rules {
			fmt.Fprintf(env.Stdout, "%s  %-8s  %s\n", r.ID, r.Severity, r.Title)
		}
		return 0
	}
	if len(args) == 1 && reRulePrefix.MatchString(args[0]) {
		// A range: KD2 is every KD2xx rule, KD14 every rule about scheduling.
		prefix, n := strings.ToUpper(args[0]), 0
		for _, r := range diagnose.Rules {
			if strings.HasPrefix(r.ID, prefix) {
				fmt.Fprintf(env.Stdout, "%s  %-8s  %s\n", r.ID, r.Severity, r.Title)
				n++
			}
		}
		if n == 0 {
			fmt.Fprintf(env.Stderr, "kube-diagnose: no rule starts with %s (kube-diagnose rules lists them)\n", prefix)
			return 2
		}
		return 0
	}
	if !reRuleID.MatchString(args[0]) {
		// Words, not IDs: list the rules whose title or description mentions every one of them.
		n := 0
		for _, r := range diagnose.Rules {
			text := strings.ToLower(r.Title + " " + r.Detects)
			all := true
			for _, w := range args {
				all = all && strings.Contains(text, strings.ToLower(w))
			}
			if all {
				fmt.Fprintf(env.Stdout, "%s  %-8s  %s\n", r.ID, r.Severity, r.Title)
				n++
			}
		}
		if n == 0 {
			fmt.Fprintf(env.Stderr, "kube-diagnose: no rule mentions %s (kube-diagnose rules lists them)\n", strings.Join(args, " "))
			return 2
		}
		return 0
	}
	code := 0
	for _, id := range args {
		r, ok := diagnose.RuleByID(strings.ToUpper(id))
		if !ok {
			fmt.Fprintf(env.Stderr, "kube-diagnose: no rule %s (kube-diagnose rules lists them)\n", id)
			code = 2
			continue
		}
		fmt.Fprintf(env.Stdout, "%s %s (%s)\n\nDetects: %s\n\nEvidence: %s\n\n", r.ID, r.Title, r.Severity, r.Detects, r.Evidence)
	}
	return code
}

func parseExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}
