// Command faultsuite breaks a kind cluster in known ways, runs each troubleshooting tool on every broken namespace,
// and scores whether each tool named the root cause. It refuses to touch any cluster but a kind one.
//
//	faultsuite run   --kubeconfig .faults/kubeconfig [--k8sgpt bin/k8sgpt] [--holmes holmes]
//	faultsuite score --results .faults/results
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/faults"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: faultsuite run|score [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run(os.Args[2:])
	case "score":
		err = score(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "faultsuite:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig of the kind cluster to break (required; its context must be kind-*)")
	dir := fs.String("faults", "faults", "directory of scenarios")
	out := fs.String("out", ".faults", "where to write results/ and snapshots/")
	settle := fs.Duration("settle", 150*time.Second, "how long the faults run before any tool looks")
	kd := fs.String("kube-diagnose", "bin/kube-diagnose", "kube-diagnose binary")
	k8sgpt := fs.String("k8sgpt", "", "k8sgpt binary; empty skips it")
	holmes := fs.String("holmes", "", "HolmesGPT CLI; empty skips it")
	holmesModel := fs.String("holmes-model", "", "model for HolmesGPT (its --model flag)")
	only := fs.String("only", "", "comma-separated scenario names to run (default: all)")
	fs.Parse(args)
	if *kubeconfig == "" {
		return fmt.Errorf("--kubeconfig is required: faultsuite never uses the default kubeconfig")
	}
	kc, err := filepath.Abs(*kubeconfig)
	if err != nil {
		return err
	}
	ctxName, err := output("kubectl", "--kubeconfig", kc, "config", "current-context")
	if err != nil {
		return err
	}
	if ctxName = strings.TrimSpace(ctxName); !strings.HasPrefix(ctxName, "kind-") {
		return fmt.Errorf("refusing to break context %q: faultsuite only runs against kind clusters (kind-*)", ctxName)
	}
	scenarios, err := faults.Load(*dir)
	if err != nil {
		return err
	}
	if *only != "" {
		keep := map[string]bool{}
		for _, n := range strings.Split(*only, ",") {
			keep[strings.TrimSpace(n)] = true
		}
		var picked []faults.Scenario
		for _, s := range scenarios {
			if keep[s.Name] {
				picked = append(picked, s)
			}
		}
		scenarios = picked
	}
	for _, s := range scenarios {
		if _, err := output("kubectl", "--kubeconfig", kc, "apply", "-f", filepath.Join(*dir, s.Name, "manifest.yaml")); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	fmt.Fprintf(os.Stderr, "applied %d scenarios to %s; letting them run for %s\n", len(scenarios), ctxName, *settle)
	time.Sleep(*settle)

	env := append(os.Environ(), "KUBECONFIG="+kc, "NO_COLOR=1")
	timings := map[string]map[string]float64{}
	record := func(tool, ns string, d time.Duration) {
		if timings[tool] == nil {
			timings[tool] = map[string]float64{}
		}
		timings[tool][ns] = d.Seconds()
	}
	for _, s := range scenarios {
		ns := s.Namespace
		d, err := capture(env, filepath.Join(*out, "results", "kube-diagnose", ns+".json"), *kd, "-n", ns, "-o", "json")
		record("kube-diagnose", ns, d)
		report("kube-diagnose", ns, err)
		os.MkdirAll(filepath.Join(*out, "snapshots"), 0o755)
		_, err = capture(env, "", *kd, "record", "-n", ns, "-o", filepath.Join(*out, "snapshots", ns+".snapshot.json.gz"))
		report("kube-diagnose record", ns, err)
		if *k8sgpt != "" {
			d, err := capture(env, filepath.Join(*out, "results", "k8sgpt", ns+".json"), *k8sgpt,
				"analyze", "--namespace", ns, "--output", "json", "--kubeconfig", kc)
			record("k8sgpt", ns, d)
			report("k8sgpt", ns, err)
		}
		if *holmes != "" {
			q := fmt.Sprintf("Something is broken in Kubernetes namespace %s. Investigate it and state the root cause.", ns)
			a := []string{"ask", q, "--no-interactive"}
			if *holmesModel != "" {
				a = append(a, "--model", *holmesModel)
			}
			d, err := capture(env, filepath.Join(*out, "results", "holmesgpt", ns+".txt"), *holmes, a...)
			record("holmesgpt", ns, d)
			report("holmesgpt", ns, err)
		}
	}
	b, _ := json.MarshalIndent(timings, "", "  ")
	return os.WriteFile(filepath.Join(*out, "results", "timings.json"), append(b, '\n'), 0o644)
}

// capture runs a tool and writes its stdout to path; on failure it writes path's .err twin instead, which the
// scorer reads as a failed run. kube-diagnose exits 1 only with --fail-on, so any non-zero exit is a failure.
func capture(env []string, path, bin string, args ...string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	d := time.Since(start)
	if path == "" {
		if err != nil {
			return d, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return d, nil
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		msg := fmt.Sprintf("%v\n%s", err, stderr.String())
		os.WriteFile(strings.TrimSuffix(path, filepath.Ext(path))+".err", []byte(msg), 0o644)
		return d, fmt.Errorf("%w: %s", err, firstLine(stderr.String()))
	}
	return d, os.WriteFile(path, stdout.Bytes(), 0o644)
}

func report(tool, ns string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s on %s failed: %v\n", tool, ns, err)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func output(bin string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func score(args []string) error {
	fs := flag.NewFlagSet("score", flag.ExitOnError)
	dir := fs.String("faults", "faults", "directory of scenarios")
	results := fs.String("results", ".faults/results", "directory of tool outputs from faultsuite run")
	md := fs.String("markdown", "", "also write the Markdown table here")
	js := fs.String("json", "", "also write the scored results as JSON here")
	fs.Parse(args)
	scenarios, err := faults.Load(*dir)
	if err != nil {
		return err
	}
	r, err := faults.Score(scenarios, *results)
	if err != nil {
		return err
	}
	text := faults.Markdown(r)
	fmt.Print(text)
	if *md != "" {
		if err := os.WriteFile(*md, []byte(text), 0o644); err != nil {
			return err
		}
	}
	if *js != "" {
		b, _ := json.MarshalIndent(r, "", "  ")
		return os.WriteFile(*js, append(b, '\n'), 0o644)
	}
	return nil
}
