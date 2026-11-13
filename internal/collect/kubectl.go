// Package collect reads a cluster through kubectl into a snapshot. kubectl does the talking: it already knows the
// user's contexts, credentials and auth plugins, and every read it makes is one the user can repeat by hand.
package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Runner runs one kubectl command and returns its standard output.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

// ErrNotReadOnly is returned for any kubectl command outside the read-only allowlist.
var ErrNotReadOnly = errors.New("refusing a kubectl command that is not read-only")

// CheckReadOnly allows `kubectl get`, `kubectl logs`, `kubectl version` and `kubectl config current-context`, and
// nothing else. Every kubectl call goes through it, so kube-diagnose cannot change a cluster or a kubeconfig even if
// a bug builds the wrong arguments.
func CheckReadOnly(args []string) error {
	if len(args) == 0 {
		return ErrNotReadOnly
	}
	for _, a := range args {
		switch {
		// Watching never returns, --raw reaches arbitrary API paths, and -f/-k read manifests the caller chose.
		case a == "-w", a == "--watch", a == "--watch-only", strings.HasPrefix(a, "--watch="), strings.HasPrefix(a, "--watch-only="),
			a == "-f", a == "--follow", strings.HasPrefix(a, "--follow="),
			a == "--raw", strings.HasPrefix(a, "--raw="), strings.HasPrefix(a, "--filename"),
			a == "-k", strings.HasPrefix(a, "--kustomize"):
			return fmt.Errorf("%w: flag %s", ErrNotReadOnly, a)
		}
	}
	switch args[0] {
	case "get", "logs", "version":
		return nil
	case "config":
		if len(args) == 2 && args[1] == "current-context" {
			return nil
		}
	}
	return fmt.Errorf("%w: kubectl %s", ErrNotReadOnly, strings.Join(args, " "))
}

// Kubectl runs the kubectl binary, adding --context when one is set.
type Kubectl struct {
	Path    string // default "kubectl"
	Context string
}

func (k Kubectl) Run(ctx context.Context, args ...string) ([]byte, error) {
	if err := CheckReadOnly(args); err != nil {
		return nil, err
	}
	full := append([]string{}, args...)
	if k.Context != "" && args[0] != "config" {
		full = append(full, "--context", k.Context)
	}
	bin := k.Path
	if bin == "" {
		bin = "kubectl"
	}
	cmd := exec.CommandContext(ctx, bin, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), &CommandError{Args: full, Message: msg}
	}
	return stdout.Bytes(), nil
}

// CommandError is a kubectl command that exited non-zero, with what it printed on stderr.
type CommandError struct {
	Args    []string
	Message string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("kubectl %s: %s", strings.Join(e.Args, " "), e.Message)
}

// Forbidden reports whether the error is an RBAC denial.
func Forbidden(err error) bool {
	var ce *CommandError
	return errors.As(err, &ce) && strings.Contains(strings.ToLower(ce.Message), "forbidden")
}
