// Command kube-diagnose finds why Kubernetes workloads are broken and shows the evidence for each cause. Installed as
// kubectl-diagnose on the PATH, it also runs as `kubectl diagnose`.
package main

import (
	"os"

	"github.com/sunilmehta-si/kube-diagnose/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.DefaultEnv()))
}
