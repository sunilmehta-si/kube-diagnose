# Security policy

## Reporting a vulnerability

Please report it privately: use GitHub's **Report a vulnerability** button on this repository's Security tab, or
email sunilmehta695@gmail.com. Say what you found, how to reproduce it, and what it affects. You will get a reply
within three working days and a fix or a plan within fourteen. Please do not open a public issue first.

Fixes go into the latest release only.

## What kube-diagnose touches

- **It reads, and only reads, the cluster your kubectl context points at, through kubectl.** Every call goes
  through one allowlist (`CheckReadOnly` in `internal/collect/kubectl.go`) that permits `kubectl get`, `kubectl
  logs`, `kubectl version`, `kubectl config current-context` and one `kubectl config view` that prints the
  context's namespace, and refuses everything else, including `--watch`, `--raw`, `-f` and `--follow`, before a
  process starts. It never edits a kubeconfig and never stores credentials: kubectl authenticates as it always does.
- **Secret values never reach it.** Secrets and ConfigMaps are listed with a kubectl go-template that prints names,
  types and key names only. kubectl receives the objects; kube-diagnose sees the keys.
- **Snapshots and reports name your namespaces, pods and images, and quote event messages and log lines.** Log
  lines can hold anything an app prints. Snapshots are written readable by their owner only; treat them and the
  reports like the cluster data they came from before you share them.
- **Untrusted input.** A snapshot file is parsed as data; a newer snapshot schema is refused rather than misread.
  Evidence commands in a report are built from object names the API server accepted, quoted for the shell.

## The fault suite

`cmd/faultsuite` and `hack/faults.sh` apply broken workloads to a cluster on purpose. They take an explicit
`--kubeconfig`, never the default one, and refuse any context whose name does not start with `kind-`. `hack/faults.sh`
creates its own kind cluster and checks every download against a checksum in `faults/versions.env`. The scenarios'
working images are pinned by digest; the one deliberately missing repository is under this project's own ghcr.io
namespace, so nobody else can publish an image there.

## Supply chain

- The module has no dependencies outside the Go standard library.
- Every GitHub Action is pinned by commit SHA; Dependabot proposes updates 14 days after their release, security
  updates at once. Go is pinned in `go.mod`.
- Release binaries are built by the release workflow from the tagged commit, with provenance attestations:
  `gh attestation verify <archive> --repo sunilmehta-si/kube-diagnose`.
