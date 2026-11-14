# Contributing

Thank you for helping. Issues and pull requests are welcome; for a large change, open an issue first so we can
agree on the approach.

## Build and test

```bash
make test     # gofmt, go vet, and every test with the race detector, as CI runs them
make vuln     # govulncheck
make docs     # rewrite docs/rules.md after changing the rule catalogue
hack/faults.sh   # the fault suite on a fresh kind cluster (needs Docker; never uses your kubeconfig)
```

`make test` needs no cluster: the rules run on snapshots built in the tests, and the CLI tests use a fake kubectl.
Do not point a development build at a cluster you care about with anything but the read-only commands it already
uses; a test fails if a command outside the allowlist appears in the evidence.

## How the code is laid out

| Package | Does |
|---|---|
| `internal/kube` | the fields of Kubernetes objects the rules read, quantities, label selectors |
| `internal/collect` | runs kubectl, read-only by construction, into a snapshot |
| `internal/snapshot` | the snapshot format, and redaction for sharing one |
| `internal/diagnose` | the rules, the order they run in, grouping by owner, the rule catalogue |
| `internal/report` | text, Markdown and JSON output |
| `internal/cli` | the command line |
| `internal/faults`, `cmd/faultsuite` | loading and scoring the fault suite, and running it on kind |

## Adding a rule

1. Write the test first in `internal/diagnose/rules_test.go`, with the message the kubelet, scheduler or controller
   really writes; say in the test which Kubernetes version it is from if it changed recently.
2. Add the rule where it belongs in the start order (`podProblem`) or to the Service, storage, controller or node
   checks. Give it the next free ID in its range; IDs are never reused.
3. Every finding needs evidence with a read-only kubectl command for each fact, a cause sentence that names the
   object and what is wrong with it, and a fix. Never claim something is missing from a list that was not read
   (`index.read`).
4. Add it to `catalog.go` and run `make docs`.
5. If a cluster can be broken that way, add a scenario to `faults/` with the words that name the cause.

## Commits

Small commits that each build and pass `make test`, with a message that says why.
