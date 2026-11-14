# Changelog

## [Unreleased]

### Added
- `record --redact`: names, label values, image repositories and IP addresses become pseudonyms, and the context
  name and logs are dropped, so a snapshot can be attached to a public issue; it diagnoses to the same causes.

## [0.1.0] - 2026-11-13

The first version: find why Kubernetes workloads are broken, with the evidence for each cause.

### Added
- `kube-diagnose` (and `kubectl diagnose`): diagnoses the current namespace, one namespace (`-n`) or all (`-A`),
  read-only through kubectl. Text for a terminal, Markdown for an issue or pull request, JSON for tools;
  `--fail-on` for CI.
- 41 rules (`docs/rules.md`): image pulls (tag not found, access denied, registry unreachable, invalid reference),
  crashes with the exit code explained and the error line from the log, out-of-memory kills, liveness and readiness
  probes (with the probe's port checked against the container's), commands missing from the image, images for
  another CPU architecture, init containers, missing ConfigMaps, Secrets and keys (by key name only), volumes that
  will not mount, pods no node can take (resources against the largest node, node selectors, taints, cordons,
  claims), StorageClasses that do not exist or no default class, Services that select nothing or target a port the
  pods do not have or declare, NetworkPolicies that close a Service, exhausted quotas, missing ServiceAccounts,
  Pod Security and webhook rejections, failed Jobs, stalled rollouts, nodes not ready or under pressure, evictions.
- Pods are checked in the order they start so the first failure is the cause; pods with the same cause become one
  finding on their owner, with the Services they break listed under it.
- `record` saves what kube-diagnose read to a snapshot, and `--snapshot` diagnoses one without a cluster.
- `rules` lists the rule catalogue or explains one rule.
- The fault suite: 23 broken namespaces and a healthy one on kind, run on every push, scoring kube-diagnose,
  k8sgpt and (by hand, with a model) HolmesGPT by the same keywords. The run committed in `results/faults`:
  kube-diagnose named the root cause in its first finding for 23 of 23, with no false alarm; k8sgpt named 14, 4 of
  them first. Its recordings are in `testdata/faults`, and `make test` replays them through the current code.

### Fixed (found by the fault suite's first run)
- A container that had just exited, before the kubelet marked it CrashLoopBackOff, matched no rule, and its log
  was read from an instance the kubelet had already removed. Both are fixed: 4 faults the first run missed.
