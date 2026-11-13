# Changelog

## [Unreleased]

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
  k8sgpt and (by hand, with a model) HolmesGPT by the same keywords.
