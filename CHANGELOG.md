# Changelog

## [Unreleased]

### Added
- 11 rules, 85 in all (`docs/rules.md`):
  - scheduling and start-up: pods held by a scheduling gate, with Kueue's admission gate named (KD146); pod
    sandboxes the network plugin cannot set up or the node has no IP address for (KD134); hostPath volumes whose
    path the node does not have (KD135); readiness gates no controller sets (KD128);
  - crashes traced to a ServiceAccount token that automounting turned off (KD125), an RBAC denial, with the Role
    and RoleBinding to create (KD126), and a NetworkPolicy that drops the connection to a Service, on the client's
    egress or the backends' ingress (KD127);
  - storage: claims that name a PersistentVolume they cannot bind to: missing, reserved for another claim, Released
    with the old claim's UID, or of another class or a smaller size (KD157);
  - controllers: pods rejected for a RuntimeClass that does not exist (KD183), Deployments left paused before their
    rollout finished (KD184), and pods stuck terminating, with the finalizer or node that holds them (KD194).
- Liveness and readiness findings say when an exec probe runs a command the image does not have (curl in a busybox
  or distroless image).
- The snapshot holds pods' scheduling gates, readiness gates, finalizers and automountServiceAccountToken, init
  containers' restartPolicy, ServiceAccounts' automountServiceAccountToken, a Deployment's paused field and a
  PersistentVolume's claimRef UID.

### Fixed
- A claim for a class that no StorageClass object has was reported as asking for a StorageClass that does not exist
  (KD150) even when PersistentVolumes carry that class name, as static volumes do.
- A sidecar (an init container with `restartPolicy: Always`) was reported as an init container that never finishes
  (KD119) once it had run for two minutes in a pending pod, and a later init container that really was stuck went
  unnamed. Sidecars are now skipped there, a crashing sidecar is reported as a crashing container (KD110) and not
  as a failed init container (KD115), and the collector no longer reads a running sidecar's log.

## [0.3.0] - 2026-11-15

### Added
- 12 rules, 74 in all (`docs/rules.md`):
  - images: not on the node with `imagePullPolicy: Never` (KD108), and no build for the node's platform (KD109),
    which read as "does not exist" before;
  - containers: init containers that never finish, with the Service they wait for named when it is missing (KD119);
    crashes traced to a Service name that does not resolve because the Service does not exist (KD121), a port
    another container of the pod holds (KD122), an egress NetworkPolicy that blocks DNS (KD123), or a Service that
    refuses the connection because it has no ready pods (KD124);
  - storage: claims for an access mode the StorageClass cannot provide (KD156);
  - networking: LoadBalancer Services with no external address (KD168), Ingress TLS Secrets that are missing or
    hold no certificate (KD169), and an Ingress that routes to a workload scaled to zero (KD160, as a warning);
  - StatefulSets whose governing Service is missing or not headless (KD182), and PodDisruptionBudgets that select
    no pods (KD186).
- A CronJob's failing runs are one finding on the CronJob instead of one per Job.
- `--ignore KD168,...` leaves out the findings of chosen rules, and says on stderr how many it left out.
- The collector reads the current log of an init container still running in a pending pod.
- The snapshot holds containers' imagePullPolicy, Services' load balancer status, Ingress TLS entries and a
  StatefulSet's serviceName.
- 14 fault scenarios, 54 broken namespaces in all.
- The fault suite's committed run (43681868847): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 54 of 54 faults and raises no false alarm; k8sgpt v0.4.41 names 24, 13 of them first.
- KD123 and KD124 also read Go's DNS timeout and curl 8's refused-connection message.

### Fixed
- `record --redact` left the names of objects a snapshot only refers to in clear text: a missing ConfigMap, Secret,
  claim, pull secret, Ingress backend Service or HPA target, and the CronJob that owns a Job. Those are the names
  a diagnosis reports, so they are pseudonymised now.

## [0.2.0] - 2026-11-14

### Added
- 21 rules, 62 in all (`docs/rules.md`):
  - images: registry rate limits (KD105), pull secrets that do not exist (KD106) or are not of type
    `kubernetes.io/dockerconfigjson` (KD107);
  - containers: failing postStart hooks (KD116), runAsNonRoot with an image that runs as root or names a
    non-numeric user (KD117), writes to a read-only root filesystem with the path named (KD118), eviction for
    exceeding an ephemeral-storage limit (KD193), and evictions for node pressure name the resource (KD192);
  - scheduling: unsatisfiable topology spread or pod (anti-)affinity (KD144), host ports taken on every node
    (KD145), pods waiting for a scheduler that is not running (KD148), volumes pinned to a zone or node the pod
    cannot use (KD154);
  - volumes: ReadWriteOnce volumes still attached to another node (KD155);
  - admission: LimitRange (KD174) and missing PriorityClass (KD175) rejections;
  - HorizontalPodAutoscalers that cannot read their metrics (KD176), are held at maxReplicas (KD177), or target a
    workload that does not exist (KD178);
  - PodDisruptionBudgets that allow no disruptions while every pod is healthy (KD185);
  - Ingresses whose backend Service does not exist (KD165), whose backend port the Service lacks (KD166), or that no
    controller serves (KD167).
- The snapshot holds HorizontalPodAutoscalers, PodDisruptionBudgets, Ingresses and IngressClasses, and containers'
  securityContext, host ports and the pod's schedulerName.
- 17 fault scenarios, 40 broken namespaces in all, for the new rules that a one-node kind cluster can reproduce.
- `record --redact`: names, label values, image repositories and IP addresses become pseudonyms, and the context
  name and logs are dropped, so a snapshot can be attached to a public issue; it diagnoses to the same causes.
- The fault suite's committed run (43578580025): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 40 of 40 faults and raises no false alarm; k8sgpt v0.4.41 names 21.

### Fixed (found by the fault suite on Kubernetes 1.37)
- A failing postStart hook is named from the pod spec, since the kubelet's event says only "PostStartHook failed".
- The pod-level ephemeral-storage eviction message, which ends with a space, is recognised.

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
