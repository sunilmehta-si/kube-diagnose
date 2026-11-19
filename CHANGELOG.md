# Changelog

## [Unreleased]

### Added
- 8 rules, 129 in all (`docs/rules.md`):
  - the node and its runtime: a RuntimeClass whose handler the node's container runtime does not have, so no pod
    sandbox is created (KD196); a Localhost seccomp profile that is not on the node, which the kubelet passes on
    unchecked (KD207); a pod for another operating system, which the scheduler places and the kubelet rejects
    (KD244);
  - probes and hooks: a preStop hook that waits as long as the termination grace period, which includes it, so the
    app is killed before SIGTERM (KD208); a gRPC probe on a port that does not speak gRPC or lacks the health service
    (KD209);
  - NetworkPolicies: an egress policy that leaves the pod no way to the API server, which egress rules see at its own
    endpoints, usually on 6443 (KD267), and an ingress rule that allows a port name the pods do not declare (KD268);
  - CronJobs: a startingDeadlineSeconds under 10 seconds, so the controller misses the starts (KD285).
- 7 fault scenarios, 115 broken namespaces in all, one for each new rule but KD267: on kind's single node, which
  runs the API server too, a DNS-only egress policy did not block the pod's connection to it, so the fault does not
  happen there. Unit tests cover KD267.
- The snapshot holds a pod's spec.os, runtimeClassName and terminationGracePeriodSeconds, a preStop sleep, a gRPC
  probe, and a CronJob's startingDeadlineSeconds.

### Changed
- The fault suite's optional HolmesGPT run uses 0.46.0 (was 0.45.0; published 4 Nov, adoptable from 18 Nov), checked
  against its SHA-256. Its `ask` command takes the same arguments; the suite runs it only with a model and that
  provider's key, so the committed runs do not include it.

## [0.7.0] - 2026-11-18

- The fault suite's committed run (44296881025): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 108 of 108 faults and raises no false alarm; k8sgpt v0.4.41 names 42, 22 of them first.

### Added
- 8 rules, 121 in all (`docs/rules.md`):
  - commands and probes: a command or args using $(NAME) for a variable the container's env and envFrom do not
    define, which the kubelet passes on as the literal text, not reading the image's ENV (KD205); a probe that sets
    host, so the kubelet checks that address, the node itself for localhost, instead of the pod (KD206);
  - the kubelet: a pod that names its node in spec.nodeName, skipping the scheduler, and is rejected for the node's
    labels (KD242) or a host port another pod on it holds (KD243); a pod stopped at its own activeDeadlineSeconds,
    which in a Job's pod template fails every attempt (KD195);
  - Services and DNS: a headless Service whose targetPort differs from its port, which nothing maps (KD265), and a pod
    subdomain no headless Service serves, so an Indexed Job's workers cannot resolve each other (KD266);
  - CronJobs: a schedule that names a date that never comes, such as 30 February (KD284).
- 9 fault scenarios, 108 broken namespaces in all, one or more for each new rule and the KD264 change.
- The snapshot holds a pod's IP, hostname and subdomain and activeDeadlineSeconds, a probe's host and an envFrom
  prefix. `record --redact` gives a probe's host name a pseudonym, as it does other names.

### Changed
- KD264 names an EndpointSlice made for a selectorless Service that lacks the kubernetes.io/service-name label, the
  only link between a slice and its Service, and how to add it.
- `record --redact` gives an EndpointSlice named for its Service (the Service's name and a suffix) the Service's
  pseudonym and the suffix, so KD264 still finds a slice that lacks its label; a suffix longer than five characters
  is replaced too.
- The README's account of k8sgpt's output follows this run: for the liveness probe on the wrong port it gave the
  termination reason, as in the 0.5.0 run, where in the 0.6.0 run it reported nothing.

## [0.6.0] - 2026-11-18

- The fault suite's committed run (44269976066): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 99 of 99 faults and raises no false alarm; k8sgpt v0.4.41 names 35, 18 of them first.

### Added
- 11 rules, 113 in all (`docs/rules.md`):
  - containers: a command or args written as one string, ["sleep 3600"] for ["sleep", "3600"], with the list to write
    instead (KD201); an OOM kill caused by a memory-backed emptyDir, whose tmpfs pages count against the limit of
    the container that writes them and outlive its restarts (KD204);
  - probes: an httpGet probe with scheme HTTPS against a port that answers plain HTTP (KD202), and a probe that names
    a port the container does not declare, which the kubelet reports as errored: a readiness or startup probe never
    passes, and a liveness probe checks nothing, a warning (KD203);
  - volumes: a subPath that names a key the ConfigMap or Secret does not have, which the kubelet turns into an empty
    directory: the app finds a directory where it expects its file, or the runtime cannot mount it over a file the
    image has (KD234);
  - scheduling and the kubelet: a pod held back because another pod uses its ReadWriteOncePod claim, with the holder
    named (KD147); pods the kubelet rejects for a sysctl it does not allow (KD232) or a resource the node lacks, as when
    spec.nodeName skips the scheduler (KD241);
  - controllers that fail without a word: a CronJob whose concurrencyPolicy Replace deletes each run before it
    finishes (KD280), a DaemonSet that matches no node (KD282), and a Job with parallelism 0 (KD283).
- 12 fault scenarios, 99 broken namespaces in all, one or more for each new rule.
- The snapshot holds a probe's httpGet scheme and a Job's parallelism.

### Changed
- The README's account of k8sgpt's output follows this run: for the liveness probe on the wrong port it reported
  nothing, as in the 0.4.0 run, where in the 0.5.0 run it gave the termination reason.

## [0.5.0] - 2026-11-17

- The fault suite's committed run (44028804687): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 87 of 87 faults and raises no false alarm; k8sgpt v0.4.41 names 33, 15 of them first.

### Added
- 13 rules, 102 in all (`docs/rules.md`):
  - volumes: permission denied on a mounted volume, with the volume, the user the container runs as, and what to
    change: fsGroup, the owner of a hostPath directory (fsGroup does not apply there), or a Secret or ConfigMap
    volume's file mode (KD137); writes to a read-only volume, ConfigMap, Secret, projected and downward API volumes
    always being read-only (KD138); a file the app reads or runs that its ConfigMap or Secret volume does not have,
    with the keys it does have (KD230); a command that is not executable, with the volume's file mode when it comes
    from a ConfigMap (KD200); KD230 and KD200 read projected volumes made of ConfigMaps and Secrets too;
  - scheduling: pods bound by nodeName to a node that does not exist (KD240), and WaitForFirstConsumer claims that
    never bind because their pod bypasses the scheduler with nodeName (KD159);
  - networking: ExternalName Services set to an IP address (KD260), pods that resolve names with the node's DNS
    through dnsPolicy Default or the host network (KD261), NetworkPolicies that select no pods (KD262), Ingresses that
    send one host and path to different Services (KD263), and Services with no selector and no endpoints (KD264);
  - CronJobs: runs skipped because the last one is still running under concurrencyPolicy Forbid (KD188), and
    suspended CronJobs (KD189, a note).
- KD2xx: once an area's KD1xx numbers are used up, its rules continue at KD2xx; `docs/rules.md` says what each range
  covers.
- A pod that does not fit because of a LimitRange's default request, not one in its template, says so (KD140).
- A StatefulSet stuck on a pod that is not ready names the pods it has not created because of it (OrderedReady).
- A StatefulSet whose claim a ResourceQuota rejects is said to be unable to create that claim, not pods (KD170).
- An emptyDir volume evicted for exceeding its sizeLimit (KD193).
- 21 fault scenarios, 87 broken namespaces in all, one or more for each new rule and change above.
- `kube-diagnose rules <words>` lists the rules whose title or description mentions every word, and
  `kube-diagnose rules KD14` the rules in a range.
- The collector reads CronJobs. The snapshot holds volume mounts, volume file modes, hostPath and emptyDir sources,
  the pod's security context, hostNetwork and dnsPolicy, ingress path types, a Job's start time and a StatefulSet's
  podManagementPolicy.

### Changed
- The README's account of k8sgpt's output follows this run: for the liveness probe on the wrong port it now gives
  the termination reason, where in the 0.4.0 run it reported nothing.

### Fixed
- Redaction now covers the ConfigMaps and Secrets a projected volume names, and a namespace inside a cluster DNS name
  (api.shop.svc.cluster.local), as in a container's command.

## [0.4.0] - 2026-11-16

- The fault suite's committed run (43810509539): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 66 of 66 faults and raises no false alarm; k8sgpt v0.4.41 names 29, 12 of them first.

### Added
- 15 rules, 89 in all (`docs/rules.md`):
  - scheduling and start-up: pods held by a scheduling gate, with Kueue's admission gate named (KD146); pod
    sandboxes the network plugin cannot set up or the node has no IP address for (KD134); hostPath volumes whose
    path the node does not have (KD135); readiness gates no controller sets (KD128);
  - crashes traced to a ServiceAccount token that automounting turned off (KD125), an RBAC denial, with the Role
    and RoleBinding to create (KD126), and a NetworkPolicy that drops the connection to a Service, on the client's
    egress or the backends' ingress (KD127);
  - storage: claims that name a PersistentVolume they cannot bind to: missing, reserved for another claim, Released
    with the old claim's UID, or of another class or a smaller size (KD157); volumes whose CSI driver is not running
    (KD136); bound claims whose volume failed to grow (KD158);
  - controllers: pods rejected for a RuntimeClass that does not exist (KD183), Deployments left paused before their
    rollout finished (KD184), Jobs left suspended, or waiting for Kueue to admit them (KD187), and pods stuck
    terminating, with the finalizer or node that holds them (KD194).
- Probes whose exec command is not in the image (curl in a busybox or distroless image): a readiness probe keeps the
  pod out of its Services (KD120 says why), and a liveness or startup probe errors without ever restarting the
  container, so it silently checks nothing (KD129, a warning). The fault suite showed the second on Kubernetes 1.37;
  KD112 still names the command where a runtime reports it as a failure. A liveness finding also says when the probe
  times out, with its timeoutSeconds.
- 12 fault scenarios, 66 broken namespaces in all, one for each new cause a kind cluster can reproduce. KD134, KD126,
  KD158 and KD194 need a broken network plugin, an API client, a cloud volume or a deletion, and are tested on the
  messages Kubernetes and its clients write for them.
- A registry the node cannot reach (KD103) is told apart when its TLS certificate is not trusted (x509) or it speaks
  plain HTTP, with the containerd setting to change.
- A pod that requests an extended resource no node advertises (KD140) is said to lack its device plugin.
- An init container that never finishes (KD119) names the Service it waits for when that Service has no ready pods.
- The snapshot holds pods' scheduling gates, readiness gates, finalizers and automountServiceAccountToken, init
  containers' restartPolicy, ServiceAccounts' automountServiceAccountToken, a Deployment's paused field, a Job's
  suspend field, a claim's capacity and conditions, and a PersistentVolume's claimRef UID.

### Changed
- The report's summary counts info findings as notes, not problems: "2 problems: 1 critical, 1 warning. 1 note."

### Fixed
- An out-of-memory kill that the runtime reports as exit code 137 with reason Error, not OOMKilled, was reported as
  a crash (KD110). A SIGKILL with no probe or hook behind it, in a container with a memory limit, is now reported as
  running out of memory (KD111), and the cause says how the runtime labelled it. The fault suite caught this once on
  Kubernetes 1.37, where the kill landed as the container started.
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
