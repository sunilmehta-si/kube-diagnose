# Changelog

## [Unreleased]

## [0.13.0] - 2026-11-23

- The fault suite's committed run (45167155607): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 181 of 181 faults and raises no false alarm; k8sgpt v0.4.41 names 36, 10 of them first.

### Added
- 14 rules, 181 in all (`docs/rules.md`). KD3xx continues an area whose KD2xx numbers are used up: KD300 and on are
  running the container, KD360 and on Services and networking.
  - RBAC, each read from the API server's refusal and the Roles bound to the ServiceAccount: a Role that grants the
    resource in another API group, deployments in "" instead of apps (KD300); one that names a resource the API does
    not have, configmap for configmaps (KD301); one that grants the resource but not the verb, get and list where the
    app also watches (KD302); one that limits a list or watch by resourceNames, which those requests never match
    (KD303); a permission granted in another namespace than the one the app reads (KD304); and a RoleBinding asked
    for a cluster-wide request, across all namespaces or of nodes, which only a ClusterRoleBinding grants (KD305);
  - scheduling: a topology spread constraint over a node label no node has, topology.kubernetes.io/zone on kind or
    bare metal (KD245), and a required pod affinity to pods that do not exist (KD246);
  - volumes and configuration: a ConfigMap or Secret mounted whole where the app reads a file, without subPath
    (KD233), and a variable left unset because the optional key or envFrom object it comes from does not exist
    (KD235);
  - probes: a liveness probe that kills the app before it has started, with no startupProbe (KD306);
  - networking: a NetworkPolicy that allows a Service's cluster IP by ipBlock, which a policy never sees (KD360), and
    an app given a Service's old cluster IP in place of its name (KD361);
  - autoscaling: an HPA that names its target with a kind or apiVersion the cluster does not serve, a Deployment in
    extensions/v1beta1 (KD293).
- 21 fault scenarios, 181 broken namespaces in all: one for each new rule, a second for KD305 and KD235, and one each
  for the existing rules' new causes below. The RBAC ones run kubectl (registry.k8s.io/kubectl v1.37.2, pinned by
  digest in `faults/versions.env`), which prints the API server's refusal as client-go apps do.
- The snapshot holds a pod's topologySpreadConstraints, a node's container runtime, an HPA target's apiVersion and a
  NetworkPolicy ipBlock's except list.

### Changed
- KD141 names the expressions of a required node affinity that no node meets, with the values the nodes have, and
  says when a nodeSelector pins pods by hostname to a node that does not exist.
- KD135 says when the Docker socket is mounted on a node that runs containerd, and shows the node's container runtime
  whenever it is known.
- KD111 names the app's own memory setting when it is above the limit: -Xmx, --max-old-space-size, GOMEMLIMIT, or a
  variable such as CACHE_SIZE_MB.
- KD120 says when a readiness probe times out, as KD112 did for liveness probes.
- A NetworkPolicy ipBlock is judged against the other pod's IP; before, any ipBlock counted as allowing every pod.

### Fixed
- An out-of-memory kill that the runtime reported as Error lost the LimitRange that had set the limit from its cause.
- A Service whose pods wait for a claim was reported as a finding of its own, ahead of the claim; it is listed under
  the claim's finding now.
- A container caught between a failed postStart hook and the kubelet's back-off (waiting in PostStartHookError) gave
  no finding; it is KD116.

## [0.12.0] - 2026-11-22

- The fault suite's committed run (44996999466): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 160 of 160 faults and raises no false alarm; k8sgpt v0.4.41 names 35, 10 of them first.

### Added
- 16 rules, 167 in all (`docs/rules.md`):
  - commands: a flag and its value written as one argument, "--port 8080" (KD221); a command that is there and still
    fails with "no such file or directory", because the interpreter on its first line, or its loader, is not in the
    image (KD222); a shell operator such as && in a command that runs without a shell (KD226); and flags written
    under command, which replaces the image's entrypoint, where args is meant (KD229);
  - configuration: an app that reads REDIS_PORT as its own setting when the kubelet set it for Service redis, to
    tcp://IP:PORT (KD223), and a container run as a user other than root that is denied a path of its image (KD224);
  - connections: a Service whose ready pods refuse the port it targets, because nothing listens there and no
    readiness probe checks it (KD225);
  - storage: a claim that only a hand-made PersistentVolume can satisfy and that none fits, being too small, of
    other access modes, labels or volume mode, or taken (KD250); one whose fitting volume is Released (KD251); and a
    claim that is Lost, bound on paper to a volume that does not exist (KD252);
  - NetworkPolicy: a rule that selects namespaces by a label no namespace has (KD274);
  - RBAC: a RoleBinding that grants a Role which does not exist (KD227) or names a ServiceAccount which does not
    exist (KD228), tied to the container the API server refuses when there is one;
  - admission: a ResourceQuota on a request or limit that the pods do not set (KD275, which KD170 used to report as
    a quota used up), a LimitRange whose default limit is below the container's request (KD276), and an admission
    webhook the API server cannot reach, which refuses every pod though it rejected none (KD277).
- 19 fault scenarios, 160 broken namespaces in all: one for each new rule but KD277, a second for KD250, and one
  each for a NetworkPolicy that allows the Service's port, a probe command written as one string and a Job cut off
  by its deadline. KD277 has unit tests and no scenario: its webhook configuration is a cluster-wide object, and
  k8sgpt reported it in every namespace it scanned, the healthy one included, which would have counted against
  k8sgpt 160 times for one fault.
- The snapshot holds the names and labels of the cluster's namespaces, the Roles and RoleBindings of the namespaces
  read, the names of the cluster's ClusterRoles, a pod's enableServiceLinks, and a claim's and a volume's volumeMode,
  selector and reclaim policy. `--redact` renames all of them; the built-in ClusterRoles (view, edit, admin,
  cluster-admin, system:*) keep their names.

### Changed
- The cluster is read with up to eight kubectl calls at once, not one by one. On the fault suite's cluster a
  namespace took 1.4 to 2.3 seconds to read before, over this round's three runs, and 0.8 to 1.4 after, over its
  four (the runners differ from run to run). The snapshot is the same either way.
- NetworkPolicy rules that select by namespace are judged against the namespaces' labels when those were read;
  before, any such rule counted as allowing the connection.
- KD127 names a policy that allows the Service's port where the pods' port (the targetPort) is meant.
- KD129, KD120 and KD112 name an exec probe whose whole command line is one item, such as "cat /tmp/healthy".
- KD180 says when a Job was stopped by its own activeDeadlineSeconds: its pods were ended while running, and
  nothing crashed.

### Fixed
- A container of a long-running workload whose process keeps ending with code 0 was not reported at all when the
  snapshot caught it between an exit and the kubelet's back-off (state terminated, reason Completed). It is KD110
  now, or the rule that explains the exit.
- A pending claim's finding no longer changes once the fault is more than ten minutes old. At that point the
  scheduler stops saying which claim a pod waits for ("binding volumes: context deadline exceeded") and the
  Deployment passes its progress deadline; the first was reported as KD149 ahead of the claim, the second as a KD181
  of its own. The fault suite showed both once it had grown past ten minutes a run.
- The NetworkPolicy scenarios' clients made one request and then slept; one made it in the moment before its policy
  took effect and never failed. They call every five seconds now.

## [0.11.0] - 2026-11-21

- The fault suite's committed run (44877424146): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 141 of 141 faults and raises no false alarm; k8sgpt v0.4.41 names 33, 11 of them first.
  k8sgpt's count is lower than in earlier releases because the judge was wrong, not because k8sgpt changed (see Fixed).

### Added
- 9 rules, 151 in all (`docs/rules.md`):
  - configuration: an env value that refers to $(NAME) where NAME is defined later in the env list, or not at all, so
    the process gets the literal text (KD216);
  - connections: a container that connects to 127.0.0.1 or localhost for something a Service serves from other pods
    (KD217), or to a Service on a port it does not expose, most often the pods' targetPort (KD218);
  - security: a container that exits with "Operation not permitted" on something a Linux capability guards while its
    securityContext drops that capability or ALL (KD219);
  - init containers: one that waits for a Service whose only pods are its own workload's, so each waits for the other
    (KD220);
  - disruption: pods that more than one PodDisruptionBudget covers, which the eviction API refuses (KD289);
  - autoscaling: an HPA switched off because its target has 0 replicas (KD290), and HPAs that control the same pods,
    none of which scales (KD291);
  - Jobs: a Job that never completes because a container declared next to the work, a proxy say, keeps running
    (KD292).
- 10 fault scenarios, 141 broken namespaces in all: one for each new rule and one for a probe answered 401.
- The snapshot holds a container's securityContext.capabilities.

### Changed
- KD120 and KD112 say what the HTTP status means when an httpGet probe fails: 404 (the app does not serve the path),
  401 or 403 (the path needs credentials the kubelet does not send), 400, 405, and 5xx (the app reports itself
  unhealthy).

### Fixed
- The fault suite's judge counted the namespace's own name as naming the cause. Each namespace is named for its fault
  (kd-oomkilled) and its keywords are often words of that name, so a tool that printed only the path of an object,
  such as "ConfigMap kd-oomkilled/kube-root-ca.crt is not used", scored. The judge now takes the namespace's name out
  of the text first. Scored again, the 0.10.0 run reads: k8sgpt 32 of 131, 9 of them first (published as 48 and 27).
- That check also caught kube-diagnose once: for a StatefulSet whose claim a quota refuses, Kubernetes 1.37 writes the
  event as "Create Claim" with a capital, the rule expected a small letter, and KD170 said "cannot create pods" without
  naming the claim. It names the claim now.

## [0.10.0] - 2026-11-20

- The fault suite's committed run (44730219543): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 131 of 131 faults and raises no false alarm; k8sgpt v0.4.41 names 48, 27 of them first.

### Added
- 5 rules, 142 in all (`docs/rules.md`):
  - commands: the shell's $NAME or ${NAME} in a command that runs no shell, so the process gets the literal text
    (KD213); a volume (emptyDir, claim or hostPath) mounted on the directory that holds the command, hiding it (KD214);
  - probes: an app that listens on 127.0.0.1 or localhost only, which in a pod nothing else can reach, shown by its
    command, a bind variable in env or its own log line (KD215);
  - Services: a selector that also matches the ready pods of another workload, which do not serve the numeric target
    port, so a share of connections fails (KD273);
  - Deployments: a minReadySeconds of a minute or more that keeps ready pods from counting as available (KD288).
- 6 fault scenarios, 131 broken namespaces in all, one for each new rule and the change below.
- The snapshot holds a Deployment's minReadySeconds.

### Changed
- KD111 says when the memory limit that killed the container is a LimitRange default the pod template never set.
- `record --redact` leaves loopback addresses (127.0.0.0/8) and 0.0.0.0 as they are: they name no machine, and a
  redacted snapshot of an app bound to 127.0.0.1 lost the cause KD215 reads.

## [0.9.0] - 2026-11-20

- The fault suite's committed run (44709934332): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 125 of 125 faults and raises no false alarm; k8sgpt v0.4.41 names 46, 27 of them first.
- The fault suite's kind node takes 250 pods (`hack/kind-faults.yaml`): at 125 namespaces at once the default 110
  ran out, and scenarios showed a pod waiting for a slot instead of their fault.

### Added
- 8 rules, 137 in all (`docs/rules.md`):
  - resources: a memory limit without a unit, which Kubernetes reads as bytes, so the container dies as it starts
    (KD210);
  - probes and DNS: a readiness probe held back by an initialDelaySeconds of 5 minutes or more (KD211); a pod with
    dnsPolicy None whose dnsConfig leaves out cluster DNS (KD269); an ExternalName Service whose externalName does not
    resolve (KD270);
  - Services and Ingresses: a Service port whose protocol the pods do not declare for it, as for UDP behind a TCP
    port (KD271); an Ingress with TLS that also serves a host no TLS entry covers (KD272);
  - workloads: a multi-replica Deployment whose pods share one ReadWriteOnce claim (KD287), and a CronJob with
    concurrencyPolicy Allow whose runs outlast the schedule and pile up (KD286).
- 10 fault scenarios, 125 broken namespaces in all, one for each new rule and each change below.
- The snapshot holds a pod's dnsConfig.

### Changed
- KD140 names a cpu request written as a bare number of 100 or more (cpu: 500 is 500 cores) and the millicores it
  likely meant.
- KD110 says when a Job's podFailurePolicy matched the exit and failed the whole Job at once, without the retries its
  backoffLimit allows, and names the rule.

## [0.8.0] - 2026-11-19

- The fault suite's committed run (44485671336): kube-diagnose names the root cause in its first finding, with the
  exact rule and object, for 115 of 115 faults and raises no false alarm; k8sgpt v0.4.41 names 44, 24 of them first.

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
