// Package kube holds the parts of Kubernetes objects that kube-diagnose reads, decoded from `kubectl get -o json`.
// Only the fields a rule uses are declared; everything else in the API response is ignored.
package kube

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Ref names one object. Namespace is empty for cluster-scoped kinds.
type Ref struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (r Ref) String() string {
	if r.Namespace == "" {
		return r.Kind + " " + r.Name
	}
	return r.Kind + " " + r.Namespace + "/" + r.Name
}

type OwnerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller,omitempty"`
}

type ObjectMeta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace,omitempty"`
	UID               string            `json:"uid,omitempty"`
	Labels            map[string]string `json:"labels,omitempty"`
	Annotations       map[string]string `json:"annotations,omitempty"`
	OwnerReferences   []OwnerReference  `json:"ownerReferences,omitempty"`
	CreationTimestamp time.Time         `json:"creationTimestamp"`
	DeletionTimestamp *time.Time        `json:"deletionTimestamp,omitempty"`
	// Finalizers must all be removed before a deleted object goes away.
	Finalizers []string `json:"finalizers,omitempty"`
}

// Controller returns the owner that controls the object, if any.
func (m ObjectMeta) Controller() (OwnerReference, bool) {
	for _, o := range m.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return o, true
		}
	}
	return OwnerReference{}, false
}

type Condition struct {
	Type               string    `json:"type"`
	Status             string    `json:"status"`
	Reason             string    `json:"reason,omitempty"`
	Message            string    `json:"message,omitempty"`
	LastTransitionTime time.Time `json:"lastTransitionTime"`
}

// FindCondition returns the condition of the given type.
func FindCondition(cs []Condition, typ string) (Condition, bool) {
	for _, c := range cs {
		if c.Type == typ {
			return c, true
		}
	}
	return Condition{}, false
}

// IntOrString is a port or a named port, as the API writes it: a JSON number or a string.
type IntOrString struct {
	Int    int32
	Str    string
	IsName bool
}

func (v *IntOrString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if n, err := strconv.Atoi(s); err == nil {
			v.Int = int32(n)
			return nil
		}
		v.Str, v.IsName = s, true
		return nil
	}
	return json.Unmarshal(b, &v.Int)
}

func (v IntOrString) MarshalJSON() ([]byte, error) {
	if v.IsName {
		return json.Marshal(v.Str)
	}
	return json.Marshal(v.Int)
}

func (v IntOrString) String() string {
	if v.IsName {
		return v.Str
	}
	return strconv.Itoa(int(v.Int))
}

type LabelSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

type LabelSelector struct {
	MatchLabels      map[string]string          `json:"matchLabels,omitempty"`
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// ---- Pods ----

type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int32  `json:"containerPort"`
	HostPort      int32  `json:"hostPort,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
}

type KeyRef struct {
	Name     string `json:"name"`
	Key      string `json:"key"`
	Optional *bool  `json:"optional,omitempty"`
}

type EnvVarSource struct {
	ConfigMapKeyRef *KeyRef `json:"configMapKeyRef,omitempty"`
	SecretKeyRef    *KeyRef `json:"secretKeyRef,omitempty"`
}

type EnvVar struct {
	Name      string        `json:"name"`
	Value     string        `json:"value,omitempty"`
	ValueFrom *EnvVarSource `json:"valueFrom,omitempty"`
}

type NameRef struct {
	Name     string `json:"name"`
	Optional *bool  `json:"optional,omitempty"`
}

type EnvFromSource struct {
	ConfigMapRef *NameRef `json:"configMapRef,omitempty"`
	SecretRef    *NameRef `json:"secretRef,omitempty"`
}

type Resources struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

type HTTPGetAction struct {
	Path   string      `json:"path,omitempty"`
	Port   IntOrString `json:"port"`
	Scheme string      `json:"scheme,omitempty"`
}

type TCPSocketAction struct {
	Port IntOrString `json:"port"`
}

type ExecAction struct {
	Command []string `json:"command,omitempty"`
}

type Probe struct {
	HTTPGet             *HTTPGetAction   `json:"httpGet,omitempty"`
	TCPSocket           *TCPSocketAction `json:"tcpSocket,omitempty"`
	Exec                *ExecAction      `json:"exec,omitempty"`
	InitialDelaySeconds int32            `json:"initialDelaySeconds,omitempty"`
	PeriodSeconds       int32            `json:"periodSeconds,omitempty"`
	TimeoutSeconds      int32            `json:"timeoutSeconds,omitempty"`
	FailureThreshold    int32            `json:"failureThreshold,omitempty"`
}

type LifecycleHandler struct {
	Exec    *ExecAction    `json:"exec,omitempty"`
	HTTPGet *HTTPGetAction `json:"httpGet,omitempty"`
}

type Lifecycle struct {
	PostStart *LifecycleHandler `json:"postStart,omitempty"`
	PreStop   *LifecycleHandler `json:"preStop,omitempty"`
}

type SecurityContext struct {
	ReadOnlyRootFilesystem *bool  `json:"readOnlyRootFilesystem,omitempty"`
	RunAsNonRoot           *bool  `json:"runAsNonRoot,omitempty"`
	RunAsUser              *int64 `json:"runAsUser,omitempty"`
	RunAsGroup             *int64 `json:"runAsGroup,omitempty"`
}

// PodSecurityContext holds the pod-wide user and group settings; a container's own securityContext overrides them.
type PodSecurityContext struct {
	RunAsUser  *int64 `json:"runAsUser,omitempty"`
	RunAsGroup *int64 `json:"runAsGroup,omitempty"`
	FSGroup    *int64 `json:"fsGroup,omitempty"`
}

// VolumeMount places a pod volume in a container's filesystem.
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	SubPath   string `json:"subPath,omitempty"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

type Container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	ImagePullPolicy string           `json:"imagePullPolicy,omitempty"`
	Command         []string         `json:"command,omitempty"`
	Args            []string         `json:"args,omitempty"`
	Ports           []ContainerPort  `json:"ports,omitempty"`
	Env             []EnvVar         `json:"env,omitempty"`
	EnvFrom         []EnvFromSource  `json:"envFrom,omitempty"`
	Resources       Resources        `json:"resources,omitempty"`
	LivenessProbe   *Probe           `json:"livenessProbe,omitempty"`
	ReadinessProbe  *Probe           `json:"readinessProbe,omitempty"`
	StartupProbe    *Probe           `json:"startupProbe,omitempty"`
	SecurityContext *SecurityContext `json:"securityContext,omitempty"`
	Lifecycle       *Lifecycle       `json:"lifecycle,omitempty"`
	VolumeMounts    []VolumeMount    `json:"volumeMounts,omitempty"`
	// RestartPolicy is Always on a sidecar: an init container that keeps running beside the app containers.
	RestartPolicy string `json:"restartPolicy,omitempty"`
}

type KeyToPath struct {
	Key  string `json:"key"`
	Path string `json:"path,omitempty"`
	Mode *int32 `json:"mode,omitempty"`
}

type ConfigMapVolumeSource struct {
	Name        string      `json:"name"`
	Items       []KeyToPath `json:"items,omitempty"`
	Optional    *bool       `json:"optional,omitempty"`
	DefaultMode *int32      `json:"defaultMode,omitempty"`
}

type SecretVolumeSource struct {
	SecretName  string      `json:"secretName"`
	Items       []KeyToPath `json:"items,omitempty"`
	Optional    *bool       `json:"optional,omitempty"`
	DefaultMode *int32      `json:"defaultMode,omitempty"`
}

type HostPathVolumeSource struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"`
}

type EmptyDirVolumeSource struct {
	Medium    string `json:"medium,omitempty"`
	SizeLimit string `json:"sizeLimit,omitempty"`
}

type PVCVolumeSource struct {
	ClaimName string `json:"claimName"`
}

type ProjectedSource struct {
	ConfigMap *ConfigMapVolumeSource `json:"configMap,omitempty"`
	Secret    *struct {
		Name     string      `json:"name"`
		Items    []KeyToPath `json:"items,omitempty"`
		Optional *bool       `json:"optional,omitempty"`
	} `json:"secret,omitempty"`
	// The other sources put files of their own in the volume; only that they are there matters here.
	DownwardAPI         *struct{} `json:"downwardAPI,omitempty"`
	ServiceAccountToken *struct{} `json:"serviceAccountToken,omitempty"`
	ClusterTrustBundle  *struct{} `json:"clusterTrustBundle,omitempty"`
}

type ProjectedVolumeSource struct {
	Sources     []ProjectedSource `json:"sources,omitempty"`
	DefaultMode *int32            `json:"defaultMode,omitempty"`
}

type Volume struct {
	Name                  string                 `json:"name"`
	ConfigMap             *ConfigMapVolumeSource `json:"configMap,omitempty"`
	Secret                *SecretVolumeSource    `json:"secret,omitempty"`
	PersistentVolumeClaim *PVCVolumeSource       `json:"persistentVolumeClaim,omitempty"`
	Projected             *ProjectedVolumeSource `json:"projected,omitempty"`
	HostPath              *HostPathVolumeSource  `json:"hostPath,omitempty"`
	EmptyDir              *EmptyDirVolumeSource  `json:"emptyDir,omitempty"`
	DownwardAPI           *struct{}              `json:"downwardAPI,omitempty"`
}

type Toleration struct {
	Key      string `json:"key,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

type LocalObjectReference struct {
	Name string `json:"name"`
}

type PodSpec struct {
	NodeName           string                 `json:"nodeName,omitempty"`
	HostNetwork        bool                   `json:"hostNetwork,omitempty"`
	DNSPolicy          string                 `json:"dnsPolicy,omitempty"`
	SecurityContext    *PodSecurityContext    `json:"securityContext,omitempty"`
	SchedulerName      string                 `json:"schedulerName,omitempty"`
	NodeSelector       map[string]string      `json:"nodeSelector,omitempty"`
	ServiceAccountName string                 `json:"serviceAccountName,omitempty"`
	InitContainers     []Container            `json:"initContainers,omitempty"`
	Containers         []Container            `json:"containers"`
	Volumes            []Volume               `json:"volumes,omitempty"`
	Tolerations        []Toleration           `json:"tolerations,omitempty"`
	ImagePullSecrets   []LocalObjectReference `json:"imagePullSecrets,omitempty"`
	Affinity           json.RawMessage        `json:"affinity,omitempty"`
	PriorityClassName  string                 `json:"priorityClassName,omitempty"`
	// AutomountServiceAccountToken false leaves the ServiceAccount token out of the pod's containers.
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
	// ReadinessGates are extra conditions, set by a controller, that must be True for the pod to be Ready.
	ReadinessGates []PodReadinessGate `json:"readinessGates,omitempty"`
	// SchedulingGates hold the pod back from the scheduler until whatever set each gate removes it.
	SchedulingGates []SchedulingGate `json:"schedulingGates,omitempty"`
}

type PodReadinessGate struct {
	ConditionType string `json:"conditionType"`
}

type SchedulingGate struct {
	Name string `json:"name"`
}

type ContainerStateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type ContainerStateRunning struct {
	StartedAt time.Time `json:"startedAt"`
}

type ContainerStateTerminated struct {
	ExitCode   int32     `json:"exitCode"`
	Signal     int32     `json:"signal,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Message    string    `json:"message,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
}

type ContainerState struct {
	Waiting    *ContainerStateWaiting    `json:"waiting,omitempty"`
	Running    *ContainerStateRunning    `json:"running,omitempty"`
	Terminated *ContainerStateTerminated `json:"terminated,omitempty"`
}

type ContainerStatus struct {
	Name                 string         `json:"name"`
	Ready                bool           `json:"ready"`
	Started              *bool          `json:"started,omitempty"`
	RestartCount         int32          `json:"restartCount"`
	Image                string         `json:"image"`
	State                ContainerState `json:"state"`
	LastTerminationState ContainerState `json:"lastState"`
}

type PodStatus struct {
	Phase                 string            `json:"phase,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Message               string            `json:"message,omitempty"`
	Conditions            []Condition       `json:"conditions,omitempty"`
	InitContainerStatuses []ContainerStatus `json:"initContainerStatuses,omitempty"`
	ContainerStatuses     []ContainerStatus `json:"containerStatuses,omitempty"`
	StartTime             *time.Time        `json:"startTime,omitempty"`
}

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
	Status   PodStatus  `json:"status"`
}

func (p Pod) Ref() Ref {
	return Ref{Kind: "Pod", Namespace: p.Metadata.Namespace, Name: p.Metadata.Name}
}

// IsSidecar reports whether the named container is a sidecar: an init container with restartPolicy Always, which
// starts before the app containers and keeps running beside them instead of finishing.
func (p Pod) IsSidecar(name string) bool {
	for _, c := range p.Spec.InitContainers {
		if c.Name == name {
			return c.RestartPolicy == "Always"
		}
	}
	return false
}

// Mount is a path's place in a container's filesystem: the volume mount it is under and the volume behind it.
type Mount struct {
	VolumeMount
	Volume Volume
	// Rel is the path below the mount point, without a leading slash; empty when the path is the mount point.
	Rel string
}

// MountAt finds the volume mount of the named container that holds path: the one with the longest mount path that
// is the path or one of its parent directories.
func (p Pod) MountAt(container, path string) (Mount, bool) {
	var best Mount
	found := false
	for _, c := range append(append([]Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
		if c.Name != container {
			continue
		}
		for _, m := range c.VolumeMounts {
			mp := strings.TrimRight(m.MountPath, "/")
			if path != mp && !strings.HasPrefix(path, mp+"/") || found && len(mp) <= len(strings.TrimRight(best.MountPath, "/")) {
				continue
			}
			for _, v := range p.Spec.Volumes {
				if v.Name == m.Name {
					best, found = Mount{VolumeMount: m, Volume: v, Rel: strings.TrimPrefix(strings.TrimPrefix(path, mp), "/")}, true
				}
			}
		}
	}
	return best, found
}

// Source names what a volume is: "ConfigMap app-config", "emptyDir", "hostPath /var/lib/x" and so on.
func (v Volume) Source() string {
	switch {
	case v.ConfigMap != nil:
		return "ConfigMap " + v.ConfigMap.Name
	case v.Secret != nil:
		return "Secret " + v.Secret.SecretName
	case v.PersistentVolumeClaim != nil:
		return "PersistentVolumeClaim " + v.PersistentVolumeClaim.ClaimName
	case v.Projected != nil:
		return "projected volume"
	case v.HostPath != nil:
		return "hostPath " + v.HostPath.Path
	case v.EmptyDir != nil:
		return "emptyDir"
	case v.DownwardAPI != nil:
		return "downwardAPI volume"
	}
	return "volume"
}

// AlwaysReadOnly reports whether the kubelet mounts the volume read-only whatever the mount says: ConfigMap, Secret,
// projected and downward API volumes are.
func (v Volume) AlwaysReadOnly() bool {
	return v.ConfigMap != nil || v.Secret != nil || v.Projected != nil || v.DownwardAPI != nil
}

// RunAsUser is the user ID the named container runs as when the pod or container sets one; the container's own
// setting wins.
func (p Pod) RunAsUser(container string) (int64, bool) {
	for _, c := range append(append([]Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
		if c.Name == container && c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
			return *c.SecurityContext.RunAsUser, true
		}
	}
	if p.Spec.SecurityContext != nil && p.Spec.SecurityContext.RunAsUser != nil {
		return *p.Spec.SecurityContext.RunAsUser, true
	}
	return 0, false
}

// Ready reports whether the pod's Ready condition is True.
func (p Pod) Ready() bool {
	c, ok := FindCondition(p.Status.Conditions, "Ready")
	return ok && c.Status == "True"
}

// ---- Events ----

type EventSeries struct {
	Count            int32     `json:"count"`
	LastObservedTime time.Time `json:"lastObservedTime"`
}

type Event struct {
	Metadata       ObjectMeta `json:"metadata"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace,omitempty"`
		Name      string `json:"name"`
		UID       string `json:"uid,omitempty"`
		FieldPath string `json:"fieldPath,omitempty"`
	} `json:"involvedObject"`
	Reason         string       `json:"reason,omitempty"`
	Message        string       `json:"message,omitempty"`
	Type           string       `json:"type,omitempty"`
	Count          int32        `json:"count,omitempty"`
	FirstTimestamp *time.Time   `json:"firstTimestamp,omitempty"`
	LastTimestamp  *time.Time   `json:"lastTimestamp,omitempty"`
	EventTime      *time.Time   `json:"eventTime,omitempty"`
	Series         *EventSeries `json:"series,omitempty"`
}

// Last is when the event was last seen, from whichever timestamp the reporter filled in.
func (e Event) Last() time.Time {
	switch {
	case e.Series != nil && !e.Series.LastObservedTime.IsZero():
		return e.Series.LastObservedTime
	case e.LastTimestamp != nil && !e.LastTimestamp.IsZero():
		return *e.LastTimestamp
	case e.EventTime != nil && !e.EventTime.IsZero():
		return *e.EventTime
	case e.FirstTimestamp != nil:
		return *e.FirstTimestamp
	}
	return e.Metadata.CreationTimestamp
}

// Times is how often the event happened.
func (e Event) Times() int32 {
	if e.Series != nil && e.Series.Count > 0 {
		return e.Series.Count
	}
	if e.Count > 0 {
		return e.Count
	}
	return 1
}

// ---- Nodes ----

type Taint struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
}

type Node struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Taints        []Taint `json:"taints,omitempty"`
		Unschedulable bool    `json:"unschedulable,omitempty"`
	} `json:"spec"`
	Status struct {
		Conditions  []Condition       `json:"conditions,omitempty"`
		Allocatable map[string]string `json:"allocatable,omitempty"`
		Capacity    map[string]string `json:"capacity,omitempty"`
	} `json:"status"`
}

// ---- Services and endpoints ----

type ServicePort struct {
	Name       string      `json:"name,omitempty"`
	Port       int32       `json:"port"`
	TargetPort IntOrString `json:"targetPort"`
	Protocol   string      `json:"protocol,omitempty"`
}

type Service struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Type         string            `json:"type,omitempty"`
		Selector     map[string]string `json:"selector,omitempty"`
		Ports        []ServicePort     `json:"ports,omitempty"`
		ClusterIP    string            `json:"clusterIP,omitempty"`
		ExternalName string            `json:"externalName,omitempty"`
	} `json:"spec"`
	Status struct {
		LoadBalancer struct {
			Ingress []struct {
				IP       string `json:"ip,omitempty"`
				Hostname string `json:"hostname,omitempty"`
			} `json:"ingress,omitempty"`
		} `json:"loadBalancer,omitempty"`
	} `json:"status,omitempty"`
}

func (s Service) Ref() Ref {
	return Ref{Kind: "Service", Namespace: s.Metadata.Namespace, Name: s.Metadata.Name}
}

type EndpointConditions struct {
	Ready       *bool `json:"ready,omitempty"`
	Serving     *bool `json:"serving,omitempty"`
	Terminating *bool `json:"terminating,omitempty"`
}

type Endpoint struct {
	Addresses  []string           `json:"addresses"`
	Conditions EndpointConditions `json:"conditions"`
	TargetRef  *struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace,omitempty"`
		Name      string `json:"name"`
	} `json:"targetRef,omitempty"`
}

type EndpointSlice struct {
	Metadata  ObjectMeta `json:"metadata"`
	Endpoints []Endpoint `json:"endpoints"`
	Ports     []struct {
		Name *string `json:"name,omitempty"`
		Port *int32  `json:"port,omitempty"`
	} `json:"ports"`
}

// ServiceName is the Service the slice belongs to.
func (e EndpointSlice) ServiceName() string { return e.Metadata.Labels["kubernetes.io/service-name"] }

type IngressServiceBackend struct {
	Name string `json:"name"`
	Port struct {
		Name   string `json:"name,omitempty"`
		Number int32  `json:"number,omitempty"`
	} `json:"port"`
}

type IngressBackend struct {
	Service *IngressServiceBackend `json:"service,omitempty"`
}

type HTTPIngressPath struct {
	Path     string         `json:"path,omitempty"`
	PathType string         `json:"pathType,omitempty"`
	Backend  IngressBackend `json:"backend"`
}

type IngressRule struct {
	Host string `json:"host,omitempty"`
	HTTP *struct {
		Paths []HTTPIngressPath `json:"paths"`
	} `json:"http,omitempty"`
}

type IngressTLS struct {
	Hosts      []string `json:"hosts,omitempty"`
	SecretName string   `json:"secretName,omitempty"`
}

type Ingress struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		IngressClassName *string         `json:"ingressClassName,omitempty"`
		DefaultBackend   *IngressBackend `json:"defaultBackend,omitempty"`
		Rules            []IngressRule   `json:"rules,omitempty"`
		TLS              []IngressTLS    `json:"tls,omitempty"`
	} `json:"spec"`
}

func (i Ingress) Ref() Ref {
	return Ref{Kind: "Ingress", Namespace: i.Metadata.Namespace, Name: i.Metadata.Name}
}

type IngressClass struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Controller string `json:"controller"`
	} `json:"spec"`
}

// IsDefault reports whether the class is marked as the cluster default.
func (c IngressClass) IsDefault() bool {
	return c.Metadata.Annotations["ingressclass.kubernetes.io/is-default-class"] == "true"
}

// ---- Workloads ----

type PodTemplate struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
}

type WorkloadStatus struct {
	Replicas               int32       `json:"replicas,omitempty"`
	ReadyReplicas          int32       `json:"readyReplicas,omitempty"`
	AvailableReplicas      int32       `json:"availableReplicas,omitempty"`
	UpdatedReplicas        int32       `json:"updatedReplicas,omitempty"`
	UnavailableReplicas    int32       `json:"unavailableReplicas,omitempty"`
	DesiredNumberScheduled int32       `json:"desiredNumberScheduled,omitempty"`
	NumberReady            int32       `json:"numberReady,omitempty"`
	NumberUnavailable      int32       `json:"numberUnavailable,omitempty"`
	Conditions             []Condition `json:"conditions,omitempty"`
}

// Workload is a Deployment, ReplicaSet, StatefulSet or DaemonSet: the parts they share.
type Workload struct {
	Kind     string     `json:"kind"`
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Replicas *int32         `json:"replicas,omitempty"`
		Selector *LabelSelector `json:"selector,omitempty"`
		Template PodTemplate    `json:"template"`
		// ServiceName is a StatefulSet's governing Service, which gives its pods their DNS names.
		ServiceName string `json:"serviceName,omitempty"`
		// Paused stops a Deployment's rollouts until it is resumed.
		Paused bool `json:"paused,omitempty"`
		// PodManagementPolicy is a StatefulSet's: OrderedReady (the default) creates pod n only once pod n-1 is ready.
		PodManagementPolicy string `json:"podManagementPolicy,omitempty"`
	} `json:"spec"`
	Status WorkloadStatus `json:"status"`
}

func (w Workload) Ref() Ref {
	return Ref{Kind: w.Kind, Namespace: w.Metadata.Namespace, Name: w.Metadata.Name}
}

// Desired is the number of replicas the workload asks for (DaemonSets: the nodes it should run on).
func (w Workload) Desired() int32 {
	if w.Kind == "DaemonSet" {
		return w.Status.DesiredNumberScheduled
	}
	if w.Spec.Replicas == nil {
		return 1
	}
	return *w.Spec.Replicas
}

// Ready is the number of ready replicas.
func (w Workload) Ready() int32 {
	if w.Kind == "DaemonSet" {
		return w.Status.NumberReady
	}
	return w.Status.ReadyReplicas
}

type Job struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		BackoffLimit          *int32      `json:"backoffLimit,omitempty"`
		Completions           *int32      `json:"completions,omitempty"`
		ActiveDeadlineSeconds *int64      `json:"activeDeadlineSeconds,omitempty"`
		Suspend               *bool       `json:"suspend,omitempty"`
		Template              PodTemplate `json:"template"`
	} `json:"spec"`
	Status struct {
		StartTime  *time.Time  `json:"startTime,omitempty"`
		Active     int32       `json:"active,omitempty"`
		Succeeded  int32       `json:"succeeded,omitempty"`
		Failed     int32       `json:"failed,omitempty"`
		Conditions []Condition `json:"conditions,omitempty"`
	} `json:"status"`
}

func (j Job) Ref() Ref {
	return Ref{Kind: "Job", Namespace: j.Metadata.Namespace, Name: j.Metadata.Name}
}

// CronJob creates a Job on a schedule.
type CronJob struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Schedule          string  `json:"schedule"`
		TimeZone          *string `json:"timeZone,omitempty"`
		ConcurrencyPolicy string  `json:"concurrencyPolicy,omitempty"`
		Suspend           *bool   `json:"suspend,omitempty"`
		JobTemplate       struct {
			Spec struct {
				Template PodTemplate `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
	Status struct {
		Active []struct {
			Name string `json:"name"`
		} `json:"active,omitempty"`
		LastScheduleTime   *time.Time `json:"lastScheduleTime,omitempty"`
		LastSuccessfulTime *time.Time `json:"lastSuccessfulTime,omitempty"`
	} `json:"status"`
}

func (c CronJob) Ref() Ref {
	return Ref{Kind: "CronJob", Namespace: c.Metadata.Namespace, Name: c.Metadata.Name}
}

// ---- Autoscaling ----

type HorizontalPodAutoscaler struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		ScaleTargetRef struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"scaleTargetRef"`
		MinReplicas *int32 `json:"minReplicas,omitempty"`
		MaxReplicas int32  `json:"maxReplicas"`
	} `json:"spec"`
	Status struct {
		CurrentReplicas int32       `json:"currentReplicas,omitempty"`
		DesiredReplicas int32       `json:"desiredReplicas,omitempty"`
		Conditions      []Condition `json:"conditions,omitempty"`
	} `json:"status"`
}

func (h HorizontalPodAutoscaler) Ref() Ref {
	return Ref{Kind: "HorizontalPodAutoscaler", Namespace: h.Metadata.Namespace, Name: h.Metadata.Name}
}

type PodDisruptionBudget struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		MinAvailable   *IntOrString   `json:"minAvailable,omitempty"`
		MaxUnavailable *IntOrString   `json:"maxUnavailable,omitempty"`
		Selector       *LabelSelector `json:"selector,omitempty"`
	} `json:"spec"`
	Status struct {
		DisruptionsAllowed int32 `json:"disruptionsAllowed"`
		CurrentHealthy     int32 `json:"currentHealthy"`
		DesiredHealthy     int32 `json:"desiredHealthy"`
		ExpectedPods       int32 `json:"expectedPods"`
	} `json:"status"`
}

func (p PodDisruptionBudget) Ref() Ref {
	return Ref{Kind: "PodDisruptionBudget", Namespace: p.Metadata.Namespace, Name: p.Metadata.Name}
}

// ---- Storage ----

type PersistentVolumeClaim struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		StorageClassName *string  `json:"storageClassName,omitempty"`
		AccessModes      []string `json:"accessModes,omitempty"`
		VolumeName       string   `json:"volumeName,omitempty"`
		Resources        struct {
			Requests map[string]string `json:"requests,omitempty"`
		} `json:"resources,omitempty"`
	} `json:"spec"`
	Status struct {
		Phase      string            `json:"phase,omitempty"`
		Capacity   map[string]string `json:"capacity,omitempty"`
		Conditions []Condition       `json:"conditions,omitempty"`
	} `json:"status"`
}

func (p PersistentVolumeClaim) Ref() Ref {
	return Ref{Kind: "PersistentVolumeClaim", Namespace: p.Metadata.Namespace, Name: p.Metadata.Name}
}

type StorageClass struct {
	Metadata          ObjectMeta `json:"metadata"`
	Provisioner       string     `json:"provisioner"`
	VolumeBindingMode string     `json:"volumeBindingMode,omitempty"`
}

// IsDefault reports whether the class is marked as the cluster default.
func (s StorageClass) IsDefault() bool {
	return s.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"] == "true"
}

// ClaimReference is the claim a PersistentVolume is bound or reserved to. UID is set once it binds; a volume whose
// claim was deleted keeps the old UID, which stops a new claim of the same name from binding.
type ClaimReference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
}

type PersistentVolume struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		StorageClassName string            `json:"storageClassName,omitempty"`
		Capacity         map[string]string `json:"capacity,omitempty"`
		AccessModes      []string          `json:"accessModes,omitempty"`
		ClaimRef         *ClaimReference   `json:"claimRef,omitempty"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase,omitempty"`
	} `json:"status"`
}

// ---- Policy and quota ----

type NetworkPolicyPeer struct {
	PodSelector       *LabelSelector `json:"podSelector,omitempty"`
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`
	IPBlock           *struct {
		CIDR string `json:"cidr"`
	} `json:"ipBlock,omitempty"`
}

type NetworkPolicyPort struct {
	Port *IntOrString `json:"port,omitempty"`
}

type NetworkPolicyRule struct {
	From  []NetworkPolicyPeer `json:"from,omitempty"`
	To    []NetworkPolicyPeer `json:"to,omitempty"`
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

type NetworkPolicy struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		PodSelector LabelSelector       `json:"podSelector"`
		PolicyTypes []string            `json:"policyTypes,omitempty"`
		Ingress     []NetworkPolicyRule `json:"ingress,omitempty"`
		Egress      []NetworkPolicyRule `json:"egress,omitempty"`
	} `json:"spec"`
}

func (n NetworkPolicy) Ref() Ref {
	return Ref{Kind: "NetworkPolicy", Namespace: n.Metadata.Namespace, Name: n.Metadata.Name}
}

// AppliesToIngress reports whether the policy restricts ingress, following the API's defaulting: a policy with no
// policyTypes restricts ingress, and egress too when it has egress rules.
func (n NetworkPolicy) AppliesToIngress() bool {
	if len(n.Spec.PolicyTypes) == 0 {
		return true
	}
	for _, t := range n.Spec.PolicyTypes {
		if t == "Ingress" {
			return true
		}
	}
	return false
}

// AppliesToEgress reports whether the policy restricts egress: it lists Egress in policyTypes, or it has no
// policyTypes and has egress rules.
func (n NetworkPolicy) AppliesToEgress() bool {
	if len(n.Spec.PolicyTypes) == 0 {
		return len(n.Spec.Egress) > 0
	}
	for _, t := range n.Spec.PolicyTypes {
		if t == "Egress" {
			return true
		}
	}
	return false
}

type ResourceQuota struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   struct {
		Hard map[string]string `json:"hard,omitempty"`
		Used map[string]string `json:"used,omitempty"`
	} `json:"status"`
}

type ServiceAccount struct {
	Metadata                     ObjectMeta `json:"metadata"`
	AutomountServiceAccountToken *bool      `json:"automountServiceAccountToken,omitempty"`
}

// KeySet is a ConfigMap or Secret reduced to its name and key names. kube-diagnose never reads values: the
// collector asks kubectl for key names only, so Secret data never reaches this process.
type KeySet struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Type      string   `json:"type,omitempty"`
	Keys      []string `json:"keys"`
}

// Has reports whether the key exists.
func (k KeySet) Has(key string) bool {
	for _, x := range k.Keys {
		if x == key {
			return true
		}
	}
	return false
}

// List is the shape of `kubectl get <kind> -o json`.
type List[T any] struct {
	Items []T `json:"items"`
}
