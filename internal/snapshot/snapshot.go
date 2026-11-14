// Package snapshot is everything kube-diagnose read from a cluster, in one file. A diagnosis is a pure function of a
// snapshot, so `kube-diagnose record` on one machine and `kube-diagnose --snapshot` on another give the same answer,
// and the tests run on recorded clusters.
package snapshot

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// SchemaVersion changes when a field is renamed or its meaning changes; adding a field does not change it.
const SchemaVersion = 1

// Log is the tail of one container's log, as `kubectl logs` printed it.
type Log struct {
	Pod       kube.Ref `json:"pod"`
	Container string   `json:"container"`
	Previous  bool     `json:"previous"` // the log of the last terminated instance, not the running one
	Lines     []string `json:"lines"`
}

// Gap is something the collector could not read, usually for lack of RBAC permission. A diagnosis that needed it
// says so instead of guessing.
type Gap struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Error     string `json:"error"`
}

type Snapshot struct {
	SchemaVersion int       `json:"schemaVersion"`
	Tool          string    `json:"tool"`
	CollectedAt   time.Time `json:"collectedAt"`
	Context       string    `json:"context,omitempty"`
	ServerVersion string    `json:"serverVersion,omitempty"`
	// Namespaces read; empty means all namespaces.
	Namespaces []string `json:"namespaces,omitempty"`
	Redacted   bool     `json:"redacted,omitempty"`

	Pods            []kube.Pod                     `json:"pods"`
	Events          []kube.Event                   `json:"events"`
	Nodes           []kube.Node                    `json:"nodes"`
	Services        []kube.Service                 `json:"services"`
	EndpointSlices  []kube.EndpointSlice           `json:"endpointSlices"`
	Workloads       []kube.Workload                `json:"workloads"`
	Jobs            []kube.Job                     `json:"jobs"`
	HPAs            []kube.HorizontalPodAutoscaler `json:"horizontalPodAutoscalers"`
	PVCs            []kube.PersistentVolumeClaim   `json:"persistentVolumeClaims"`
	PVs             []kube.PersistentVolume        `json:"persistentVolumes"`
	StorageClasses  []kube.StorageClass            `json:"storageClasses"`
	NetworkPolicies []kube.NetworkPolicy           `json:"networkPolicies"`
	ResourceQuotas  []kube.ResourceQuota           `json:"resourceQuotas"`
	ServiceAccounts []kube.ServiceAccount          `json:"serviceAccounts"`
	ConfigMaps      []kube.KeySet                  `json:"configMaps"`
	Secrets         []kube.KeySet                  `json:"secrets"`
	Logs            []Log                          `json:"logs"`
	Gaps            []Gap                          `json:"gaps,omitempty"`
}

// Read loads a snapshot written by Write; a name ending in .gz is gunzipped.
func Read(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}
	return Decode(r)
}

// Decode reads a snapshot from JSON.
func Decode(r io.Reader) (*Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(r)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("not a kube-diagnose snapshot: %w", err)
	}
	if s.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("snapshot schema %d; this kube-diagnose reads schema %d", s.SchemaVersion, SchemaVersion)
	}
	return &s, nil
}

// Write saves the snapshot as indented JSON, gzipped when the name ends in .gz. The file is readable by the owner
// only: it holds object names, labels and log lines.
func Write(path string, s *Snapshot) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	var w io.Writer = f
	var gz *gzip.Writer
	if strings.HasSuffix(path, ".gz") {
		gz = gzip.NewWriter(f)
		w = gz
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	err = enc.Encode(s)
	if gz != nil {
		if cerr := gz.Close(); err == nil {
			err = cerr
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
