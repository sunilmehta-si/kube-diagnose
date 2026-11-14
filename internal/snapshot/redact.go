package snapshot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// Redact returns a copy of the snapshot that can be shared: every namespace, object, node and container name is
// replaced by a pseudonym wherever it appears (fields, event messages, conditions), image repositories are
// replaced (tags are kept), IP addresses are replaced, the context name is dropped, and container logs are removed.
// Pseudonyms are keyed by a random secret that is not kept, so they cannot be reversed, and a name maps to the same
// pseudonym throughout one snapshot, so the diagnosis of the redacted snapshot is the diagnosis of the original.
func Redact(s *Snapshot) (*Snapshot, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return redactWithKey(s, key)
}

func redactWithKey(s *Snapshot, key []byte) (*Snapshot, error) {
	r := &redactor{key: key, names: map[string]string{}, images: map[string]string{}, ips: map[string]string{}}
	r.collect(s)
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(b, &tree); err != nil {
		return nil, err
	}
	r.gatherLabels(tree, false)
	r.build()
	tree = r.walk(tree)
	b, err = json.Marshal(tree)
	if err != nil {
		return nil, err
	}
	out := &Snapshot{}
	if err := json.Unmarshal(b, out); err != nil {
		return nil, err
	}
	out.Context, out.Redacted = "", true
	if len(s.Logs) > 0 {
		out.Gaps = append(out.Gaps, Gap{Resource: "logs", Error: fmt.Sprintf("%d container logs removed by redaction", len(s.Logs))})
	}
	out.Logs = []Log{}
	return out, nil
}

type redactor struct {
	key    []byte
	names  map[string]string // name -> pseudonym
	images map[string]string // image repository -> pseudonym
	ips    map[string]string
	nameRe *regexp.Regexp
}

func (r *redactor) pseudonym(prefix, value string) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(prefix + "\x00" + value))
	return prefix + "-" + hex.EncodeToString(m.Sum(nil))[:8]
}

func (r *redactor) addName(prefix, name string) {
	if name == "" || name == "*" || name == "default" || name == "kube-system" {
		return
	}
	if _, ok := r.names[name]; !ok {
		r.names[name] = r.pseudonym(prefix, name)
	}
}

func (r *redactor) addImage(image string) {
	repo := imageRepository(image)
	if repo != "" {
		if _, ok := r.images[repo]; !ok {
			r.images[repo] = "registry.invalid/" + r.pseudonym("image", repo)
		}
	}
}

// imageRepository is the image reference without its tag or digest.
func imageRepository(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		image = image[:i]
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		image = image[:i]
	}
	return image
}

// collect gathers every identifier the snapshot holds, longest pseudonymised first later.
func (r *redactor) collect(s *Snapshot) {
	for _, ns := range s.Namespaces {
		r.addName("ns", ns)
	}
	for _, p := range s.Pods {
		r.addName("ns", p.Metadata.Namespace)
		r.addName("pod", p.Metadata.Name)
		r.addName("node", p.Spec.NodeName)
		r.addName("sa", p.Spec.ServiceAccountName)
		for _, o := range p.Metadata.OwnerReferences {
			r.addName("owner", o.Name)
		}
		for _, c := range append(append([]kubeContainer{}, toContainers(p.Spec.InitContainers)...), toContainers(p.Spec.Containers)...) {
			r.addName("ctr", c.name)
			r.addImage(c.image)
		}
		for _, v := range p.Spec.Volumes {
			r.addName("vol", v.Name)
		}
	}
	for _, n := range s.Nodes {
		r.addName("node", n.Metadata.Name)
	}
	for _, w := range s.Workloads {
		r.addName("ns", w.Metadata.Namespace)
		r.addName(strings.ToLower(w.Kind), w.Metadata.Name)
	}
	for _, j := range s.Jobs {
		r.addName("job", j.Metadata.Name)
	}
	for _, x := range s.Services {
		r.addName("svc", x.Metadata.Name)
	}
	for _, x := range s.EndpointSlices {
		r.addName("eps", x.Metadata.Name)
	}
	for _, x := range s.Ingresses {
		r.addName("ing", x.Metadata.Name)
		for _, rule := range x.Spec.Rules {
			r.addName("host", rule.Host)
		}
	}
	for _, x := range s.HPAs {
		r.addName("hpa", x.Metadata.Name)
	}
	for _, x := range s.PDBs {
		r.addName("pdb", x.Metadata.Name)
	}
	for _, x := range s.PVCs {
		r.addName("pvc", x.Metadata.Name)
		r.addName("pv", x.Spec.VolumeName)
	}
	for _, x := range s.PVs {
		r.addName("pv", x.Metadata.Name)
	}
	for _, x := range s.NetworkPolicies {
		r.addName("netpol", x.Metadata.Name)
	}
	for _, x := range s.ResourceQuotas {
		r.addName("quota", x.Metadata.Name)
	}
	for _, x := range s.ServiceAccounts {
		r.addName("sa", x.Metadata.Name)
	}
	for _, x := range s.ConfigMaps {
		r.addName("cm", x.Name)
	}
	for _, x := range s.Secrets {
		r.addName("secret", x.Name)
	}
	for _, e := range s.Events {
		r.addName("ns", e.InvolvedObject.Namespace)
		r.addName("obj", e.InvolvedObject.Name)
		r.addName("event", e.Metadata.Name)
	}
}

type kubeContainer struct{ name, image string }

func toContainers(cs []kube.Container) []kubeContainer {
	out := make([]kubeContainer, len(cs))
	for i, c := range cs {
		out[i] = kubeContainer{c.Name, c.Image}
	}
	return out
}

var labelMaps = map[string]bool{"labels": true, "selector": true, "matchLabels": true, "nodeSelector": true}

// gatherLabels pseudonymises every label value before any text is rewritten, so a value is replaced the same way
// in labels, selectors and free text.
func (r *redactor) gatherLabels(v any, inLabels bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok && inLabels {
				if _, known := r.names[s]; !known && s != "" {
					r.names[s] = r.pseudonym("label", s)
				}
				continue
			}
			r.gatherLabels(val, labelMaps[k])
		}
	case []any:
		for _, e := range x {
			r.gatherLabels(e, false)
		}
	}
}

// build compiles one pattern that matches any collected name as a whole token, longest first, so that "web-rs-a"
// is replaced as a whole before "web".
func (r *redactor) build() {
	if len(r.names) == 0 {
		return
	}
	names := make([]string, 0, len(r.names))
	for n := range r.names {
		names = append(names, regexp.QuoteMeta(n))
	}
	sort.Slice(names, func(i, j int) bool {
		return len(names[i]) > len(names[j]) || len(names[i]) == len(names[j]) && names[i] < names[j]
	})
	// Names never contain "_", and the kubelet writes pods as name_namespace(uid), so "_" ends a name.
	r.nameRe = regexp.MustCompile(`(^|[^A-Za-z0-9.-])(` + strings.Join(names, "|") + `)($|[^A-Za-z0-9-]|\.[^A-Za-z0-9])`)
}

var reIPv4 = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)

func (r *redactor) text(s string) string {
	repos := make([]string, 0, len(r.images))
	for repo := range r.images {
		repos = append(repos, repo)
	}
	sort.Slice(repos, func(i, j int) bool { return len(repos[i]) > len(repos[j]) })
	for _, repo := range repos {
		s = strings.ReplaceAll(s, repo, r.images[repo])
	}
	s = reIPv4.ReplaceAllStringFunc(s, func(ip string) string {
		if _, ok := r.ips[ip]; !ok {
			m := hmac.New(sha256.New, r.key)
			m.Write([]byte("ip\x00" + ip))
			h := m.Sum(nil)
			r.ips[ip] = fmt.Sprintf("10.%d.%d.%d", h[0], h[1], h[2])
		}
		return r.ips[ip]
	})
	if r.nameRe == nil {
		return s
	}
	// A match consumes its delimiters, so run until nothing changes to catch adjacent names.
	for i := 0; i < 4; i++ {
		next := r.nameRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := r.nameRe.FindStringSubmatch(m)
			return sub[1] + r.names[sub[2]] + sub[3]
		})
		if next == s {
			break
		}
		s = next
	}
	return s
}

func (r *redactor) walk(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if labelMaps[k] {
				out[k] = r.labels(val)
				continue
			}
			out[k] = r.walk(val)
		}
		return out
	case []any:
		for i := range x {
			x[i] = r.walk(x[i])
		}
		return x
	case string:
		return r.text(x)
	}
	return v
}

// labels keeps label keys and redacts values, so selectors still match the pods they matched.
func (r *redactor) labels(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return r.walk(v)
	}
	out := make(map[string]any, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok && r.names[s] != "" {
			out[k] = r.names[s]
			continue
		}
		out[k] = r.walk(val)
	}
	return out
}
