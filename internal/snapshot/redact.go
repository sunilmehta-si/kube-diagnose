package snapshot

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
)

// Redact returns a copy of the snapshot that can be shared: every namespace, object, node and container name is
// replaced by a pseudonym wherever it appears (fields, event messages, conditions), image repositories are
// replaced (tags are kept; Docker Hub's official base images, busybox or ubuntu, are kept whole), IP addresses are replaced, the context name is dropped, and container logs are removed.
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
	// kept are the official base images, left as they are, tag and digest too: a name inside one (a volume called
	// docker, in docker.io/library/busybox; a pod index label 1, in tag 1.37.0) must not be replaced there.
	kept   []string
	ips    map[string]string
	nameRe *regexp.Regexp
	// claimPrefixes maps POD-ENTRY, the start of a claim made from a template for a pod (POD-ENTRY-xxxxx), to the
	// pod's pseudonym and the entry: such a claim may be named in a message before it exists, or after it is gone.
	claimPrefixes map[string]string
	claimRe       *regexp.Regexp
	// svcRe finds a name in a cluster DNS name, service.namespace.svc, where a dot comes before it.
	svcRe *regexp.Regexp
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

// addHost names a Gateway API hostname label by label, so that a wildcard listener (*.shop.example.com) still covers
// the route hostnames under it (pay.shop.example.com) after redaction, and KD367 judges them alike.
func (r *redactor) addHost(h string) {
	if _, ok := r.names[h]; ok || h == "" || h == "*" {
		return
	}
	labels := strings.Split(h, ".")
	for i, l := range labels {
		if l != "*" {
			labels[i] = r.pseudonym("h", l)
		}
	}
	r.names[h] = strings.Join(labels, ".")
}

// addSliceName gives an EndpointSlice named for a Service (the Service's name and a suffix, as slices are named) the
// Service's pseudonym and the same suffix, so the slice still reads as the Service's after redaction; KD264 links a
// slice that lacks its label by that name. Services must be added first.
func (r *redactor) addSliceName(name string) {
	if _, ok := r.names[name]; ok || name == "" {
		return
	}
	best := ""
	for svc, pseudo := range r.names {
		if strings.HasPrefix(pseudo, "svc-") && len(svc) > len(best) && len(name) > len(svc)+1 && strings.HasPrefix(name, svc) && name[len(svc)] == '-' {
			best = svc
		}
	}
	if best == "" {
		r.addName("eps", name)
		return
	}
	suffix := name[len(best)+1:]
	if !reGeneratedSuffix.MatchString(suffix) {
		suffix = r.pseudonym("eps", name)[len("eps-"):] // a suffix someone wrote may say something: replaced too
	}
	r.names[name] = r.names[best] + "-" + suffix
}

// reGeneratedSuffix is a suffix a controller or a person adds to tell slices apart: a number or a few random characters.
var reGeneratedSuffix = regexp.MustCompile(`^[a-z0-9]{1,5}$`)

func (r *redactor) addImage(image string) {
	repo := imageRepository(image)
	// An official base image names nothing of the cluster's, and a diagnosis reads it (KD315).
	if repo != "" && kube.OfficialBaseImage(repo) != "" && !slices.Contains(r.kept, image) {
		r.kept = append(r.kept, image)
		sort.Slice(r.kept, func(i, j int) bool { return len(r.kept[i]) > len(r.kept[j]) })
	}
	if repo != "" && kube.OfficialBaseImage(repo) == "" {
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
	for _, ns := range s.NamespaceObjects {
		r.addName("ns", ns.Metadata.Name)
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
		// Objects the pod refers to are named even when they do not exist, which is when a diagnosis names them.
		for _, c := range append(append([]kube.Container{}, p.Spec.InitContainers...), p.Spec.Containers...) {
			for _, e := range c.EnvFrom {
				if e.ConfigMapRef != nil {
					r.addName("cm", e.ConfigMapRef.Name)
				}
				if e.SecretRef != nil {
					r.addName("secret", e.SecretRef.Name)
				}
			}
			// A probe's host may name a machine; an IP address is replaced with the other addresses.
			for _, pr := range []*kube.Probe{c.LivenessProbe, c.ReadinessProbe, c.StartupProbe} {
				if pr != nil && pr.HTTPGet != nil && !reIPv4.MatchString(pr.HTTPGet.Host) && pr.HTTPGet.Host != "localhost" {
					r.addName("host", pr.HTTPGet.Host)
				}
				if pr != nil && pr.TCPSocket != nil && !reIPv4.MatchString(pr.TCPSocket.Host) && pr.TCPSocket.Host != "localhost" {
					r.addName("host", pr.TCPSocket.Host)
				}
			}
			for _, e := range c.Env {
				if e.ValueFrom != nil && e.ValueFrom.ConfigMapKeyRef != nil {
					r.addName("cm", e.ValueFrom.ConfigMapKeyRef.Name)
				}
				if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
					r.addName("secret", e.ValueFrom.SecretKeyRef.Name)
				}
			}
		}
		for _, ref := range p.Spec.ImagePullSecrets {
			r.addName("secret", ref.Name)
		}
		r.addName("pc", p.Spec.PriorityClassName)
		for _, v := range p.Spec.Volumes {
			r.addName("vol", v.Name)
			if v.ConfigMap != nil {
				r.addName("cm", v.ConfigMap.Name)
			}
			if v.Secret != nil {
				r.addName("secret", v.Secret.SecretName)
			}
			if v.PersistentVolumeClaim != nil {
				r.addName("pvc", v.PersistentVolumeClaim.ClaimName)
			}
			if v.Projected != nil {
				for _, src := range v.Projected.Sources {
					if src.ConfigMap != nil {
						r.addName("cm", src.ConfigMap.Name)
					}
					if src.Secret != nil {
						r.addName("secret", src.Secret.Name)
					}
				}
			}
		}
	}
	for _, n := range s.Nodes {
		r.addName("node", n.Metadata.Name)
	}
	for _, w := range s.Workloads {
		r.addName("ns", w.Metadata.Namespace)
		r.addName(strings.ToLower(w.Kind), w.Metadata.Name)
		r.addName("svc", w.Spec.ServiceName)
	}
	for _, c := range s.CronJobs {
		r.addName("cronjob", c.Metadata.Name)
		for _, a := range c.Status.Active {
			r.addName("job", a.Name)
		}
	}
	for _, j := range s.Jobs {
		r.addName("job", j.Metadata.Name)
		for _, o := range j.Metadata.OwnerReferences {
			r.addName("owner", o.Name)
		}
	}
	for _, w := range s.Workloads {
		for _, o := range w.Metadata.OwnerReferences {
			r.addName("owner", o.Name)
		}
	}
	for _, x := range s.Services {
		r.addName("svc", x.Metadata.Name)
		for _, lb := range x.Status.LoadBalancer.Ingress {
			r.addName("host", lb.Hostname)
		}
	}
	for _, x := range s.EndpointSlices {
		r.addSliceName(x.Metadata.Name)
	}
	for _, x := range s.Ingresses {
		r.addName("ing", x.Metadata.Name)
		for _, rule := range x.Spec.Rules {
			r.addName("host", rule.Host)
			if rule.HTTP != nil {
				for _, p := range rule.HTTP.Paths {
					if p.Backend.Service != nil {
						r.addName("svc", p.Backend.Service.Name)
					}
				}
			}
		}
		if b := x.Spec.DefaultBackend; b != nil && b.Service != nil {
			r.addName("svc", b.Service.Name)
		}
		for _, t := range x.Spec.TLS {
			r.addName("secret", t.SecretName)
			for _, h := range t.Hosts {
				r.addName("host", h)
			}
		}
		if x.Spec.IngressClassName != nil {
			r.addName("ingclass", *x.Spec.IngressClassName)
		}
	}
	// The Gateway API's objects and what they name. Listener names (http, https) are left: they are a Gateway's
	// section names, chosen from a few words, and replacing them would replace those words everywhere.
	for _, x := range s.GatewayClasses {
		r.addName("gwclass", x.Metadata.Name)
	}
	for _, x := range s.Gateways {
		r.addName("gw", x.Metadata.Name)
		r.addName("gwclass", x.Spec.GatewayClassName) // the class it names may not exist, and is then named
		for _, l := range x.Spec.Listeners {
			r.addHost(l.Hostname)
			if l.TLS != nil {
				for _, c := range l.TLS.CertificateRefs {
					r.addName("ns", c.Namespace)
					r.addName("secret", c.Name)
				}
			}
		}
	}
	for _, x := range s.LocalQueues {
		r.addName("lq", x.Metadata.Name)
		r.addName("cq", x.Spec.ClusterQueue)
	}
	for _, x := range s.BackendTLSPolicies {
		r.addName("btls", x.Metadata.Name)
		for _, t := range x.Spec.TargetRefs {
			r.addName("svc", t.Name)
		}
		for _, c := range x.Spec.Validation.CACertificateRefs {
			r.addName("cm", c.Name)
		}
		r.addHost(x.Spec.Validation.Hostname)
	}
	for _, x := range s.ReferenceGrants {
		r.addName("refgrant", x.Metadata.Name)
		for _, f := range x.Spec.From {
			r.addName("ns", f.Namespace)
		}
		for _, t := range x.Spec.To {
			r.addName("svc", t.Name)
		}
	}
	for _, x := range s.Routes {
		r.addName("route", x.Metadata.Name)
		for _, h := range x.Spec.Hostnames {
			r.addHost(h)
		}
		for _, p := range x.Spec.ParentRefs {
			r.addName("ns", p.Namespace)
			r.addName("gw", p.Name)
		}
		for _, rule := range x.Spec.Rules {
			for _, b := range rule.BackendRefs {
				r.addName("ns", b.Namespace)
				r.addName("svc", b.Name)
			}
		}
	}
	// Dynamic resource allocation: claims and templates are named, as is a pod's reference to one that may not
	// exist. The name a pod gives a claim in its own spec (gpu) is left, as are DeviceClass and driver names: like a
	// StorageClass's, they name a kind of device, not something of the cluster's.
	for _, p := range s.Pods {
		for _, c := range p.Spec.ResourceClaims {
			r.addName("claim", c.ResourceClaimName)
			r.addName("claimtpl", c.ResourceClaimTemplateName)
			if c.ResourceClaimTemplateName != "" && p.Metadata.Name != "" {
				if r.claimPrefixes == nil {
					r.claimPrefixes = map[string]string{}
				}
				r.claimPrefixes[p.Metadata.Name+"-"+c.Name] = r.names[p.Metadata.Name] + "-" + c.Name
			}
		}
		for _, c := range p.Status.ResourceClaimStatuses {
			r.addName("claim", c.ResourceClaimName)
		}
	}
	for _, x := range s.ResourceClaims {
		r.addName("claim", x.Metadata.Name)
		for _, o := range x.Metadata.OwnerReferences {
			r.addName("owner", o.Name)
		}
	}
	for _, x := range s.ResourceClaimTemplates {
		r.addName("claimtpl", x.Metadata.Name)
	}
	for _, x := range s.ResourceSlices {
		r.addName("rslice", x.Metadata.Name)
		r.addName("node", x.Spec.NodeName)
		r.addName("pool", x.Spec.Pool.Name)
	}
	for _, x := range s.HPAs {
		r.addName("hpa", x.Metadata.Name)
		r.addName("target", x.Spec.ScaleTargetRef.Name)
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
		if x.Spec.ClaimRef != nil {
			r.addName("pvc", x.Spec.ClaimRef.Name) // the claim it is reserved for may be gone, and is then named
		}
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
	for _, x := range s.Roles {
		r.addName("role", x.Metadata.Name)
	}
	for _, x := range s.RoleBindings {
		r.addName("ns", x.Metadata.Namespace)
		r.addName("rolebinding", x.Metadata.Name)
		if !builtinClusterRole(x.RoleRef.Name) {
			r.addName("role", x.RoleRef.Name) // the role it grants may not exist, and is then named
		}
		for _, sub := range x.Subjects {
			r.addName("ns", sub.Namespace)
			r.addName("subject", sub.Name)
		}
	}
	for _, x := range s.ClusterRoles {
		if !builtinClusterRole(x) {
			r.addName("role", x)
		}
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
	// A CronJob's runs are named for it, NAME-<the minute it was scheduled for>, and a diagnosis reads that: a run
	// that is deleted leaves only its name in events (KD297). The run keeps its CronJob's pseudonym and its suffix,
	// a time that says nothing of the cluster.
	for _, c := range s.CronJobs {
		pseudo, prefix := r.names[c.Metadata.Name], c.Metadata.Name+"-"
		for n := range r.names {
			if suffix, ok := strings.CutPrefix(n, prefix); ok && pseudo != "" && reRunSuffix.MatchString(suffix) {
				r.names[n] = pseudo + "-" + suffix
			}
		}
	}
}

var reRunSuffix = regexp.MustCompile(`^\d{6,}$`)

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
	if len(r.claimPrefixes) > 0 {
		var ps []string
		for p := range r.claimPrefixes {
			ps = append(ps, regexp.QuoteMeta(p))
		}
		sort.Slice(ps, func(i, j int) bool { return len(ps[i]) > len(ps[j]) || len(ps[i]) == len(ps[j]) && ps[i] < ps[j] })
		r.claimRe = regexp.MustCompile(`(` + strings.Join(ps, "|") + `)-([a-z0-9]{5})\b`)
	}
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
	r.svcRe = regexp.MustCompile(`(\.)(` + strings.Join(names, "|") + `)(\.svc(?:$|[^A-Za-z0-9-]))`)
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
		// The loopback and "every address" forms name no machine, and a diagnosis reads them: an app bound to
		// 127.0.0.1 is a fault (KD215), one bound to 0.0.0.0 is not.
		if strings.HasPrefix(ip, "127.") || ip == "0.0.0.0" {
			return ip
		}
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
	// A claim made for a pod from a template keeps the pod's pseudonym, the entry and the generated suffix.
	if r.claimRe != nil {
		s = r.claimRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := r.claimRe.FindStringSubmatch(m)
			return r.claimPrefixes[sub[1]] + "-" + sub[2]
		})
	}
	// Kept image repositories are set aside while names are replaced, then put back.
	for i, image := range r.kept {
		s = strings.ReplaceAll(s, image, keptToken(i))
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
	s = r.svcRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := r.svcRe.FindStringSubmatch(m)
		return sub[1] + r.names[sub[2]] + sub[3]
	})
	for i, image := range r.kept {
		s = strings.ReplaceAll(s, keptToken(i), image)
	}
	return s
}

// keptToken stands in for a kept image while names are replaced: control characters only, which no name or label
// value holds.
func keptToken(i int) string { return "\x00" + strings.Repeat("\x01", i+1) + "\x00" }

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

// builtinClusterRole reports whether a ClusterRole is one every cluster has. Their names say nothing about the
// cluster, and several are everyday words (view, edit, admin) that must not be replaced wherever they occur.
func builtinClusterRole(name string) bool {
	switch name {
	case "admin", "edit", "view", "cluster-admin":
		return true
	}
	return strings.HasPrefix(name, "system:")
}
