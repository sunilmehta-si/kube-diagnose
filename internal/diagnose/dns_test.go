package diagnose

import (
	"testing"

	"github.com/sunilmehta-si/kube-diagnose/internal/kube"
	"github.com/sunilmehta-si/kube-diagnose/internal/snapshot"
)

// The lines are what each client prints when DNS does not know a name.
func TestUnresolvedHost(t *testing.T) {
	for line, want := range map[string]string{
		"wget: bad address 'db:5432'":                                                                 "db",
		"curl: (6) Could not resolve host: payments.shop":                                             "payments.shop",
		`dial tcp: lookup orders on 10.96.0.10:53: no such host`:                                      "orders",
		`dial tcp: lookup orders.shop.svc.cluster.local: no such host`:                                "orders.shop.svc.cluster.local",
		`NameResolutionError: Failed to resolve 'redis' ([Errno -2] Name or service not known)`:       "redis",
		"Error: getaddrinfo ENOTFOUND mongo":                                                          "mongo",
		"java.net.UnknownHostException: kafka":                                                        "kafka",
		`psql: error: could not translate host name "postgres" to address: Name or service not known`: "postgres",
		"** server can't find db.: NXDOMAIN":                                                          "db",
		`dial tcp: lookup db on 10.96.0.10:53: read udp 10.244.0.9:41234->10.96.0.10:53: i/o timeout`: "db",
		"connection refused": "",
	} {
		if got, _ := unresolvedHost([]string{line}); got != want {
			t.Errorf("%q: got %q, want %q", line, got, want)
		}
	}
}

func TestServiceName(t *testing.T) {
	for host, want := range map[string][2]string{
		"db":                            {"shop", "db"},
		"db.billing":                    {"billing", "db"},
		"db.billing.svc":                {"billing", "db"},
		"db.billing.svc.cluster.local":  {"billing", "db"},
		"DB.Billing.svc.cluster.local.": {"", ""}, // a trailing dot is trimmed by unresolvedHost, not here
		"api.example.com":               {"", ""},
	} {
		ns, svc, ok := serviceName("shop", host)
		if ok != (want[1] != "") || ns != want[0] || svc != want[1] {
			t.Errorf("%s: got %s/%s %v, want %v", host, ns, svc, ok, want)
		}
	}
}

func TestMissingServiceNeedsTheNamespaceRead(t *testing.T) {
	s := snap()
	s.Services = []kube.Service{service("db", map[string]string{"app": "db"}, port(5432))}
	ix := newIndex(s)
	lines := []string{"wget: bad address 'db:5432'"}
	if _, _, _, ok := ix.missingService("shop", lines); ok {
		t.Error("Service db exists")
	}
	if ns, svc, _, ok := ix.missingService("shop", []string{"wget: bad address 'cache:6379'"}); !ok || ns != "shop" || svc != "cache" {
		t.Errorf("cache is missing: %s/%s %v", ns, svc, ok)
	}
	if _, _, _, ok := ix.missingService("shop", []string{"wget: bad address 'cache.billing'"}); ok {
		t.Error("namespace billing was not collected, so the snapshot cannot say cache is missing there")
	}
	s.Gaps = []snapshot.Gap{{Resource: "services", Error: "forbidden"}}
	if _, _, _, ok := newIndex(s).missingService("shop", []string{"wget: bad address 'cache:6379'"}); ok {
		t.Error("the Service list was not read")
	}
}

// curl 8 says "Couldn't connect to server" where older versions said "Connection refused".
func TestRefusedServiceByCurl(t *testing.T) {
	s := snap()
	s.Services = []kube.Service{service("db", map[string]string{"app": "db"}, port(5432))}
	ix := newIndex(s)
	for _, line := range []string{
		"curl: (7) Failed to connect to db port 5432 after 2 ms: Couldn't connect to server",
		"curl: (7) Failed to connect to db port 5432: Connection refused",
	} {
		if svc, _, ok := refusedService(ix, "shop", []string{line}); !ok || svc.Metadata.Name != "db" {
			t.Errorf("%q: %v %v", line, svc.Metadata.Name, ok)
		}
	}
}
