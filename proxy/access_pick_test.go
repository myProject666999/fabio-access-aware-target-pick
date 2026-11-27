package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabiolb/fabio/config"
	"github.com/fabiolb/fabio/route"

	"google.golang.org/grpc/metadata"
)

// accessTestProxy returns an HTTPProxy whose lookup uses the given table.
func accessTestProxy(tbl route.Table) *HTTPProxy {
	gc := route.NewGlobCache(100)
	return &HTTPProxy{
		Transport: http.DefaultTransport,
		Lookup: func(r *http.Request) *route.Target {
			return tbl.Lookup(r, route.Picker["rr"], route.Matcher["prefix"], gc, false)
		},
	}
}

func serveAccess(p *HTTPProxy, host, remoteAddr, xff string) (int, string) {
	req := httptest.NewRequest("GET", "http://"+host+"/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	return w.Code, strings.TrimSpace(string(body))
}

func TestHTTPProxyAccessAwarePick(t *testing.T) {
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "a")
	}))
	defer srvA.Close()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "b")
	}))
	defer srvB.Close()
	srvD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "d")
	}))
	defer srvD.Close()

	// table 1: a and b only - every source is either routed to the one
	// target that allows it or denied altogether
	tbl, err := route.NewTable(bytes.NewBufferString(`
route add svc foo.com/ ` + srvA.URL + `/ opts "allow=ip:10.0.0.0/8"
route add svc foo.com/ ` + srvB.URL + `/ opts "allow=ip:192.168.0.0/16"
route add other / ` + srvD.URL + `/
`))
	if err != nil {
		t.Fatal(err)
	}
	p := accessTestProxy(tbl)

	tests := []struct {
		desc       string
		host       string
		remoteAddr string
		xff        string
		wantCode   int
		wantBody   string
	}{
		{"allowed by a only", "foo.com", "10.1.2.3:5000", "", 200, "a"},
		{"allowed by b only", "foo.com", "192.168.1.1:5000", "", 200, "b"},
		{"ipv4-in-ipv6 remote", "foo.com", "[::ffff:10.1.2.3]:5000", "", 200, "a"},
		{"excluded by both", "foo.com", "172.16.0.1:5000", "", 403, "access denied"},
		{"allowed remote but denied xff element", "foo.com", "10.1.2.3:5000", "10.1.2.3, 172.16.0.9", 403, "access denied"},
		{"hostless route still works", "bar.com", "172.16.0.1:5000", "", 200, "d"},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			code, body := serveAccess(p, tt.host, tt.remoteAddr, tt.xff)
			if code != tt.wantCode || body != tt.wantBody {
				t.Fatalf("got %d %q, want %d %q", code, body, tt.wantCode, tt.wantBody)
			}
		})
	}

	// table 2: with an additional target d without rules, sources allowed
	// by neither a nor b fall to d
	tbl, err = route.NewTable(bytes.NewBufferString(`
route add svc foo.com/ ` + srvA.URL + `/ opts "allow=ip:10.0.0.0/8"
route add svc foo.com/ ` + srvB.URL + `/ opts "allow=ip:192.168.0.0/16"
route add svc foo.com/ ` + srvD.URL + `/
`))
	if err != nil {
		t.Fatal(err)
	}
	p = accessTestProxy(tbl)

	tests2 := []struct {
		desc       string
		remoteAddr string
		wantCode   int
		wantBody   string
	}{
		{"unruled target takes the rest", "172.16.0.1:5000", 200, "d"},
		{"ipv6 remote falls to unruled target", "[2001:db8::1]:443", 200, "d"},
	}
	for _, tt := range tests2 {
		t.Run(tt.desc, func(t *testing.T) {
			code, body := serveAccess(p, "foo.com", tt.remoteAddr, "")
			if code != tt.wantCode || body != tt.wantBody {
				t.Fatalf("got %d %q, want %d %q", code, body, tt.wantCode, tt.wantBody)
			}
		})
	}
}

// TestHTTPProxyAccessAwarePickAllExcluded verifies that a request whose
// source is excluded by every target of a host-specific route gets a 403
// and is not rerouted to the hostless catch-all route.
func TestHTTPProxyAccessAwarePickAllExcluded(t *testing.T) {
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "a")
	}))
	defer srvA.Close()
	srvOther := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "other")
	}))
	defer srvOther.Close()

	tbl, err := route.NewTable(bytes.NewBufferString(`
route add svc foo.com/ ` + srvA.URL + `/ opts "allow=ip:10.0.0.0/8"
route add other / ` + srvOther.URL + `/
`))
	if err != nil {
		t.Fatal(err)
	}
	p := accessTestProxy(tbl)

	if code, body := serveAccess(p, "foo.com", "172.16.0.1:5000", ""); code != 403 {
		t.Fatalf("got %d %q, want 403 (no fallthrough to hostless route)", code, body)
	}
	if code, body := serveAccess(p, "foo.com", "10.1.2.3:5000", ""); code != 200 || body != "a" {
		t.Fatalf("got %d %q, want 200 a", code, body)
	}
}

// TestGRPCAccessRulesIgnored verifies that gRPC target selection is
// unchanged by access-aware picking: the gRPC lookup builds a request
// without RemoteAddr, which is treated as allowed, so targets with rules
// keep receiving their share exactly as before.
func TestGRPCAccessRulesIgnored(t *testing.T) {
	tbl, err := route.NewTable(bytes.NewBufferString(`
route add svc / http://a:1/ opts "allow=ip:10.0.0.0/8"
route add svc / http://b:2/ opts "allow=ip:192.168.0.0/16"
`))
	if err != nil {
		t.Fatal(err)
	}
	old := route.GetTable()
	route.SetTable(tbl)
	defer route.SetTable(old)

	cfg := &config.Config{}
	cfg.Proxy.Strategy = "rr"
	cfg.Proxy.Matcher = "prefix"
	g := GrpcProxyInterceptor{Config: cfg, GlobCache: route.NewGlobCache(100)}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{})
	got := map[string]int{}
	for i := 0; i < 4; i++ {
		target, err := g.lookup(ctx, "/foo.bar.Service/Method")
		if err != nil {
			t.Fatal(err)
		}
		if target == nil {
			t.Fatal("got nil target")
		}
		got[target.URL.Host]++
	}
	// both targets carry rules, yet rr must rotate across them exactly as
	// it did before access-aware picking was introduced
	if got["a:1"] != 2 || got["b:2"] != 2 {
		t.Fatalf("got %v, want 2x a:1 and 2x b:2", got)
	}
}
