package route

import (
	"bytes"
	"fmt"
	"log"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newAccessTestTable builds the table from the opening example:
// a allows 10.0.0.0/8, b allows 192.168.0.0/16, both with dynamic weights.
func newAccessTestTable(t *testing.T, extra ...string) Table {
	t.Helper()
	lines := []string{
		`route add svc foo.com/ http://a:1/ opts "allow=ip:10.0.0.0/8"`,
		`route add svc foo.com/ http://b:2/ opts "allow=ip:192.168.0.0/16"`,
	}
	lines = append(lines, extra...)
	tbl, err := NewTable(bytes.NewBufferString(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	return tbl
}

// lookupHost counts targets selected by tbl.Lookup for n requests from the
// given remote address / xff combination using the rr picker.
func pickDistribution(t *testing.T, tbl Table, host, remoteAddr, xff string, n int) map[string]int {
	t.Helper()
	gc := NewGlobCache(100)
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		req := httptest.NewRequest("GET", "http://"+host+"/", nil)
		req.RemoteAddr = remoteAddr
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		tg := tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false)
		if tg == nil {
			counts["<nil>"]++
			continue
		}
		counts[tg.URL.Host]++
	}
	return counts
}

func TestAccessAwarePickBasicDistribution(t *testing.T) {
	tbl := newAccessTestTable(t)

	// 10.1.2.3 is allowed by a only: everything goes to a
	if got := pickDistribution(t, tbl, "foo.com", "10.1.2.3:5000", "", 100); got["a:1"] != 100 {
		t.Fatalf("10.1.2.3: got %v, want all 100 on a:1", got)
	}
	// 192.168.1.1 is allowed by b only: everything goes to b
	if got := pickDistribution(t, tbl, "foo.com", "192.168.1.1:5000", "", 100); got["b:2"] != 100 {
		t.Fatalf("192.168.1.1: got %v, want all 100 on b:2", got)
	}
	// ipv4-in-ipv6 remote address is parsed and allowed by a
	if got := pickDistribution(t, tbl, "foo.com", "[::ffff:10.1.2.3]:5000", "", 100); got["a:1"] != 100 {
		t.Fatalf("[::ffff:10.1.2.3]: got %v, want all 100 on a:1", got)
	}
}

func TestAccessAwarePickAllExcluded(t *testing.T) {
	tbl := newAccessTestTable(t)
	gc := NewGlobCache(100)

	// 172.16.0.1 is allowed by neither a nor b: Lookup must still return a
	// target (not nil, so no fallthrough to other routes) and the caller's
	// AccessDeniedHTTP check turns it into a 403.
	req := httptest.NewRequest("GET", "http://foo.com/", nil)
	req.RemoteAddr = "172.16.0.1:5000"
	tg := tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false)
	if tg == nil {
		t.Fatal("got nil target, want a target so the caller can return 403")
	}
	if !tg.AccessDeniedHTTP(req) {
		t.Fatal("got access allowed, want denied (403)")
	}

	// XFF elements must all pass: 172.16.0.9 in the chain is allowed by
	// neither target even though the remote address itself is fine for a.
	req = httptest.NewRequest("GET", "http://foo.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	req.Header.Set("X-Forwarded-For", "10.1.2.3, 172.16.0.9")
	tg = tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false)
	if tg == nil {
		t.Fatal("got nil target, want a target so the caller can return 403")
	}
	if !tg.AccessDeniedHTTP(req) {
		t.Fatal("got access allowed, want denied (403)")
	}
}

func TestAccessAwarePickNoFallthroughToHostlessRoute(t *testing.T) {
	tbl := newAccessTestTable(t, `route add other / http://10.9.0.1:80/`)
	gc := NewGlobCache(100)

	// a request for foo.com from a source excluded by a's rules must get a
	// 403, not the hostless catch-all route.
	req := httptest.NewRequest("GET", "http://foo.com/", nil)
	req.RemoteAddr = "172.16.0.1:5000"
	tg := tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false)
	if tg == nil {
		t.Fatal("got nil target, want the foo.com target")
	}
	if got := tg.URL.Host; got != "a:1" {
		t.Fatalf("got target %s, want a:1 (no fallthrough to hostless route)", got)
	}
	if !tg.AccessDeniedHTTP(req) {
		t.Fatal("got access allowed, want denied (403)")
	}

	// the hostless route itself is still reachable for other hosts
	req = httptest.NewRequest("GET", "http://bar.com/", nil)
	req.RemoteAddr = "172.16.0.1:5000"
	if tg = tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false); tg == nil || tg.URL.Host != "10.9.0.1:80" {
		t.Fatalf("got %v, want hostless target 10.9.0.1:80", tg)
	}
}

func TestAccessAwarePickUnruledTargetTakesRest(t *testing.T) {
	tbl := newAccessTestTable(t, `route add svc foo.com/ http://d:4/`)

	// a source allowed by neither a nor b falls to the target without rules
	if got := pickDistribution(t, tbl, "foo.com", "[2001:db8::1]:443", "", 100); got["d:4"] != 100 {
		t.Fatalf("[2001:db8::1]: got %v, want all 100 on d:4", got)
	}
}

func TestAccessAwarePickRRRotation(t *testing.T) {
	tbl, err := NewTable(bytes.NewBufferString(`
route add svc foo.com/ http://a:1/ opts "allow=ip:10.0.0.0/8"
route add svc foo.com/ http://d:4/
`))
	if err != nil {
		t.Fatal(err)
	}

	// 10.1.2.3 is allowed by both: rr rotates across a and d
	if got := pickDistribution(t, tbl, "foo.com", "10.1.2.3:5000", "", 2); got["a:1"] != 1 || got["d:4"] != 1 {
		t.Fatalf("10.1.2.3: got %v, want 1x a:1 and 1x d:4", got)
	}
	// 172.16.0.1 is allowed by d only: both requests go to d
	if got := pickDistribution(t, tbl, "foo.com", "172.16.0.1:5000", "", 2); got["d:4"] != 2 {
		t.Fatalf("172.16.0.1: got %v, want 2x d:4", got)
	}
}

// TestAccessAwarePickSlotRatios verifies the chosen distribution algorithm:
// the surviving targets keep the slots they had on the original weighted
// ring, so their ratio is the ratio of their original slot counts.
func TestAccessAwarePickSlotRatios(t *testing.T) {
	// a has fixed weight 0.2, b and c are dynamic: the ring holds
	// 2000 slots for a and 4000 slots each for b and c.
	// c denies 10.0.0.0/8, so from 10.1.2.3 the candidates are a and b
	// with their original 2000:4000 slots, i.e. 1/3 vs 2/3.
	tbl, err := NewTable(bytes.NewBufferString(`
route add svc foo.com/ http://a:1/ weight 0.2
route add svc foo.com/ http://b:2/
route add svc foo.com/ http://c:3/ opts "deny=ip:10.0.0.0/8"
`))
	if err != nil {
		t.Fatal(err)
	}
	got := pickDistribution(t, tbl, "foo.com", "10.1.2.3:5000", "", 6000)
	if got["a:1"] != 2000 || got["b:2"] != 4000 || got["c:3"] != 0 {
		t.Fatalf("got %v, want 2000x a:1, 4000x b:2, 0x c:3", got)
	}

	// a and b have fixed weight 0.5 each, c is dynamic and therefore has
	// zero slots on the original ring. With a excluded, c still gets
	// nothing: it never had a share of this route's traffic.
	tbl, err = NewTable(bytes.NewBufferString(`
route add svc foo.com/ http://a:1/ weight 0.5 opts "deny=ip:10.0.0.0/8"
route add svc foo.com/ http://b:2/ weight 0.5
route add svc foo.com/ http://c:3/
`))
	if err != nil {
		t.Fatal(err)
	}
	got = pickDistribution(t, tbl, "foo.com", "10.1.2.3:5000", "", 6000)
	if got["b:2"] != 6000 || got["c:3"] != 0 {
		t.Fatalf("got %v, want 6000x b:2, 0x c:3", got)
	}
}

func TestAccessAwarePickUnparseableRemoteAddr(t *testing.T) {
	tbl := newAccessTestTable(t)

	// RemoteAddr without a port fails SplitHostPort: AccessDeniedHTTP
	// treats this as allowed and so does the filtering - the distribution
	// is the same as if no rules existed (rr alternates a and b).
	got := pickDistribution(t, tbl, "foo.com", "10.1.2.3", "", 4)
	if got["a:1"] != 2 || got["b:2"] != 2 {
		t.Fatalf("got %v, want 2x a:1 and 2x b:2", got)
	}
}

func TestAccessAwarePickConcurrency(t *testing.T) {
	tbl := newAccessTestTable(t)
	gc := NewGlobCache(100)

	const groups = 2
	const reqs = 6000
	remotes := []string{"10.1.2.3:5000", "192.168.1.1:5000"}
	wants := []string{"a:1", "b:2"}

	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	errs := make(chan error, groups*reqs)
	for g := 0; g < groups; g++ {
		done.Add(1)
		go func(g int) {
			defer done.Done()
			start.Wait()
			for i := 0; i < reqs; i++ {
				req := httptest.NewRequest("GET", "http://foo.com/", nil)
				req.RemoteAddr = remotes[g]
				tg := tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false)
				if tg == nil {
					errs <- fmt.Errorf("group %d: nil target", g)
					return
				}
				if tg.URL.Host != wants[g] {
					errs <- fmt.Errorf("group %d: got %s, want %s", g, tg.URL.Host, wants[g])
					return
				}
			}
		}(g)
	}
	start.Done()
	done.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// countDenialLogs runs fn with the standard logger redirected and returns
// the number of "route rules denied access" lines it emitted.
func countDenialLogs(t *testing.T, fn func()) int {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)
	fn()
	return strings.Count(buf.String(), "route rules denied access")
}

func TestAccessAwarePickDenialLogCounts(t *testing.T) {
	tbl := newAccessTestTable(t)
	gc := NewGlobCache(100)

	// a request that is served normally must not produce any denial log,
	// even though the filtering excluded one of the targets
	req := httptest.NewRequest("GET", "http://foo.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	if n := countDenialLogs(t, func() {
		tg := tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false)
		if tg == nil || tg.AccessDeniedHTTP(req) {
			t.Error("request should have been served")
		}
	}); n != 0 {
		t.Fatalf("got %d denial log lines for a served request, want 0", n)
	}

	// a request that ends in a 403 must produce exactly one denial log
	req = httptest.NewRequest("GET", "http://foo.com/", nil)
	req.RemoteAddr = "172.16.0.1:5000"
	if n := countDenialLogs(t, func() {
		tg := tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false)
		if tg == nil || !tg.AccessDeniedHTTP(req) {
			t.Error("request should have been denied")
		}
	}); n != 1 {
		t.Fatalf("got %d denial log lines for a 403 request, want 1", n)
	}
}
