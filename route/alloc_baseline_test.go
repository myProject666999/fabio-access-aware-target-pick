package route

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

// TestLookupAllocsNoRules guards the fast path: Lookup on a route whose
// targets carry no access rules must not allocate more than it did before
// access-aware target selection was introduced (baseline: 2 allocs).
func TestLookupAllocsNoRules(t *testing.T) {
	tbl, err := NewTable(bytes.NewBufferString(`
route add svc foo.com/ http://10.0.0.1:80/
route add svc foo.com/ http://10.0.0.2:80/
`))
	if err != nil {
		t.Fatal(err)
	}
	gc := NewGlobCache(100)
	req := httptest.NewRequest("GET", "http://foo.com/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	const baseline = 2
	allocs := testing.AllocsPerRun(1000, func() {
		if tg := tbl.Lookup(req, Picker["rr"], Matcher["prefix"], gc, false); tg == nil {
			t.Fatal("no target")
		}
	})
	if allocs > baseline {
		t.Fatalf("got %v allocs per Lookup, want <= %d (pre-change baseline)", allocs, baseline)
	}
}
