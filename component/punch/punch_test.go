package punch

import (
	"net"
	"strings"
	"testing"

	"github.com/hashicorp/yamux"
)

const testFP = "0000000000000000000000000000000000000000000000000000000000000000"

func TestOptionDefaults(t *testing.T) {
	v, err := (&Option{Coordinator: "example.invalid:48080", Fingerprint: strings.ToUpper(testFP[:2]) + ":" + testFP[2:], Token: "t"}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if v.Fingerprint != testFP {
		t.Fatalf("fingerprint not normalised: %q", v.Fingerprint)
	}
	if v.Attempts != 4 || v.Keep != 2 || v.Refresh != 60 || v.MaxAge <= v.Refresh {
		t.Fatalf("unexpected defaults: %+v", v)
	}
	if len(v.ProbePorts) != 2 {
		t.Fatalf("probe ports default missing: %v", v.ProbePorts)
	}
}

func TestOptionRejectsUnsafeConfig(t *testing.T) {
	cases := map[string]Option{
		"no coordinator": {Fingerprint: testFP, Token: "t"},
		"no token":       {Coordinator: "example.invalid:1", Fingerprint: testFP},
		"no pin":         {Coordinator: "example.invalid:1", Token: "t"},
		"short pin":      {Coordinator: "example.invalid:1", Token: "t", Fingerprint: "abcd"},
	}
	for name, o := range cases {
		if _, err := o.withDefaults(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestKeepNeverExceedsAttempts(t *testing.T) {
	v, err := (&Option{Coordinator: "example.invalid:1", Fingerprint: testFP, Token: "t", Attempts: 1, Keep: 3}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if v.Attempts < v.Keep {
		t.Fatalf("attempts %d < keep %d", v.Attempts, v.Keep)
	}
}

func TestPoolsSharedPerServerAndToken(t *testing.T) {
	o := Option{Coordinator: "example.invalid:1", Fingerprint: testFP, Token: "same"}
	a, _ := NewDialer(o)
	b, _ := NewDialer(o)
	if a.(*punchDialer).p != b.(*punchDialer).p {
		t.Fatal("two proxies for the same coordinator+token should share one pool")
	}
	o.Token = "other"
	c, _ := NewDialer(o)
	if c.(*punchDialer).p == a.(*punchDialer).p {
		t.Fatal("different tokens must not share a pool")
	}
}

func TestLocalRoute(t *testing.T) {
	if got := localRoute("127.0.0.1:48080"); got != "127.0.0.1" {
		t.Fatalf("loopback route = %q", got)
	}
	if got := localRoute("no-port"); got != "" {
		t.Fatalf("bad address should give no route, got %q", got)
	}
}

// A route change means the punched flows belong to a NAT mapping that no longer exists.
func TestWatchRouteDropsSessionsOnNetworkChange(t *testing.T) {
	p := newPool(Option{Coordinator: "127.0.0.1:48080"})
	a, b := net.Pipe()
	defer b.Close()
	s, err := yamux.Client(a, yamuxCfg())
	if err != nil {
		t.Fatal(err)
	}
	p.add(s)
	p.natMode = "cone"

	p.route = "127.0.0.1"
	p.watchRoute()
	if len(p.sess) != 1 || p.natMode != "cone" {
		t.Fatal("unchanged route must keep sessions and NAT verdict")
	}

	p.route = "192.0.2.7" // the address the previous network gave us
	p.watchRoute()
	if len(p.sess) != 0 || p.natMode != "" || !s.IsClosed() {
		t.Fatalf("route change must drop sessions and re-probe: sess=%d nat=%q", len(p.sess), p.natMode)
	}
}
