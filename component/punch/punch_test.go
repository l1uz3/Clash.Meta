package punch

import (
	"strings"
	"testing"
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
