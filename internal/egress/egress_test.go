package egress

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestAllowedRejectsNonPublicAddresses(t *testing.T) {
	g := New(nil)
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "224.0.0.1",
		"fec0::1", "64:ff9b::a00:1", "64:ff9b:1::a00:1", "2002:a00:1::1", "2001:0:a00:1::1", "2001:db8::1", "100::1"} {
		if g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s must be rejected", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !g.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
}

func TestAllowListOpensPrefixes(t *testing.T) {
	g := New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if !g.Allowed(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("allow-listed prefix must be allowed")
	}
	if g.Allowed(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("other private ranges stay blocked")
	}
}

func TestClientRefusesLoopbackAndRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	if _, err := New(nil).Client(0).Get(srv.URL); err == nil {
		t.Fatal("dial to loopback must fail")
	}
	open := New([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}).Client(0)
	resp, err := open.Get(srv.URL)
	if err != nil {
		t.Fatalf("allow-listed loopback: %v", err)
	}
	_ = resp.Body.Close()
}

func TestParse(t *testing.T) {
	got, err := Parse([]string{"10.0.0.0/8", "fd00::/8"})
	if err != nil || len(got) != 2 {
		t.Fatalf("parse: %v %v", got, err)
	}
	if _, err := Parse([]string{"10.0.0.1"}); err == nil {
		t.Fatal("a bare address must be rejected")
	}
}
