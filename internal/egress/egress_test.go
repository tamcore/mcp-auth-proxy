package egress

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestAllowedRejectsNonPublicAddresses(t *testing.T) {
	g := New(Allow{})
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "224.0.0.1",
		"fec0::1", "64:ff9b::a00:1", "64:ff9b:1::a00:1", "2002:a00:1::1", "2001:0:a00:1::1", "2001:db8::1", "100::1",
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255", "2001:2::1"} {
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
	g := New(Allow{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
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
	if _, err := New(Allow{}).Client(0).Get(srv.URL); err == nil {
		t.Fatal("dial to loopback must fail")
	}
	open := New(Allow{Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}).Client(0)
	resp, err := open.Get(srv.URL)
	if err != nil {
		t.Fatalf("allow-listed loopback: %v", err)
	}
	_ = resp.Body.Close()
}

func TestParse(t *testing.T) {
	got, err := Parse([]string{"10.0.0.0/8", "fd00::/8", "NTFY.Example.COM."})
	if err != nil || len(got.Prefixes) != 2 || !got.Hosts["ntfy.example.com"] {
		t.Fatalf("parse: %+v %v", got, err)
	}
	for _, bad := range []string{"10.0.0.1", "*.example.com", "exa mple.com", "http://x", "",
		"127.1", "2130706433", "0x7f.1"} {
		if _, err := Parse([]string{bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestAllowedHostSkipsTheAddressCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	byName := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if _, err := New(Allow{}).Client(0).Get(byName); err == nil {
		t.Fatal("an unlisted name resolving to loopback must fail")
	}
	open := New(Allow{Hosts: map[string]bool{"localhost": true}}).Client(0)
	resp, err := open.Get(byName)
	if err != nil {
		t.Fatalf("listed host: %v", err)
	}
	_ = resp.Body.Close()
	if _, err := open.Get(srv.URL); err == nil {
		t.Fatal("the same address under an unlisted host must still fail")
	}
}

func TestRedirectFromAListedHostIsChecked(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer target.Close()
	redirector := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirector.Close()
	byName := strings.Replace(redirector.URL, "127.0.0.1", "localhost", 1)
	open := New(Allow{Hosts: map[string]bool{"localhost": true}}).Client(0)
	if _, err := open.Get(byName); err == nil {
		t.Fatal("a redirect from a listed host to an unlisted private address must fail")
	}
}

func TestUnrestrictedGuardAllowsEverything(t *testing.T) {
	g := New(Allow{Any: true})
	if !g.Allowed(netip.MustParseAddr("127.0.0.1")) || !g.Allowed(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("an unrestricted guard must allow private addresses")
	}
}

func TestUnrestrictedTransportKeepsTheProxySetting(t *testing.T) {
	if New(Allow{Any: true}).Transport().Proxy == nil {
		t.Fatal("unrestricted mode must honour HTTP_PROXY like the default transport")
	}
	if New(Allow{}).Transport().Proxy != nil {
		t.Fatal("restricted mode must ignore proxy settings")
	}
}
