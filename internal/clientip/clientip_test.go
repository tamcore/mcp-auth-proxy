package clientip

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	p, err := ParsePrefixes(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParsePrefixes(t *testing.T) {
	got := mustPrefixes(t, "192.168.69.211", " 10.1.2.3/8 ", "", "::1", "::ffff:1.2.3.4")
	want := []string{"192.168.69.211/32", "10.0.0.0/8", "::1/128", "1.2.3.4/32"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Errorf("entry %d = %s, want %s", i, got[i], w)
		}
	}
	for _, bad := range []string{"nope", "1.2.3.4/33", "example.com", "::ffff:1.2.3.4/120", "fe80::1%eth0"} {
		if _, err := ParsePrefixes([]string{bad}); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

const (
	laptop = "192.168.69.211"
	other  = "203.0.113.9"
	ngf    = "10.42.3.33:5000"
	none   = "invalid IP"
)

func TestFromRequest(t *testing.T) {
	trusted := mustPrefixes(t, "10.42.0.0/16")
	cases := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct peer", laptop + ":5000", nil, laptop},
		{"untrusted peer ignores xff", other + ":5000", []string{laptop}, other},
		{"trusted peer without xff", ngf, nil, none},
		{"trusted peer uses xff", ngf, []string{laptop}, laptop},
		{"forged leftmost ignored", ngf, []string{laptop + ", " + other}, other},
		{"forged behind tunnel pod in trusted range", "10.42.1.82:5000", []string{laptop + ", 10.42.1.44"},
			"10.42.1.44"},
		{"last header line wins", ngf, []string{laptop, other}, other},
		{"garbage entry", ngf, []string{laptop + ", junk"}, none},
		{"mapped peer", "[::ffff:" + laptop + "]:5000", nil, laptop},
		{"bad remote", "nonsense", nil, none},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := FromRequest(r, trusted).String(); got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	p := mustPrefixes(t, "192.168.69.211")
	a := netip.MustParseAddr("::ffff:192.168.69.211")
	if !Contains(p, a) || Contains(p, netip.Addr{}) || Contains(nil, a) {
		t.Fatal("Contains")
	}
}
