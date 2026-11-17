// Package egress guards outbound requests to destinations users control
// (own upstreams, ntfy servers, Web Push endpoints) against SSRF.
package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Guard rejects dials to non-public addresses outside its allow list.
type Guard struct {
	allow []netip.Prefix
}

// New builds a guard; allow opens extra prefixes (e.g. a home network).
func New(allow []netip.Prefix) *Guard { return &Guard{allow: allow} }

// Parse turns config CIDR strings into prefixes.
func Parse(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("egress: %q is not a CIDR prefix", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Allowed reports whether ip may be dialed.
func (g *Guard) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range g.allow {
		if p.Contains(ip) {
			return true
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:2::/48",
		// IPv6 site-local, NAT64, 6to4, Teredo, documentation, discard: may embed or reach private IPv4.
		"fec0::/10", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "2001:db8::/32", "100::/64"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}

// control runs after DNS resolution, so rebinding cannot slip a private
// address past the check.
func (g *Guard) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("egress: unparsable address %q", address)
	}
	if !g.Allowed(ap.Addr()) {
		return fmt.Errorf("egress: %s is not a public address", ap.Addr())
	}
	return nil
}

// Transport is an http.Transport that dials only allowed addresses. It
// ignores proxy environment variables, which would bypass the check.
func (g *Guard) Transport() *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: g.control}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	return t
}

// Client wraps Transport; timeout 0 means none.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: g.Transport(), Timeout: timeout}
}
