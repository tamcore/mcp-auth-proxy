// Package egress guards outbound requests to destinations users control
// (own upstreams, ntfy servers, Web Push endpoints) against SSRF.
package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Allow opens destinations the guard would refuse: everything (Any), address
// prefixes, or exact host names, which skip the address check whatever they
// resolve to.
type Allow struct {
	Any      bool
	Prefixes []netip.Prefix
	Hosts    map[string]bool
}

// Guard rejects dials to non-public addresses outside its allow list.
type Guard struct {
	allow Allow
}

// New builds a guard.
func New(allow Allow) *Guard { return &Guard{allow: allow} }

// The last label must start with a letter: resolvers read all-numeric or hex
// forms such as 127.1 or 0x7f.1 as IPv4 addresses.
var hostName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z]([a-z0-9-]*[a-z0-9])?$`)

// Parse turns config entries into an Allow: a CIDR prefix, or a host name.
func Parse(entries []string) (Allow, error) {
	a := Allow{Hosts: map[string]bool{}}
	for _, s := range entries {
		if p, err := netip.ParsePrefix(s); err == nil {
			a.Prefixes = append(a.Prefixes, p.Masked())
			continue
		}
		h := normalizeHost(s)
		if _, err := netip.ParseAddr(h); err == nil || !hostName.MatchString(h) {
			return Allow{}, fmt.Errorf("egress: %q is neither a CIDR prefix nor a host name", s)
		}
		a.Hosts[h] = true
	}
	return a, nil
}

func normalizeHost(h string) string { return strings.TrimSuffix(strings.ToLower(h), ".") }

// Allowed reports whether ip may be dialed.
func (g *Guard) Allowed(ip netip.Addr) bool {
	if g.allow.Any {
		return true
	}
	ip = ip.Unmap()
	for _, p := range g.allow.Prefixes {
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
// ignores proxy environment variables, which would bypass the check; an
// unrestricted guard returns the default transport unchanged.
func (g *Guard) Transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if g.allow.Any {
		return t
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: g.control}
	t.Proxy = nil
	open := &net.Dialer{Timeout: d.Timeout, KeepAlive: d.KeepAlive}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// addr still carries the URL's host name here, before resolution.
		if host, _, err := net.SplitHostPort(addr); err == nil && g.allow.Hosts[normalizeHost(host)] {
			return open.DialContext(ctx, network, addr)
		}
		return d.DialContext(ctx, network, addr)
	}
	return t
}

// Client wraps Transport; timeout 0 means none.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: g.Transport(), Timeout: timeout}
}
