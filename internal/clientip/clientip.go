// Package clientip resolves a request's client address behind a trusted
// proxy and matches it against CIDR lists.
package clientip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// ParsePrefixes parses CIDR prefixes; a bare address is a single-host prefix.
func ParsePrefixes(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			a, err := netip.ParseAddr(e)
			if err != nil || a.Zone() != "" {
				return nil, fmt.Errorf("invalid address or CIDR %q", e)
			}
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(e)
		if err != nil || p.Addr().Is4In6() {
			return nil, fmt.Errorf("invalid address or CIDR %q", e)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Contains reports whether addr is in one of prefixes. An invalid addr matches nothing.
func Contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// FromRequest returns the client address: the peer, or, when the peer is a
// trusted proxy, the rightmost X-Forwarded-For entry (the address that
// connected to that proxy). Entries further left are client-controlled. A
// missing or unparsable entry yields the zero Addr, which matches no prefix.
// ponytail: one proxy layer; add a hop count if a second HTTP proxy is chained.
func FromRequest(r *http.Request, trusted []netip.Prefix) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	peer := ap.Addr().Unmap()
	if !Contains(trusted, peer) {
		return peer
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return netip.Addr{}
	}
	hops := strings.Split(values[len(values)-1], ",")
	addr, err := netip.ParseAddr(strings.TrimSpace(hops[len(hops)-1]))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap()
}
