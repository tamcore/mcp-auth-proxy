package webui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestEditKeyNetworks(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	ctx := context.Background()
	uid := linkUserID
	key := &store.Key{ID: "k_nets", Kind: store.KeyKindStatic, Label: "claude-cli", SecretHash: "h_nets",
		Upstreams: []string{testEcho}, CreatedAt: time.Now().UTC(), UserID: &uid}
	if err := st.CreateKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	bob := login(t, ts, testBob, linkPw)
	alice := login(t, ts, testAlice, linkPw)
	edit := func(c *http.Cookie, allowed, trusted string) int {
		return postStatus(t, ts, c, "/portal/key/networks",
			url.Values{"id": {key.ID}, "allowed": {allowed}, "trusted": {trusted}})
	}
	nets := func() string {
		k, err := st.KeyByID(ctx, key.ID)
		if err != nil {
			t.Fatal(err)
		}
		return formatNetworks(k.AllowedCIDRs) + " | " + formatNetworks(k.TrustedCIDRs)
	}

	if code := edit(alice, "", "192.168.69.211"); code != http.StatusNotFound {
		t.Fatalf("another user's key: want 404, got %d", code)
	}
	if code := edit(bob, "", "laptop"); code != http.StatusBadRequest {
		t.Fatalf("invalid network: want 400, got %d", code)
	}
	if code := edit(bob, "", strings.Repeat("10.0.0.1 ", maxKeyNetworks+1)); code != http.StatusBadRequest {
		t.Fatalf("too many networks: want 400, got %d", code)
	}
	if code := edit(bob, "192.168.69.0/24,\n10.1.0.0/16", "192.168.69.211"); code != http.StatusSeeOther ||
		nets() != "192.168.69.0/24, 10.1.0.0/16 | 192.168.69.211/32" {
		t.Fatalf("set: code %d, networks %q", code, nets())
	}
	if !strings.Contains(portalBody(t, ts, bob), "pre-authorized from 192.168.69.211/32") {
		t.Fatal("portal must show the pre-authorized networks")
	}
	if code := edit(bob, "", ""); code != http.StatusSeeOther || nets() != " | " {
		t.Fatalf("clear: code %d, networks %q", code, nets())
	}
	if err := st.RevokeKey(ctx, key.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if code := edit(bob, "", "192.168.69.211"); code != http.StatusNotFound {
		t.Fatalf("revoked key: want 404, got %d", code)
	}
}
