package webui

import (
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestPagesAreSelfContained(t *testing.T) {
	invites := []store.PendingInvite{{Username: "alice", Token: "abc123", ExpiresAt: time.Now().Add(time.Hour)}}
	html := page("t", loginBody("/", "", "http://proxy.local", invites))
	// No fetched external resources: no <link>, <script src>, <img>, CSS
	// @import/url(). Absolute hrefs pointing back at the proxy are fine.
	for _, bad := range []string{"<link", "<script", "<img", "@import", "url(", "srcset"} {
		if strings.Contains(html, bad) {
			t.Fatalf("page fetches external resource via %q", bad)
		}
	}
	if !strings.Contains(html, "<style>") {
		t.Fatal("inline style missing")
	}
	if !strings.Contains(html, "/invite/abc123") || !strings.Contains(html, "alice") {
		t.Fatal("pending invite link not rendered on login page")
	}
}

func TestPortalAdminLinkOnlyForAdmins(t *testing.T) {
	cfg := &config.Config{BaseURL: "http://proxy.local"}
	plain := portalPage(&store.User{Username: "bob"}, nil, nil, nil, cfg, "")
	if strings.Contains(plain, `href="/admin"`) || strings.Contains(plain, "{{") {
		t.Fatal("non-admin portal shows admin link or raw template syntax")
	}
	admin := portalPage(&store.User{Username: "alice", Admin: true}, nil, nil, nil, cfg, "")
	if !strings.Contains(admin, `href="/admin"`) {
		t.Fatal("admin portal lacks admin link")
	}
}
