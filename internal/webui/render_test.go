package webui

import (
	"strings"
	"testing"
	"time"

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
