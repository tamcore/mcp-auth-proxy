package server

import (
	"strings"
	"testing"
)

func TestLogPathRedactsEmbeddedCredential(t *testing.T) {
	for in, want := range map[string]string{
		"/mcp/mak_secret": "/mcp/[redacted]",
		"/invite/tok":     "/invite/[redacted]",
		"/.well-known/mcp/server-card/mcp/mak_secret":         "/.well-known/mcp/[redacted]",
		"/.well-known/oauth-protected-resource/mcp/mak_s":     "/.well-known/oauth-protected-resource/mcp/[redacted]",
		"/.well-known/oauth-authorization-server/mcp/map_s/x": "/.well-known/oauth-authorization-server/mcp/[redacted]",
		"/.well-known/openid-configuration/invite/tok":        "/.well-known/openid-configuration/invite/[redacted]",
	} {
		if got := logPath(in); got != want {
			t.Errorf("logPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzLogPath(f *testing.F) {
	for _, s := range []string{
		"/mcp/mak_secret", "/invite/tok", "/login", "/mcp/", "/approve/c1", "/.well-known/x/mcp/mak_s",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got := logPath(p)
		for _, marker := range []string{"/mcp/", "/invite/"} {
			i := strings.Index(p, marker)
			if i < 0 || len(p) == i+len(marker) {
				continue
			}
			kept, ok := strings.CutSuffix(got, "[redacted]")
			if !ok || !strings.HasPrefix(p, kept) || len(kept) > i+len(marker) {
				t.Fatalf("logPath(%q) = %q leaks the credential", p, got)
			}
		}
	})
}
