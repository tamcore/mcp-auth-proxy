package server

import (
	"strings"
	"testing"
)

func FuzzLogPath(f *testing.F) {
	for _, s := range []string{"/mcp/mak_secret", "/invite/tok", "/login", "/mcp/", "/approve/c1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got := logPath(p)
		for _, prefix := range []string{"/mcp/", "/invite/"} {
			if strings.HasPrefix(p, prefix) && len(p) > len(prefix) && got != prefix+"[redacted]" {
				t.Fatalf("logPath(%q) = %q leaks the credential", p, got)
			}
		}
	})
}
