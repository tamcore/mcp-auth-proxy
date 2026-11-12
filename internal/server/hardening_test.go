package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPagesForbidFramingAndForeignContent(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	h := resp.Header
	csp := h.Get("Content-Security-Policy")
	if h.Get("X-Frame-Options") != "DENY" || !strings.Contains(csp, "frame-ancestors 'none'") ||
		!strings.Contains(csp, "default-src 'self'") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing security headers: %v", h)
	}
}

func TestCrossSitePostsAreRejectedExceptClientEndpoints(t *testing.T) {
	ts := newTestServer(t)
	post := func(path string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("/portal/key"); code != http.StatusForbidden {
		t.Fatalf("cross-site portal POST: %d, want 403", code)
	}
	for _, path := range []string{"/oauth/token", "/mcp"} {
		if code := post(path); code == http.StatusForbidden {
			t.Fatalf("%s must accept cross-origin clients, got 403", path)
		}
	}
}

func TestApproveLinkOpenedWithGETOnlyAsksForConfirmation(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/approve/c1?sig=bad")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Approve this request?") ||
		!strings.Contains(string(body), `<form method="post"`) {
		t.Fatalf("GET must render a confirmation form and act on nothing: %d %s", resp.StatusCode, body)
	}
}
