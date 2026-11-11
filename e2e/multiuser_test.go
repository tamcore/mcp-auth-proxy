//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a goroutine-safe bytes.Buffer for capturing subprocess logs.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startMultiUserEnv starts the proxy with two configured users, a global and an
// alice-only upstream, and a fake ntfy. logs is captured to recover the
// invite links.
func startMultiUserEnv(t *testing.T) (*env, *lockedBuffer) {
	t.Helper()
	dir := t.TempDir()
	port := freePort(t)
	ntfy := newFakeNtfy(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`base_url: %s
listen_addr: 127.0.0.1:%d
ops_listen_addr: 127.0.0.1:0
state_dir: %s
session_ttl: 8h
users: [alice, bob]
admins: [alice]
upstreams:
  - name: echo
    command: [%q, dev-echo]
  - name: private
    command: [%q, dev-echo]
    users: [alice]
oauth:
  clients:
    - client_id: e2e
      name: E2E Client
      redirect_uris: [http://127.0.0.1:1/cb]
`, base, port, filepath.Join(dir, "state"), binary, binary)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	cmd := exec.Command(binary, "serve", "--config", cfgPath)
	cmd.Stdout = logs
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, bin: binary, cfg: cfgPath, base: base, ntfy: ntfy, cmd: cmd,
		client: &http.Client{Timeout: 10 * time.Second}}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := e.client.Get(base + "/login")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return e, logs
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("proxy did not come up")
	return nil, nil
}

func inviteURL(t *testing.T, logs *lockedBuffer, user string) string {
	t.Helper()
	re := regexp.MustCompile(`"user":"` + user + `","url":"([^"]+)"`)
	m := re.FindStringSubmatch(logs.String())
	if m == nil {
		t.Fatalf("no invite link for %s in logs", user)
	}
	return m[1]
}

// setPasswordViaInvite clicks the invite link and sets a password, returning
// the session cookie.
func setPasswordViaInvite(t *testing.T, inviteURL, pw string) *http.Cookie {
	t.Helper()
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(inviteURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invite page: %d", resp.StatusCode)
	}
	resp, err = client.PostForm(inviteURL, url.Values{"password": {pw}, "password2": {pw}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("invite set: %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "mcp_proxy_session" {
			return c
		}
	}
	t.Fatal("no session cookie after invite")
	return nil
}

func TestMultiUserPortalAndVisibility(t *testing.T) {
	e, logs := startMultiUserEnv(t)
	cookie := setPasswordViaInvite(t, inviteURL(t, logs, "alice"), "alice-password-1")
	setPushTarget(t, e, cookie)
	token := portalCreateKey(t, e, cookie, []string{"echo", "private"})
	bobRejected(t, e, logs)
	toolsAndAudit(t, e, cookie, token)
	out := logs.String()
	for _, want := range []string{`"msg":"http request"`, `"path":"/mcp/[redacted]"`, `"msg":"tool call"`,
		`"msg":"migration applied","migration":"0009_audit_keeps_deleted_keys"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout log missing %s", want)
		}
	}
	if strings.Contains(out, token) {
		t.Fatal("stdout log leaks the key token")
	}
}

// portalCreateKey creates a key through the portal and returns the token.
func portalCreateKey(t *testing.T, e *env, cookie *http.Cookie, upstreams []string) string {
	t.Helper()
	form := url.Values{"label": {"claude"}}
	for _, u := range upstreams {
		form.Add("upstream", u)
	}
	req, _ := http.NewRequest(http.MethodPost, e.base+"/portal/key", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	token := regexp.MustCompile(`mak_[0-9a-f]{64}`).FindString(string(body))
	if token == "" {
		t.Fatal("no token shown once in portal response")
	}
	return token
}

// bobRejected verifies bob cannot use the alice-only upstream.
func bobRejected(t *testing.T, e *env, logs *lockedBuffer) {
	t.Helper()
	bobCookie := setPasswordViaInvite(t, inviteURL(t, logs, "bob"), "bob-password-1")
	form := url.Values{"label": {"x"}, "upstream": {"private"}}
	req, _ := http.NewRequest(http.MethodPost, e.base+"/portal/key", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(bobCookie)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bob using private upstream must be rejected: %d", resp.StatusCode)
	}
}

// toolsAndAudit checks namespacing, the OTP gate, and the audit page.
func toolsAndAudit(t *testing.T, e *env, cookie *http.Cookie, token string) {
	t.Helper()
	sess := e.mcpClient(t, token)
	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	if !names["echo__echo"] || !names["private__echo"] || !names["auth"] {
		t.Fatalf("tools: %v", names)
	}
	if blocked := callTool(t, sess, "echo__echo", map[string]any{textArg: "audit-me"}); !blocked.IsError {
		t.Fatal("call must be blocked first")
	}
	e.ntfy.waitFor(t, 1)
	if e.ntfy.last()["topic"] != "e2etopic" {
		t.Fatalf("push must go to the user's own topic: %v", e.ntfy.last()["topic"])
	}
	if res := callTool(t, sess, "auth", map[string]any{"otp": lastCode(t, e.ntfy)}); res.IsError {
		t.Fatalf("auth: %q", textOf(res))
	}
	if res := callTool(t, sess, "echo__echo", map[string]any{textArg: "audit-me"}); res.IsError {
		t.Fatalf("retry: %q", textOf(res))
	}
	req, _ := http.NewRequest(http.MethodGet, e.base+"/portal/audit", nil)
	req.AddCookie(cookie)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "echo__echo") || !strings.Contains(string(body), "audit-me") {
		t.Fatal("audit page missing the recorded call")
	}
}

func TestServeExitsCleanlyOnSIGINT(t *testing.T) {
	e, _ := startMultiUserEnv(t)
	if err := e.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve must exit 0 on SIGINT: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not exit within 10s of SIGINT")
	}
}

// setPushTarget points the user's pushes at the fake ntfy via the portal.
func setPushTarget(t *testing.T, e *env, cookie *http.Cookie) {
	t.Helper()
	form := url.Values{"url": {e.ntfy.srv.URL}, "topic": {"e2etopic"}}
	req, _ := http.NewRequest(http.MethodPost, e.base+"/portal/notify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("set push target: %d", resp.StatusCode)
	}
}
