//go:build e2e

// Package e2e runs the full proxy as a subprocess against a fake upstream
// (dev-echo) and a fake ntfy server, driving it with the official MCP client.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mcp-auth-proxy-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	binary = filepath.Join(dir, "mcp-auth-proxy")
	build := exec.Command("go", "build", "-o", binary, "../cmd/mcp-auth-proxy")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build failed:", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// fakeNtfy captures published messages.
type fakeNtfy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	msgs []map[string]any
}

func newFakeNtfy(t *testing.T) *fakeNtfy {
	t.Helper()
	f := &fakeNtfy{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			f.mu.Lock()
			f.msgs = append(f.msgs, m)
			f.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNtfy) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

func (f *fakeNtfy) last() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		return nil
	}
	return f.msgs[len(f.msgs)-1]
}

func (f *fakeNtfy) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f.count() >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d ntfy pushes (have %d)", n, f.count())
}

func lastCode(t *testing.T, f *fakeNtfy) string {
	t.Helper()
	msg, _ := f.last()["message"].(string)
	// message shape: ... One-time code: 12345 (expires ...)
	parts := strings.Split(msg, "One-time code: ")
	if len(parts) != 2 {
		t.Fatalf("no code in message %q", msg)
	}
	return strings.Fields(parts[1])[0]
}

func actionURL(t *testing.T, f *fakeNtfy, label string) string {
	t.Helper()
	acts, _ := f.last()["actions"].([]any)
	for _, a := range acts {
		am, _ := a.(map[string]any)
		if am["label"] == label {
			u, _ := am["url"].(string)
			return u
		}
	}
	t.Fatalf("no %s action in %v", label, f.last())
	return ""
}

// env is one running proxy subprocess.
type env struct {
	t      *testing.T
	bin    string
	cfg    string
	state  string
	base   string
	ntfy   *fakeNtfy
	cmd    *exec.Cmd
	client *http.Client
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

func startEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	port := freePort(t)
	ntfy := newFakeNtfy(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`base_url: %s
listen_addr: 127.0.0.1:%d
state_dir: %s
session_ttl: 8h
ntfy:
  url: %s
  topic: e2etopic
  enabled: true
upstreams:
  - name: echo
    command: [%q, dev-echo]
`, base, port, state, ntfy.srv.URL, binary)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "serve", "--config", cfgPath)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, bin: binary, cfg: cfgPath, state: state, base: base, ntfy: ntfy, cmd: cmd,
		client: &http.Client{Timeout: 10 * time.Second}}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	// Wait for readiness.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := e.client.Get(base + "/metrics")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				_ = resp.Body.Close()
				return e
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("proxy did not come up")
	return nil
}

func (e *env) createKey(t *testing.T, label string) map[string]string {
	t.Helper()
	out, err := exec.Command(e.bin, "key", "create", "--label", label, "--config", e.cfg, "--json").Output()
	if err != nil {
		t.Fatalf("key create: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("decode key json: %v (%s)", err, out)
	}
	return m
}

func (e *env) revoke(t *testing.T, id string) {
	t.Helper()
	if out, err := exec.Command(e.bin, "key", "revoke", id, "--config", e.cfg).CombinedOutput(); err != nil {
		t.Fatalf("revoke: %v (%s)", err, out)
	}
}

func (e *env) mcpClient(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   e.base + "/mcp/" + token,
		HTTPClient: e.client,
	}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func callTool(t *testing.T, sess *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return res
}

func textOf(res *mcp.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}
