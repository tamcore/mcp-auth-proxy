//go:build live

// Package live exercises the proxy against a real upstream MCP server: the
// garmin-mcp binary run over stdio. It is skipped unless LIVE_GARMIN_BIN
// points at a built garmin-mcp; CI builds one (see the live job in ci.yaml).
package live

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var binary string

func TestMain(m *testing.M) {
	garmin := os.Getenv("LIVE_GARMIN_BIN")
	if garmin == "" {
		fmt.Fprintln(os.Stderr, "LIVE_GARMIN_BIN not set; skipping live tests")
		os.Exit(0)
	}
	if _, err := os.Stat(garmin); err != nil {
		fmt.Fprintln(os.Stderr, "garmin binary missing:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "mcp-auth-proxy-live")
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

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// startProxy launches the proxy subprocess with garmin-mcp as stdio upstream.
func startProxy(t *testing.T) (base, cfgPath string) {
	t.Helper()
	garmin := os.Getenv("LIVE_GARMIN_BIN")
	dir := t.TempDir()
	port := freePort(t)
	base = fmt.Sprintf("http://127.0.0.1:%d", port)
	cfgPath = filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`base_url: %s
listen_addr: 127.0.0.1:%d
ops_listen_addr: 127.0.0.1:0
state_dir: %s
session_ttl: 8h
upstreams:
  - name: garmin
    command: [%q, "serve"]
`, base, port, filepath.Join(dir, "state"), garmin)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "serve", "--config", cfgPath)
	cmd.Env = append(os.Environ(), "GARMIN_MCP_TRANSPORT=stdio")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/login")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base, cfgPath
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("proxy did not come up")
	return "", ""
}

func createKey(t *testing.T, cfgPath string) map[string]string {
	t.Helper()
	out, err := exec.Command(binary, "key", "create", "--label", "live", "--config", cfgPath, "--json").Output()
	if err != nil {
		t.Fatalf("key create: %v", err)
	}
	var key map[string]string
	if err := json.Unmarshal(out, &key); err != nil {
		t.Fatal(err)
	}
	return key
}

func mcpSession(t *testing.T, base, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "live", Version: "0"}, nil)
	sess, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   base + "/mcp/" + token,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}, nil)
	if err != nil {
		t.Fatalf("mcp connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

// TestGarminUpstreamViaStdio runs the proxy with garmin-mcp as a stdio
// upstream, then checks that its tools appear namespaced and that a call is
// gated with the contract message (no Garmin credentials needed for listing).
func TestGarminUpstreamViaStdio(t *testing.T) {
	base, cfgPath := startProxy(t)
	key := createKey(t, cfgPath)
	sess := mcpSession(t, base, key["token"])

	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	garminTools, firstGarmin, hasAuth := 0, "", false
	for _, tool := range res.Tools {
		if strings.HasPrefix(tool.Name, "garmin__") {
			garminTools++
			if firstGarmin == "" {
				firstGarmin = tool.Name
			}
		}
		if tool.Name == "auth" {
			hasAuth = true
		}
	}
	if garminTools == 0 {
		t.Fatal("no garmin__* tools listed; upstream did not expose tools")
	}
	if !hasAuth {
		t.Fatal("auth tool missing")
	}
	t.Logf("listed %d garmin__* tools", garminTools)

	callRes, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: firstGarmin})
	if err != nil {
		t.Fatal(err)
	}
	if !callRes.IsError || len(callRes.Content) == 0 {
		t.Fatal("expected the garmin call to be blocked with the OTP contract")
	}
	tc, ok := callRes.Content[0].(*mcp.TextContent)
	if !ok || !strings.Contains(tc.Text, "requires a one-time code") {
		t.Fatal("expected the blocked contract message")
	}
}
