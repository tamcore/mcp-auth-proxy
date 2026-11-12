package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamcore/mcp-auth-proxy/internal/version"
)

func testConfigFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := "base_url: http://127.0.0.1:8080\nstate_dir: " + dir + "\n" +
		"upstreams:\n  - name: echo\n    command: [\"true\"]\n"
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_PROXY_CONFIG", p)
	return p
}

func runKeyCmd(t *testing.T, args ...string) string {
	t.Helper()
	c := newKeyCmd()
	buf := &bytes.Buffer{}
	c.SetOut(buf)
	c.SetErr(buf)
	c.SetArgs(args)
	if err := c.Execute(); err != nil {
		t.Fatalf("key %v: %v (%s)", args, err, buf.String())
	}
	return buf.String()
}

func TestKeyCreateListRevoke(t *testing.T) {
	testConfigFile(t)
	out := runKeyCmd(t, "create", "--label", "laptop", "--json")
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if !strings.HasPrefix(m["token"], "mak_") {
		t.Fatalf("token prefix: %q", m["token"])
	}
	if !strings.Contains(m["mcp_url"], "/mcp/"+m["token"]) {
		t.Fatalf("mcp url: %q", m["mcp_url"])
	}
	if !strings.HasSuffix(m["mcp_endpoint"], "/mcp") {
		t.Fatalf("mcp endpoint: %q", m["mcp_endpoint"])
	}
	list := runKeyCmd(t, "list")
	if !strings.Contains(list, m["id"]) || !strings.Contains(list, "laptop") {
		t.Fatalf("list: %q", list)
	}
	if strings.Contains(list, m["token"]) {
		t.Fatal("list must never print token material")
	}
	runKeyCmd(t, "revoke", m["id"])
	list = runKeyCmd(t, "list")
	if !strings.Contains(list, "revoked") {
		t.Fatalf("after revoke: %q", list)
	}
}

func TestVersionCommand(t *testing.T) {
	oldV, oldC := version.Version, version.Commit
	version.Version, version.Commit = "v1.2.3", "abc123"
	t.Cleanup(func() { version.Version, version.Commit = oldV, oldC })
	c := newVersionCmd()
	buf := &bytes.Buffer{}
	c.SetOut(buf)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "v1.2.3") || !strings.Contains(buf.String(), "abc123") {
		t.Fatalf("version output: %q", buf.String())
	}
}

func TestHTTPServersBoundSlowClients(t *testing.T) {
	s := newHTTPServer(":0", http.NotFoundHandler())
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.IdleTimeout <= 0 {
		t.Fatalf("a slow client could hold a connection forever: %+v", s)
	}
	if s.WriteTimeout != 0 {
		t.Fatal("a WriteTimeout would cut streamed MCP responses")
	}
}
