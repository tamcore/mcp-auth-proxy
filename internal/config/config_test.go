package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimal = `
base_url: http://127.0.0.1:8080
state_dir: ./data
upstreams:
  - name: echo
    command: ["mcp-auth-proxy", "dev-echo"]
`

func TestDefaults(t *testing.T) {
	cfg, err := Load(writeCfg(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != 8*time.Hour {
		t.Fatalf("default session_ttl = %v", cfg.SessionTTL)
	}
	if cfg.OTP.Digits != 5 || cfg.OTP.Expiry != 3*time.Minute ||
		cfg.OTP.Attempts != 3 || cfg.OTP.RenotifyFloor != 30*time.Second {
		t.Fatalf("otp defaults wrong: %+v", cfg.OTP)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Fatalf("listen addr default = %q", cfg.ListenAddr)
	}
	if cfg.OpsListenAddr != DefaultOpsListenAddr {
		t.Fatalf("ops listen addr default = %q", cfg.OpsListenAddr)
	}
	if cfg.LegacyNtfy {
		t.Fatal("minimal config has no ntfy block")
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("MCP_PROXY_SESSION_TTL", "1h")
	t.Setenv("MCP_PROXY_OTP_DIGITS", "6")
	cfg, err := Load(writeCfg(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != time.Hour || cfg.OTP.Digits != 6 {
		t.Fatalf("env override ignored: ttl=%v digits=%d", cfg.SessionTTL, cfg.OTP.Digits)
	}
}

func TestLegacyNtfyBlockIsFlagged(t *testing.T) {
	cfg, err := Load(writeCfg(t, minimal+"\nntfy: {enabled: true, url: https://ntfy.sh, topic: t}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LegacyNtfy {
		t.Fatal("a config with the removed ntfy block must be flagged")
	}
}

func TestValidationFailures(t *testing.T) {
	cases := map[string]string{
		"empty base_url": `
base_url: ""
state_dir: ./data
upstreams: [{name: e, command: [x]}]
`,
		"upstream with both url and command": `
base_url: http://x
state_dir: ./data
upstreams: [{name: e, url: http://u, command: [x]}]
`,
		"duplicate upstream names": `
base_url: http://x
state_dir: ./data
upstreams: [{name: e, command: [x]}, {name: e, url: http://u}]
`,
		"oauth client without redirect": `
base_url: http://x
state_dir: ./data
upstreams: [{name: e, command: [x]}]
oauth:
  clients: [{client_id: c, name: C}]
`,
		"ops listener on the app address": `
base_url: http://x
state_dir: ./data
listen_addr: 127.0.0.1:8080
ops_listen_addr: 127.0.0.1:8080
upstreams: [{name: e, command: [x]}]
`,
		"confidential oauth client": `
base_url: http://x
state_dir: ./data
upstreams: [{name: e, command: [x]}]
oauth:
  clients: [{client_id: c, name: C, redirect_uris: [https://c/cb], confidential: true}]
`,
		"bad otp digits": `
base_url: http://x
state_dir: ./data
otp: {digits: 2}
upstreams: [{name: e, command: [x]}]
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeCfg(t, body)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestOAuthClientsParsed(t *testing.T) {
	body := minimal + `
oauth:
  clients:
    - client_id: claude
      name: Claude
      redirect_uris: ["https://claude.ai/api/mcp/cb"]
      confidential: false
`
	cfg, err := Load(writeCfg(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.OAuth.Clients) != 1 || cfg.OAuth.Clients[0].RedirectURIs[0] != "https://claude.ai/api/mcp/cb" {
		t.Fatalf("clients: %+v", cfg.OAuth.Clients)
	}
	if cfg.OAuth.TokenTTL != 24*time.Hour {
		t.Fatalf("token ttl default: %v", cfg.OAuth.TokenTTL)
	}
}
