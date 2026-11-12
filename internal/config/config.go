// Package config loads and validates the mcp-auth-proxy configuration. Sources,
// in increasing precedence: built-in defaults, the YAML config file, environment
// variables prefixed with MCP_PROXY_ (dots become underscores).
package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Defaults.
const (
	DefaultListenAddr = "127.0.0.1:8080"
	// DefaultOpsListenAddr serves /metrics, /healthz and /readyz.
	DefaultOpsListenAddr = "127.0.0.1:9090"
	DefaultBaseURL       = "http://127.0.0.1:8080"
	DefaultStateDir      = "./data"
	DefaultSessionTTL    = 8 * time.Hour
	// DefaultAuditRetention is the default audit-log TTL (30 days).
	DefaultAuditRetention = 30 * 24 * time.Hour
)

// OTP defaults.
const (
	DefaultOTPDigits        = 5
	DefaultOTPExpiry        = 3 * time.Minute
	DefaultOTPAttempts      = 3
	DefaultOTPRenotifyFloor = 30 * time.Second
	DefaultOAuthTokenTTL    = 24 * time.Hour
	DefaultAuthorizeCodeTTL = 10 * time.Minute
)

// Config is the validated runtime configuration.
type Config struct {
	BaseURL       string
	ListenAddr    string
	OpsListenAddr string
	StateDir      string
	SessionTTL    time.Duration
	OTP           OTPConfig
	// LegacyNtfy is set when the config still has the removed global ntfy block.
	LegacyNtfy bool
	Audit      AuditConfig
	Users      []string
	Admins     []string
	Upstreams  []UpstreamConfig
	OAuth      OAuthConfig
}

// OTPConfig holds the one-time-code gate tuning.
type OTPConfig struct {
	Digits        int
	Expiry        time.Duration
	Attempts      int
	RenotifyFloor time.Duration
}

// AuditConfig holds the audit log settings. Retention is the garbage-collection
// TTL for log entries; the default is 30 days.
type AuditConfig struct {
	Enabled      bool
	LogResponses bool
	Retention    time.Duration
}

// UpstreamConfig is one upstream MCP server. Users lists the usernames allowed
// to use it; empty means global (every user).
type UpstreamConfig struct {
	Name    string               `mapstructure:"name"`
	URL     string               `mapstructure:"url"`
	Command []string             `mapstructure:"command"`
	Headers map[string]string    `mapstructure:"headers"`
	OAuth   *UpstreamOAuthConfig `mapstructure:"oauth"`
	Users   []string             `mapstructure:"users"`
}

// Global reports whether the upstream is available to every user.
func (u *UpstreamConfig) Global() bool { return len(u.Users) == 0 }

// Allows reports whether the named user may use this upstream.
func (u *UpstreamConfig) Allows(username string) bool {
	if u.Global() {
		return true
	}
	return slices.Contains(u.Users, username)
}

// UpstreamOAuthConfig is the OAuth client registration for an upstream that
// requires a linked token.
type UpstreamOAuthConfig struct {
	AuthorizeURL string   `mapstructure:"authorize_url"`
	TokenURL     string   `mapstructure:"token_url"`
	ClientID     string   `mapstructure:"client_id"`
	Scopes       []string `mapstructure:"scopes"`
	// Resource is the RFC 8707 resource indicator, byte-exact as the upstream
	// advertises it in /.well-known/oauth-protected-resource.
	Resource string `mapstructure:"resource"`
}

// OAuthConfig is the client-facing authorization server section.
type OAuthConfig struct {
	Clients          []ClientConfig
	TokenTTL         time.Duration
	AuthorizeCodeTTL time.Duration
}

// ClientConfig is one registered OAuth client of the proxy's AS.
type ClientConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	Name         string   `mapstructure:"name"`
	RedirectURIs []string `mapstructure:"redirect_uris"`
	Confidential bool     `mapstructure:"confidential"`
}

// Load reads the config file at path (may be empty) plus the environment and
// returns the validated configuration.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("MCP_PROXY")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	setDefaults(v)
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("config: read %s: %w", path, err)
		}
	} else if env := v.GetString("config"); env != "" {
		v.SetConfigFile(env)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("config: read %s: %w", env, err)
		}
	}
	cfg := &Config{
		BaseURL:       v.GetString("base_url"),
		ListenAddr:    v.GetString("listen_addr"),
		OpsListenAddr: v.GetString("ops_listen_addr"),
		StateDir:      v.GetString("state_dir"),
		SessionTTL:    v.GetDuration("session_ttl"),
		OTP: OTPConfig{
			Digits:        v.GetInt("otp.digits"),
			Expiry:        v.GetDuration("otp.expiry"),
			Attempts:      v.GetInt("otp.attempts"),
			RenotifyFloor: v.GetDuration("otp.renotify_floor"),
		},
		LegacyNtfy: v.IsSet("ntfy.url") || v.IsSet("ntfy.topic") || v.IsSet("ntfy.enabled"),
		Audit: AuditConfig{
			Enabled:      v.GetBool("audit.enabled"),
			LogResponses: v.GetBool("audit.log_responses"),
			Retention:    v.GetDuration("audit.retention"),
		},
		Users:  v.GetStringSlice("users"),
		Admins: v.GetStringSlice("admins"),
		OAuth: OAuthConfig{
			TokenTTL:         v.GetDuration("oauth.token_ttl"),
			AuthorizeCodeTTL: v.GetDuration("oauth.authorize_code_ttl"),
		},
	}
	if err := unmarshalSlice(v, "upstreams", &cfg.Upstreams); err != nil {
		return nil, err
	}
	if err := unmarshalSlice(v, "oauth.clients", &cfg.OAuth.Clients); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("base_url", DefaultBaseURL)
	v.SetDefault("listen_addr", DefaultListenAddr)
	v.SetDefault("ops_listen_addr", DefaultOpsListenAddr)
	v.SetDefault("state_dir", DefaultStateDir)
	v.SetDefault("session_ttl", DefaultSessionTTL)
	v.SetDefault("otp.digits", DefaultOTPDigits)
	v.SetDefault("otp.expiry", DefaultOTPExpiry)
	v.SetDefault("otp.attempts", DefaultOTPAttempts)
	v.SetDefault("otp.renotify_floor", DefaultOTPRenotifyFloor)
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.log_responses", false)
	v.SetDefault("audit.retention", DefaultAuditRetention)
	v.SetDefault("oauth.token_ttl", DefaultOAuthTokenTTL)
	v.SetDefault("oauth.authorize_code_ttl", DefaultAuthorizeCodeTTL)
}

func unmarshalSlice[T any](v *viper.Viper, key string, out *[]T) error {
	if err := v.UnmarshalKey(key, out); err != nil {
		return fmt.Errorf("config: decode %s: %w", key, err)
	}
	return nil
}

// Validate enforces the invariants the rest of the code relies on.
func (c *Config) Validate() error {
	var errs []error
	if strings.TrimSpace(c.BaseURL) == "" {
		errs = append(errs, errors.New("config: base_url must not be empty"))
	}
	if strings.TrimSpace(c.ListenAddr) == "" {
		errs = append(errs, errors.New("config: listen_addr must not be empty"))
	}
	if strings.TrimSpace(c.OpsListenAddr) == "" || c.OpsListenAddr == c.ListenAddr {
		errs = append(errs, errors.New("config: ops_listen_addr must be set and differ from listen_addr"))
	}
	if strings.TrimSpace(c.StateDir) == "" {
		errs = append(errs, errors.New("config: state_dir must not be empty"))
	}
	if c.SessionTTL <= 0 {
		errs = append(errs, errors.New("config: session_ttl must be positive"))
	}
	if err := c.OTP.validate(); err != nil {
		errs = append(errs, err)
	}
	userSet, userErrs := validateUsers(c.Users, c.Admins)
	errs = append(errs, userErrs...)
	seen := map[string]bool{}
	for i := range c.Upstreams {
		errs = append(errs, c.Upstreams[i].validate(i, seen, userSet))
	}
	if c.Audit.Retention <= 0 {
		errs = append(errs, errors.New("config: audit.retention must be positive"))
	}
	for i := range c.OAuth.Clients {
		errs = append(errs, c.OAuth.Clients[i].validate(i))
	}
	if c.OAuth.TokenTTL <= 0 {
		errs = append(errs, errors.New("config: oauth.token_ttl must be positive"))
	}
	if c.OAuth.AuthorizeCodeTTL <= 0 {
		errs = append(errs, errors.New("config: oauth.authorize_code_ttl must be positive"))
	}
	return errors.Join(errs...)
}

// validateUsers checks the users/admins lists and returns the user set.
func validateUsers(users, admins []string) (map[string]bool, []error) {
	userSet := map[string]bool{}
	var errs []error
	for i, u := range users {
		u = strings.TrimSpace(u)
		if u == "" {
			errs = append(errs, fmt.Errorf("config: users[%d] must not be empty", i))
			continue
		}
		if userSet[u] {
			errs = append(errs, fmt.Errorf("config: duplicate user %q", u))
		}
		userSet[u] = true
	}
	for i, a := range admins {
		a = strings.TrimSpace(a)
		if !userSet[a] {
			errs = append(errs, fmt.Errorf("config: admins[%d] %q is not in users", i, a))
		}
	}
	return userSet, errs
}

func (o *OTPConfig) validate() error {
	var errs []error
	if o.Digits < 3 || o.Digits > 8 {
		errs = append(errs, fmt.Errorf("config: otp.digits must be 3..8, got %d", o.Digits))
	}
	if o.Expiry <= 0 {
		errs = append(errs, errors.New("config: otp.expiry must be positive"))
	}
	if o.Attempts < 1 {
		errs = append(errs, fmt.Errorf("config: otp.attempts must be >= 1, got %d", o.Attempts))
	}
	if o.RenotifyFloor < 0 {
		errs = append(errs, errors.New("config: otp.renotify_floor must be >= 0"))
	}
	return errors.Join(errs...)
}

func (u *UpstreamConfig) validate(i int, seen map[string]bool, users map[string]bool) error {
	p := fmt.Sprintf("config: upstreams[%d]", i)
	var errs []error
	if strings.TrimSpace(u.Name) == "" {
		errs = append(errs, fmt.Errorf("%s: name must not be empty", p))
	} else if seen[u.Name] {
		errs = append(errs, fmt.Errorf("%s: duplicate upstream name %q", p, u.Name))
	} else {
		seen[u.Name] = true
	}
	if (u.URL == "") == (len(u.Command) == 0) {
		errs = append(errs, fmt.Errorf("%s (%s): exactly one of url or command is required", p, u.Name))
	}
	for _, name := range u.Users {
		if !users[name] {
			errs = append(errs, fmt.Errorf("%s (%s): users references unknown user %q", p, u.Name, name))
		}
	}
	if u.OAuth != nil {
		if u.OAuth.AuthorizeURL == "" || u.OAuth.TokenURL == "" || u.OAuth.ClientID == "" {
			errs = append(errs, fmt.Errorf("%s (%s): oauth requires authorize_url, token_url and client_id", p, u.Name))
		}
	}
	return errors.Join(errs...)
}

func (c *ClientConfig) validate(i int) error {
	p := fmt.Sprintf("config: oauth.clients[%d]", i)
	var errs []error
	if strings.TrimSpace(c.ClientID) == "" {
		errs = append(errs, fmt.Errorf("%s: client_id must not be empty", p))
	}
	if len(c.RedirectURIs) == 0 {
		errs = append(errs, fmt.Errorf("%s (%s): at least one redirect_uri is required", p, c.ClientID))
	}
	if c.Confidential {
		errs = append(errs, fmt.Errorf("%s (%s): confidential clients are not supported (no client secrets); "+
			"clients authenticate with PKCE", p, c.ClientID))
	}
	return errors.Join(errs...)
}

// UpstreamNames returns the configured upstream names in order.
func (c *Config) UpstreamNames() []string {
	out := make([]string, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		out = append(out, u.Name)
	}
	return out
}
