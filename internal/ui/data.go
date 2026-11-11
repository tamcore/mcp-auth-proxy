package ui

import "github.com/tamcore/mcp-auth-proxy/internal/store"

// Invite is a pending invite shown on the login page.
type Invite struct {
	Username string
	Link     string
}

// LoginData feeds login.tmpl.
type LoginData struct {
	Next    string
	Error   string
	Invites []Invite
}

// InviteData feeds invite.tmpl.
type InviteData struct {
	Token string
	Error string
}

// Server is an MCP server listed on the portal. ID is set only for the
// user's own servers, which can be deleted.
type Server struct {
	Name   string
	Kind   string
	Source string
	ID     string
}

// Key is an API key listed on the portal.
type Key struct {
	ID        string
	Label     string
	Kind      string
	Upstreams []string
	Revoked   bool
}

// PortalData feeds portal.tmpl. NewToken is set once, right after creation.
type PortalData struct {
	NewToken     string
	MCPURL       string
	Servers      []Server
	Keys         []Key
	OAuthClients []string
}

// AuditData feeds audit.tmpl.
type AuditData struct {
	Retention string
	Responses string
	Entries   []*store.AuditEntry
}

// AdminData feeds admin.tmpl. Invite is set once, right after minting.
type AdminData struct {
	Invite string
	Users  []*store.User
}

// ConsentData feeds consent.tmpl.
type ConsentData struct {
	Client        string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	State         string
}

// Result tones.
const (
	ToneOK    = "ok"
	ToneDeny  = "deny"
	ToneError = "error"
)

// ResultData feeds result.tmpl.
type ResultData struct {
	Tone    string
	Heading string
	Message string
}
