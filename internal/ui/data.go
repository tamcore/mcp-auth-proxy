package ui

import (
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// LoginData feeds login.tmpl.
type LoginData struct {
	Next  string
	Error string
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
	OAuth  bool
	Linked bool
}

// Key is an API key listed on the portal.
type Key struct {
	ID          string
	Label       string
	Kind        string
	Upstreams   []string
	Revoked     bool
	LastUsed    *time.Time
	LastSuccess *time.Time
	// AuthorizedUntil is the end of the current OTP session, nil if none.
	AuthorizedUntil *time.Time
}

// PortalData feeds portal.tmpl. NewToken is set once, right after creation.
type PortalData struct {
	Error        string
	NotifyURL    string
	Pending      []Pending
	NewToken     string
	MCPEndpoint  string
	MCPURL       string
	Servers      []Server
	Keys         []Key
	OAuthClients []string
}

// Pending is an open authorization request on one of the user's keys. Code
// is empty after a restart (the code then lives only in the notification).
type Pending struct {
	ID         string
	Key        string
	Tool       string
	Expires    time.Time
	Code       string
	ApproveURL string
	DenyURL    string
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
	Error  string
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
