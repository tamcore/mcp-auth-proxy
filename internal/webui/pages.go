package webui

import (
	"strings"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
	view "github.com/tamcore/mcp-auth-proxy/internal/ui"
)

func navUser(u *store.User) *view.User {
	return &view.User{Name: u.Username, Admin: u.Admin}
}

func source(url string, command []string) string {
	if url != "" {
		return url
	}
	return "command: " + strings.Join(command, " ")
}

func portalData(globals []config.UpstreamConfig, own []*store.UserUpstream,
	keys []*store.Key, cfg *config.Config, newToken string, linked map[string]bool) view.PortalData {
	d := view.PortalData{NewToken: newToken}
	if newToken != "" {
		d.MCPEndpoint = strings.TrimRight(cfg.BaseURL, "/") + "/mcp"
		d.MCPURL = d.MCPEndpoint + "/" + newToken
	}
	for _, u := range globals {
		kind := "global"
		if !u.Global() {
			kind = "shared"
		}
		d.Servers = append(d.Servers, view.Server{Name: u.Name, Kind: kind, Source: source(u.URL, u.Command),
			OAuth: u.OAuth != nil, Linked: linked[u.Name]})
	}
	for _, u := range own {
		d.Servers = append(d.Servers, view.Server{Name: u.Name, Kind: "own", Source: source(u.URL, u.Command), ID: u.ID})
	}
	for _, k := range keys {
		d.Keys = append(d.Keys, view.Key{
			ID: k.ID, Label: k.Label, Kind: k.Kind, Upstreams: k.Upstreams, Revoked: k.Revoked(),
			LastUsed: k.LastUsedAt, LastSuccess: k.LastSuccessAt,
		})
	}
	for _, c := range cfg.OAuth.Clients {
		d.OAuthClients = append(d.OAuthClients, c.Name)
	}
	return d
}

func responsesLabel(c config.AuditConfig) string {
	if c.LogResponses {
		return "logged"
	}
	return "not logged"
}

func page(title string, user *store.User, data any) view.Page {
	p := view.Page{Title: title, Data: data}
	if user != nil {
		p.User = navUser(user)
	}
	return p
}
