package webui

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/upstream"
)

const linkTTL = 10 * time.Minute

type pendingLink struct {
	req      *upstream.AuthRequest
	name     string
	userID   string
	deadline time.Time
}

// ponytail: in-memory, lost on restart; fine for the single-replica proxy.
type pendingLinks struct {
	mu sync.Mutex
	m  map[string]pendingLink
}

func (p *pendingLinks) put(l pendingLink, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.m {
		if now.After(v.deadline) {
			delete(p.m, k)
		}
	}
	p.m[l.req.State] = l
}

// take removes and returns the user's pending link for state, if still valid.
// Another user's attempt leaves the link in place.
func (p *pendingLinks) take(state, userID string, now time.Time) (pendingLink, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.m[state]
	if !ok || l.userID != userID {
		return pendingLink{}, false
	}
	delete(p.m, state)
	return l, now.Before(l.deadline)
}

// oauthUpstream returns a configured OAuth upstream the user may use.
func (ui *WebUI) oauthUpstream(name, username string) (config.UpstreamConfig, bool) {
	for _, u := range ui.cfg.Upstreams {
		if u.Name == name && u.OAuth != nil && u.Allows(username) {
			return u, true
		}
	}
	return config.UpstreamConfig{}, false
}

func (ui *WebUI) linkCallbackURL() string {
	return strings.TrimRight(ui.cfg.BaseURL, "/") + "/portal/upstream/callback"
}

// handleUpstreamLink starts linking the user's own account at an OAuth
// upstream and sends them to its authorize endpoint.
func (ui *WebUI) handleUpstreamLink(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	_ = r.ParseForm()
	c, ok := ui.oauthUpstream(r.PostForm.Get("name"), user.Username)
	if !ok {
		http.Error(w, "unknown upstream or no oauth configured", http.StatusNotFound)
		return
	}
	up := upstream.NewFromConfig(c, ui.store, nil, ui.logger).WithOwner(user.ID)
	req, err := up.BeginLink(ui.linkCallbackURL())
	if err != nil {
		ui.logger.Error("begin upstream link", "upstream", c.Name, "error", err)
		http.Error(w, "could not start link", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	ui.links.put(pendingLink{req: req, name: c.Name, userID: user.ID, deadline: now.Add(linkTTL)}, now)
	http.Redirect(w, r, req.URL, http.StatusSeeOther)
}

// handleUpstreamCallback finishes the link the same user started and stores
// the token for that user only.
func (ui *WebUI) handleUpstreamCallback(w http.ResponseWriter, r *http.Request) {
	user, ok := ui.sessions.Require(w, r, ui.store)
	if !ok {
		return
	}
	q := r.URL.Query()
	l, ok := ui.links.take(q.Get("state"), user.ID, time.Now())
	if !ok {
		ui.renderPortalStatus(w, r, user, http.StatusBadRequest, "", "Link request unknown or expired. Start it again.")
		return
	}
	if e := q.Get("error"); e != "" {
		ui.renderPortalStatus(w, r, user, http.StatusBadRequest, "", "Authorization for "+l.name+" failed: "+e)
		return
	}
	c, ok := ui.oauthUpstream(l.name, user.Username)
	if !ok {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	up := upstream.NewFromConfig(c, ui.store, nil, ui.logger).WithOwner(user.ID)
	if err := up.FinishLink(r.Context(), l.req, q.Get("code")); err != nil {
		ui.logger.Error("finish upstream link", "upstream", l.name, "user", user.Username, "error", err)
		ui.renderPortalStatus(w, r, user, http.StatusBadGateway, "", "Linking "+l.name+" failed. Try again later.")
		return
	}
	ui.logger.Info("upstream linked", "upstream", l.name, "user", user.Username)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
