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

// take removes and returns the pending link for state, if still valid.
func (p *pendingLinks) take(state string, now time.Time) (pendingLink, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.m[state]
	delete(p.m, state)
	return l, ok && now.Before(l.deadline)
}

func (ui *WebUI) oauthUpstream(name string) (config.UpstreamConfig, bool) {
	for _, u := range ui.cfg.Upstreams {
		if u.Name == name && u.OAuth != nil {
			return u, true
		}
	}
	return config.UpstreamConfig{}, false
}

func (ui *WebUI) linkCallbackURL() string {
	return strings.TrimRight(ui.cfg.BaseURL, "/") + "/admin/upstream/callback"
}

// handleUpstreamLink starts the OAuth link of a configured upstream and sends
// the admin to its authorize endpoint.
func (ui *WebUI) handleUpstreamLink(w http.ResponseWriter, r *http.Request) {
	admin, ok := ui.requireAdmin(w, r)
	if !ok {
		return
	}
	_ = r.ParseForm()
	c, ok := ui.oauthUpstream(r.PostForm.Get("name"))
	if !ok {
		http.Error(w, "unknown upstream or no oauth configured", http.StatusNotFound)
		return
	}
	req, err := upstream.NewFromConfig(c, ui.store, nil, ui.logger).BeginLink(ui.linkCallbackURL())
	if err != nil {
		ui.logger.Error("begin upstream link", "upstream", c.Name, "error", err)
		http.Error(w, "could not start link", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	ui.links.put(pendingLink{req: req, name: c.Name, userID: admin.ID, deadline: now.Add(linkTTL)}, now)
	http.Redirect(w, r, req.URL, http.StatusSeeOther)
}

// handleUpstreamCallback finishes the link the same admin started.
func (ui *WebUI) handleUpstreamCallback(w http.ResponseWriter, r *http.Request) {
	admin, ok := ui.requireAdmin(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	l, ok := ui.links.take(q.Get("state"), time.Now())
	if !ok || l.userID != admin.ID {
		ui.renderAdmin(w, r, admin, http.StatusBadRequest, "", "Link request unknown or expired. Start it again.")
		return
	}
	if e := q.Get("error"); e != "" {
		ui.renderAdmin(w, r, admin, http.StatusBadRequest, "", "Authorization for "+l.name+" failed: "+e)
		return
	}
	c, ok := ui.oauthUpstream(l.name)
	if !ok {
		http.Error(w, "unknown upstream", http.StatusNotFound)
		return
	}
	up := upstream.NewFromConfig(c, ui.store, nil, ui.logger)
	if err := up.FinishLink(r.Context(), l.req, q.Get("code")); err != nil {
		ui.logger.Error("finish upstream link", "upstream", l.name, "error", err)
		ui.renderAdmin(w, r, admin, http.StatusBadGateway, "", "Linking "+l.name+" failed. See the server log.")
		return
	}
	ui.logger.Info("upstream linked", "upstream", l.name, "user", admin.Username)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
