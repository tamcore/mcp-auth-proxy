package oauthserver

import (
	"net/http"

	"github.com/tamcore/mcp-auth-proxy/internal/ui"
)

// renderConsent serves the honest consent page: logging in grants an identity
// (the right to list tools and ask for authorization), never tool-call
// authorization, which always requires the one-time code.
func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, p *authorizeParams) {
	client, err := s.store.OAuthClientByID(r.Context(), p.clientID)
	name := p.clientID
	if err == nil && client.Name != "" {
		name = client.Name
	}
	s.pages.Render(w, http.StatusOK, "consent", ui.Page{Title: "Authorize identity", Data: ui.ConsentData{
		Client:        name,
		ClientID:      p.clientID,
		RedirectURI:   p.redirectURI,
		CodeChallenge: p.codeChallenge,
		State:         p.state,
	}})
}
