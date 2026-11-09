package oauthserver

import (
	"html"
	"net/http"
)

// renderConsent serves the honest consent page: logging in grants an identity
// (the right to list tools and ask for authorization), never tool-call
// authorization, which always requires the one-time code.
func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, p *authorizeParams) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	client, err := s.store.OAuthClientByID(r.Context(), p.clientID)
	name := p.clientID
	if err == nil && client.Name != "" {
		name = client.Name
	}
	_, _ = w.Write([]byte(consentPage(name, p)))
}

// consentPage renders the form posting to /oauth/consent with the original
// parameters as hidden fields plus a label for the new identity key.
func consentPage(clientName string, p *authorizeParams) string {
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>mcp-auth-proxy consent</title></head>
<body>
<h1>Authorize identity</h1>
<p><strong>` + html.EscapeString(clientName) + `</strong> wants to connect to this MCP auth proxy.</p>
<p>Logging in grants an <em>identity</em> only: the client may list tools and ask
for authorization. <strong>Every tool call still requires a one-time code sent
to the owner's phone.</strong> Logging in never authorizes tool calls.</p>
<form method="post" action="/oauth/consent">
<input type="hidden" name="client_id" value="` + html.EscapeString(p.clientID) + `">
<input type="hidden" name="redirect_uri" value="` + html.EscapeString(p.redirectURI) + `">
<input type="hidden" name="code_challenge" value="` + html.EscapeString(p.codeChallenge) + `">
<input type="hidden" name="state" value="` + html.EscapeString(p.state) + `">
<label>Label for this client <input type="text" name="label" maxlength="80"
placeholder="e.g. Claude on my laptop"></label>
<button type="submit">Grant identity</button>
</form>
</body></html>`
}
