package upstream

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// AuthRequest is a started OAuth link: the authorize URL to send the user to
// and the secrets the callback needs to finish it.
type AuthRequest struct {
	URL         string
	State       string
	Verifier    string
	RedirectURI string
}

// BeginLink builds an authorization-code + PKCE request for this upstream.
func (u *Upstream) BeginLink(redirectURI string) (*AuthRequest, error) {
	cfg := u.cfg.OAuth
	if cfg == nil {
		return nil, errors.New("upstream: oauth not configured for " + u.cfg.Name)
	}
	pkce, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := randomState()
	if err != nil {
		return nil, err
	}
	q := url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {pkce.challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	q.Set(clientIDFormKey, cfg.ClientID)
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	setResource(q, cfg.Resource)
	return &AuthRequest{
		URL:         cfg.AuthorizeURL + "?" + q.Encode(),
		State:       state,
		Verifier:    pkce.verifier,
		RedirectURI: redirectURI,
	}, nil
}

// FinishLink exchanges the authorization code and stores the token set.
func (u *Upstream) FinishLink(ctx context.Context, req *AuthRequest, code string) error {
	if u.cfg.OAuth == nil {
		return errors.New("upstream: oauth not configured for " + u.cfg.Name)
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {req.RedirectURI},
		"code_verifier": {req.Verifier},
	}
	form.Set(clientIDFormKey, u.cfg.OAuth.ClientID)
	setResource(form, u.cfg.OAuth.Resource)
	tok, err := exchangeToken(ctx, u.httpc, u.cfg.OAuth.TokenURL, form)
	if err != nil {
		return err
	}
	tok.Upstream = u.cfg.Name
	tok.UserID = u.owner
	return u.store.SaveUpstreamToken(ctx, tok)
}

// LinkOptions parameterizes the one-time interactive linking flow.
type LinkOptions struct {
	OpenBrowser func(url string) error
	Stdout      io.Writer
}

// Link runs the interactive CLI linking flow: it starts a loopback callback
// server, prints (and optionally opens) the authorize URL, and finishes the
// link when the browser comes back.
func (u *Upstream) Link(ctx context.Context, opts LinkOptions) error {
	srv, port, resCh, err := startLoopback(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	req, err := u.BeginLink(fmt.Sprintf("http://127.0.0.1:%d/callback", port))
	if err != nil {
		return err
	}
	if opts.Stdout != nil {
		_, _ = fmt.Fprintf(opts.Stdout,
			"Open this URL to link upstream %q:\n\n%s\n\nWaiting for callback...\n", u.cfg.Name, req.URL)
	}
	if opts.OpenBrowser != nil {
		_ = opts.OpenBrowser(req.URL)
	}
	code, err := waitForCode(ctx, resCh, req.State)
	if err != nil {
		return err
	}
	if err := u.FinishLink(ctx, req, code); err != nil {
		return err
	}
	if opts.Stdout != nil {
		_, _ = fmt.Fprintf(opts.Stdout, "Linked upstream %q.\n", u.cfg.Name)
	}
	return nil
}

func setResource(v url.Values, resource string) {
	if resource != "" {
		v.Set("resource", resource)
	}
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
