package upstream

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// clientIDFormKey is the OAuth form field name for the client id.
const clientIDFormKey = "client_id"

// ErrNoToken is returned when no stored token exists for an upstream.
var ErrNoToken = errors.New("upstream: no stored oauth token")

// authRoundTripper injects the stored bearer token, applies static headers, and
// on a 401 refreshes the token once, persists the rotated set, and retries.
type authRoundTripper struct {
	base   http.RoundTripper
	up     *Upstream
	header http.Header
	mu     sync.Mutex
}

// RoundTrip implements http.RoundTripper.
func (rt *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var token string
	if rt.up.OAuth() {
		var err error
		if token, err = rt.currentToken(req.Context()); err != nil && !errors.Is(err, ErrNoToken) {
			return nil, err
		}
	}
	clone := req.Clone(req.Context())
	for k, vs := range rt.header {
		for _, v := range vs {
			clone.Header.Add(k, v)
		}
	}
	if token != "" {
		clone.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := rt.base.RoundTrip(clone)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusUnauthorized && rt.up.OAuth() {
		_ = resp.Body.Close()
		if err := rt.refresh(req.Context()); err != nil {
			return nil, err
		}
		return rt.RoundTrip(req)
	}
	return resp, nil
}

func (rt *authRoundTripper) currentToken(ctx context.Context) (string, error) {
	tok, err := rt.up.store.GetUpstreamToken(ctx, rt.up.cfg.Name, rt.up.owner)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrNoToken
		}
		return "", err
	}
	if tok.ExpiresAt != nil && time.Now().After(tok.ExpiresAt.Add(-30*time.Second)) && tok.RefreshToken != "" {
		if err := rt.refresh(ctx); err != nil {
			rt.up.logger.Warn("upstream token refresh failed", "upstream", rt.up.cfg.Name, "error", err)
		}
		if tok2, err2 := rt.up.store.GetUpstreamToken(ctx, rt.up.cfg.Name, rt.up.owner); err2 == nil {
			return tok2.AccessToken, nil
		}
	}
	return tok.AccessToken, nil
}

// refresh exchanges the refresh token for a new set and persists it.
func (rt *authRoundTripper) refresh(ctx context.Context) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	cfg := rt.up.cfg.OAuth
	if cfg == nil {
		return errors.New("upstream: oauth not configured")
	}
	tok, err := rt.up.store.GetUpstreamToken(ctx, rt.up.cfg.Name, rt.up.owner)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNoToken
	}
	if err != nil {
		return err
	}
	if tok.RefreshToken == "" {
		return ErrNoToken
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tok.RefreshToken},
	}
	form.Set(clientIDFormKey, cfg.ClientID)
	setResource(form, cfg.Resource)
	newTok, err := exchangeToken(ctx, rt.up.httpc, cfg.TokenURL, form)
	if err != nil {
		return err
	}
	if newTok.RefreshToken == "" {
		newTok.RefreshToken = tok.RefreshToken // rotation optional; keep old
	}
	newTok.Upstream = rt.up.cfg.Name
	newTok.UserID = rt.up.owner
	return rt.up.store.SaveUpstreamToken(ctx, newTok)
}

// tokenResponse is the OAuth2 token endpoint response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// exchangeToken posts a form to a token endpoint and normalizes the result.
func exchangeToken(ctx context.Context, hc *http.Client, tokenURL string,
	form url.Values) (*store.UpstreamToken, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream: token endpoint returned %s", resp.Status)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("upstream: decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, errors.New("upstream: token endpoint returned no access_token")
	}
	tok := &store.UpstreamToken{AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken}
	if tr.ExpiresIn > 0 {
		et := time.Now().UTC().Add(time.Duration(tr.ExpiresIn) * time.Second)
		tok.ExpiresAt = &et
	}
	return tok, nil
}

// pkcePair is a PKCE S256 verifier/challenge pair.
type pkcePair struct {
	verifier  string
	challenge string
}

func newPKCE() (pkcePair, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return pkcePair{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return pkcePair{verifier: verifier, challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}
