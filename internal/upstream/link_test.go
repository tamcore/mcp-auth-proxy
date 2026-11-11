package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestBeginFinishLink(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	const redirect = "https://proxy.example/admin/upstream/callback"
	var challenge string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("code") != "the-code" || r.PostForm.Get("redirect_uri") != redirect ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "at", RefreshToken: "rt"})
	}))
	defer tokenSrv.Close()
	u := NewFromConfig(config.UpstreamConfig{Name: "garmin", URL: "https://up/mcp", OAuth: &config.UpstreamOAuthConfig{
		AuthorizeURL: "https://idp/authorize", TokenURL: tokenSrv.URL, ClientID: linkClientID, Scopes: []string{"a", "b"},
	}}, st, nil, nil).WithOwner("u_x")

	req, err := u.BeginLink(redirect)
	if err != nil {
		t.Fatal(err)
	}
	challenge = checkAuthorizeURL(t, req, redirect)
	if err := u.FinishLink(ctx, req, "the-code"); err != nil {
		t.Fatal(err)
	}
	tok, err := st.GetUpstreamToken(ctx, "garmin", "u_x")
	if err != nil || tok.AccessToken != "at" || tok.RefreshToken != "rt" {
		t.Fatalf("token not stored for its owner: %+v %v", tok, err)
	}
	if _, err := st.GetUpstreamToken(ctx, "garmin", ""); err == nil {
		t.Fatal("token leaked to the unowned slot")
	}
}

const linkClientID = "link-client"

// checkAuthorizeURL validates the authorize request and returns its challenge.
func checkAuthorizeURL(t *testing.T, req *AuthRequest, redirect string) string {
	t.Helper()
	authz, err := url.Parse(req.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := authz.Query()
	if q.Get("client_id") != linkClientID || q.Get("redirect_uri") != redirect || q.Get("state") != req.State ||
		q.Get("scope") != "a b" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize URL: %s", req.URL)
	}
	return q.Get("code_challenge")
}

func TestBeginLinkWithoutOAuth(t *testing.T) {
	u := NewFromConfig(config.UpstreamConfig{Name: "plain", URL: "https://up/mcp"}, nil, nil, nil)
	if _, err := u.BeginLink("https://x/cb"); err == nil {
		t.Fatal("want error for upstream without oauth")
	}
}
