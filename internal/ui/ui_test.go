package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func render(t *testing.T, r *Renderer, name string, p Page) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Render(rec, http.StatusOK, name, p)
	return rec.Code, rec.Body.String()
}

const testUser = "alice"

var externalRef = regexp.MustCompile(`<(link|script|img)[^>]*(src|href)="(https?:)?//`)

func TestEveryPageRendersSelfContained(t *testing.T) {
	r := New(nil)
	resp := "ok"
	alice := &User{Name: testUser}
	admin := &User{Name: testUser, Admin: true}
	pages := map[string]Page{
		"login":  {Data: LoginData{Next: "/"}},
		"invite": {Data: InviteData{Token: "abc", Error: "bad"}},
		"portal": {User: alice, Data: PortalData{
			NewToken: "mak_x", MCPURL: "http://p/mcp/mak_x",
			Servers: []Server{{Name: "echo", Kind: "own", ID: "us_1"}},
			Keys:    []Key{{ID: "k_1", Label: "l"}},
		}},
		"audit": {User: alice, Data: AuditData{Entries: []*store.AuditEntry{
			{CreatedAt: time.Unix(0, 0).UTC(), ToolName: "echo__echo", Response: &resp},
		}}},
		"admin": {User: admin, Data: AdminData{
			Invite: "http://p/invite/x",
			Users:  []*store.User{{ID: "u1", Username: "bob"}},
		}},
		"consent": {Data: ConsentData{Client: "Claude", ClientID: "claude"}},
		"result":  {Data: ResultData{Tone: ToneOK, Heading: "Approved", Message: "m"}},
	}
	for name, p := range pages {
		code, body := render(t, r, name, p)
		if code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", name, code, body)
		}
		if !strings.Contains(body, `href="/static/app.css?v=`) || !strings.Contains(body, `src="/static/app.js?v=`) {
			t.Fatalf("%s: same-origin assets missing", name)
		}
		if externalRef.MatchString(body) {
			t.Fatalf("%s: page fetches an external resource", name)
		}
	}
	_, audit := render(t, r, "audit", pages["audit"])
	if !strings.Contains(audit, "1970-01-01 00:00:00") || !strings.Contains(audit, ">ok<") {
		t.Fatal("audit row not rendered")
	}
}

func TestAdminLinkOnlyForAdmins(t *testing.T) {
	r := New(nil)
	_, plain := render(t, r, "portal", Page{User: &User{Name: "bob"}, Data: PortalData{}})
	if strings.Contains(plain, `href="/admin"`) {
		t.Fatal("non-admin sees admin link")
	}
	_, admin := render(t, r, "portal", Page{User: &User{Name: testUser, Admin: true}, Data: PortalData{}})
	if !strings.Contains(admin, `href="/admin"`) {
		t.Fatal("admin lacks admin link")
	}
}

func TestRenderEscapes(t *testing.T) {
	_, body := render(t, New(nil), "consent", Page{Data: ConsentData{Client: `<script>x</script>`}})
	if strings.Contains(body, "<script>x") {
		t.Fatal("client name not escaped")
	}
}

func TestRenderUnknownPage(t *testing.T) {
	code, _ := render(t, New(nil), "nope", Page{})
	if code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", code)
	}
}

func TestStatic(t *testing.T) {
	srv := httptest.NewServer(New(nil).Static())
	defer srv.Close()
	for path, ctype := range map[string]string{"/static/app.css": "text/css", "/static/app.js": "javascript"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), ctype) {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		immutable := strings.Contains(resp.Header.Get("Cache-Control"), "immutable")
		if !immutable || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: cache/nosniff headers missing", path)
		}
		if strings.Contains(string(body), "@import") || strings.Contains(string(body), "url(http") {
			t.Fatalf("%s: references external resources", path)
		}
	}
	resp, err := http.Get(srv.URL + "/static/missing.css")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown asset: %d", resp.StatusCode)
	}
}
