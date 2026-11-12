package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func settingsBody(t *testing.T, ts *httptest.Server, cookie *http.Cookie) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/settings", nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	return nil
}

func TestSettingsPage(t *testing.T) {
	_, ts := newLinkUI(t, "https://idp/token")
	code, body := settingsBody(t, ts, login(t, ts, testBob, linkPw))
	if code != http.StatusOK {
		t.Fatalf("settings: %d", code)
	}
	for _, want := range []string{"Change password", "Passkeys", "Push notifications", `href="/settings"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("settings page missing %q", want)
		}
	}
}

const newPw = "new-password-1"

func TestChangePassword(t *testing.T) {
	_, ts := newLinkUI(t, "https://idp/token")
	old := login(t, ts, testBob, linkPw)
	other := login(t, ts, testBob, linkPw)
	change := func(cur, pw, pw2 string) *http.Response {
		form := url.Values{"current": {cur}, pwField: {pw}, pw2Field: {pw2}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/settings/password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(old)
		resp, err := noRedirectClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	for name, args := range map[string][3]string{
		"wrong current": {"nope", newPw, newPw},
		"mismatch":      {linkPw, newPw, "new-password-2"},
		"too short":     {linkPw, "short", "short"},
	} {
		if resp := change(args[0], args[1], args[2]); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", name, resp.StatusCode)
		}
	}
	resp := change(linkPw, newPw, newPw)
	fresh := sessionCookie(resp)
	if resp.StatusCode != http.StatusSeeOther || fresh == nil {
		t.Fatalf("change: %d cookie=%v", resp.StatusCode, fresh)
	}
	if code, _ := settingsBody(t, ts, fresh); code != http.StatusOK {
		t.Fatalf("current browser must stay logged in: %d", code)
	}
	if code, _ := settingsBody(t, ts, other); code != http.StatusFound {
		t.Fatalf("other sessions must be logged out: %d", code)
	}
	login(t, ts, testBob, newPw)
}

func TestLoginRejectsOffsiteNext(t *testing.T) {
	_, ts := newLinkUI(t, "https://idp/token")
	for _, next := range []string{"https://evil.example/", "//evil.example", "/\\evil.example"} {
		form := url.Values{userField: {testBob}, pwField: {linkPw}, "next": {next}}
		resp, err := noRedirectClient().PostForm(ts.URL+"/login", form)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "/" {
			t.Fatalf("next %q redirected to %q", next, loc)
		}
	}
}

func TestPasskeyCeremonyEndpoints(t *testing.T) {
	_, ts := newLinkUI(t, "https://idp/token")
	bob := login(t, ts, testBob, linkPw)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/settings/passkeys/begin", nil)
	req.AddCookie(bob)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var opts struct {
		PublicKey struct {
			RP struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				Name string `json:"name"`
			} `json:"user"`
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&opts)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || opts.PublicKey.RP.ID != "proxy.local" ||
		opts.PublicKey.User.Name != testBob || opts.PublicKey.Challenge == "" {
		t.Fatalf("registration options: %d %+v", resp.StatusCode, opts)
	}
	finish, _ := http.NewRequest(http.MethodPost, ts.URL+"/settings/passkeys/finish?name=x", strings.NewReader(`{}`))
	finish.AddCookie(bob)
	for _, c := range resp.Cookies() {
		finish.AddCookie(c)
	}
	if resp, err := noRedirectClient().Do(finish); err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bogus attestation: want 400, got %v %v", resp, err)
	}
	resp, err = noRedirectClient().Post(ts.URL+"/login/passkey/begin", "", nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login options: %v %v", resp, err)
	}
	_ = resp.Body.Close()
	resp, err = noRedirectClient().Post(ts.URL+"/login/passkey/finish", "application/json", strings.NewReader(`{}`))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bogus assertion: want 401, got %v %v", resp, err)
	}
}
