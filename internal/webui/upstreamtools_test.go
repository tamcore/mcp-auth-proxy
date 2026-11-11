package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func toolsUpstream(t *testing.T) string {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "ha", Version: "0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "turn_on", Description: "Turn a light on"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	ts := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func getTools(t *testing.T, ts *httptest.Server, cookie *http.Cookie, name string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/portal/upstream/tools?"+url.Values{nameField: {name}}.Encode(), nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestToolsOfOwnUpstream(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	bob := login(t, ts, testBob, linkPw)
	if err := st.CreateUserUpstream(context.Background(), &store.UserUpstream{
		ID: "us_ha", UserID: linkUserID, Name: "ha", URL: toolsUpstream(t),
	}); err != nil {
		t.Fatal(err)
	}
	code, body := getTools(t, ts, bob, "ha")
	tools, _ := body["tools"].([]any)
	if code != http.StatusOK || len(tools) != 1 {
		t.Fatalf("tools: %d %v", code, body)
	}
	first := tools[0].(map[string]any)
	if first["name"] != "turn_on" || first["description"] != "Turn a light on" {
		t.Fatalf("tool: %v", first)
	}
	if code, _ := getTools(t, ts, login(t, ts, testAlice, linkPw), "ha"); code != http.StatusNotFound {
		t.Fatalf("another user's server must be unknown, got %d", code)
	}
}

func TestToolsOfUnlinkedOAuthUpstream(t *testing.T) {
	_, ts := newLinkUI(t, "https://idp/token")
	code, body := getTools(t, ts, login(t, ts, testBob, linkPw), garmin)
	if code != http.StatusBadGateway || !strings.Contains(body[errorField].(string), "not linked") {
		t.Fatalf("want 502 not linked, got %d %v", code, body)
	}
}

func TestUnlinkRemovesOnlyOwnToken(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	ctx := context.Background()
	for _, uid := range []string{linkAdminID, linkUserID} {
		tok := &store.UpstreamToken{Upstream: garmin, UserID: uid, AccessToken: "at"}
		if err := st.SaveUpstreamToken(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/upstream/unlink",
		strings.NewReader(url.Values{nameField: {garmin}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(login(t, ts, testBob, linkPw))
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unlink: %d", resp.StatusCode)
	}
	if _, err := st.GetUpstreamToken(ctx, garmin, linkUserID); err != store.ErrNotFound {
		t.Fatalf("bob's token must be gone: %v", err)
	}
	if _, err := st.GetUpstreamToken(ctx, garmin, linkAdminID); err != nil {
		t.Fatalf("alice's token must stay: %v", err)
	}
}
