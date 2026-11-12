package webui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpUpstream serves one tool over streamable HTTP; with bearer set, it
// answers 401 to requests without that token.
func mcpUpstream(t *testing.T, bearer string) string {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "test-upstream", Version: "dev"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "ping", Description: "ping"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, nil, nil
		})
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bearer != "" && r.Header.Get("Authorization") != "Bearer "+bearer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestOwnUpstreamMustBeAnMCPServer(t *testing.T) {
	st, ts := newLinkUI(t, "https://idp/token")
	bob := login(t, ts, testBob, linkPw)
	notMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"instance-id":"i-123"}`))
	}))
	t.Cleanup(notMCP.Close)
	add := func(name, u string) int {
		form := url.Values{nameField: {name}, urlField: {u}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/portal/upstream", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(bob)
		resp, err := noRedirectClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := add("meta", notMCP.URL); code != http.StatusBadRequest {
		t.Fatalf("non-MCP URL: want 400, got %d", code)
	}
	if code := add("real", mcpUpstream(t, "")); code != http.StatusFound {
		t.Fatalf("MCP server: want 302, got %d", code)
	}
	ups, err := st.ListUserUpstreams(context.Background(), linkUserID)
	if err != nil || len(ups) != 1 || ups[0].Name != "real" {
		t.Fatalf("only the MCP server may be stored: %+v %v", ups, err)
	}
}
