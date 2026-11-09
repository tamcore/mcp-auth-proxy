//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	echoTool = "echo__echo"
	authTool = "auth"
	otpArg   = "otp"
	textArg  = "text"
)

func TestToolsListUngated(t *testing.T) {
	e := startEnv(t)
	key := e.createKey(t, "laptop")
	sess := e.mcpClient(t, key["token"])
	res, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	if !names[echoTool] {
		t.Fatalf("namespaced upstream tool missing: %v", names)
	}
	if !names[authTool] {
		t.Fatalf("auth tool missing: %v", names)
	}
	if e.ntfy.count() != 0 {
		t.Fatal("tools/list must not trigger a challenge")
	}
}

func TestBlockedContractAndNtfyPush(t *testing.T) {
	e := startEnv(t)
	key := e.createKey(t, "laptop")
	sess := e.mcpClient(t, key["token"])
	res := callTool(t, sess, echoTool, map[string]any{textArg: "hi"})
	if !res.IsError {
		t.Fatal("blocked call must be an error-shaped result")
	}
	msg := textOf(res)
	for _, want := range []string{"\"" + echoTool + "\"", `"laptop"`, "5-digit",
		"`auth`", otpArg, "retry this exact tool call"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("contract missing %q: %s", want, msg)
		}
	}
	e.ntfy.waitFor(t, 1)
	m := e.ntfy.last()
	if m["topic"] != "e2etopic" {
		t.Fatalf("topic %v", m["topic"])
	}
	body, _ := m["message"].(string)
	if !strings.Contains(body, "One-time code: ") {
		t.Fatalf("push missing code: %q", body)
	}
	acts, _ := m["actions"].([]any)
	if len(acts) != 2 {
		t.Fatalf("want Approve+Deny actions, got %v", acts)
	}
}

func TestOTPFlowWrongThenCorrect(t *testing.T) {
	e := startEnv(t)
	key := e.createKey(t, "laptop")
	sess := e.mcpClient(t, key["token"])

	res := callTool(t, sess, echoTool, map[string]any{textArg: "hi"})
	if !res.IsError {
		t.Fatal("first call must be blocked")
	}
	e.ntfy.waitFor(t, 1)
	code := lastCode(t, e.ntfy)

	wrong := "00000"
	if wrong == code {
		wrong = "11111"
	}
	authRes := callTool(t, sess, authTool, map[string]any{otpArg: wrong})
	if !authRes.IsError || !strings.Contains(textOf(authRes), "Wrong one-time code") {
		t.Fatalf("wrong otp must be rejected, got: %q", textOf(authRes))
	}

	authRes = callTool(t, sess, authTool, map[string]any{otpArg: code})
	if authRes.IsError {
		t.Fatalf("correct otp must succeed: %q", textOf(authRes))
	}
	msg := textOf(authRes)
	if !strings.Contains(msg, "Session authorized until ") ||
		!strings.Contains(msg, ". Retry the tool call you were blocked on.") {
		t.Fatalf("success contract broken: %q", msg)
	}

	retry := callTool(t, sess, echoTool, map[string]any{textArg: "hi"})
	if retry.IsError {
		t.Fatalf("retry after auth must succeed: %q", textOf(retry))
	}
	if !strings.Contains(textOf(retry), "echo: hi") {
		t.Fatalf("unexpected upstream result: %q", textOf(retry))
	}
}

func TestApproveDenyButtons(t *testing.T) {
	e := startEnv(t)
	key := e.createKey(t, "phone")
	sess := e.mcpClient(t, key["token"])

	callTool(t, sess, echoTool, map[string]any{textArg: "x"})
	e.ntfy.waitFor(t, 1)

	// Bad sig -> 403.
	bad := strings.Replace(actionURL(t, e.ntfy, "Approve"), "sig=", "sig=00", 1)
	if resp, err := e.client.Post(bad, "", nil); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("bad sig: want 403, got %d", resp.StatusCode)
		}
	}

	// Deny with valid sig -> call stays blocked.
	denyURL := actionURL(t, e.ntfy, "Deny")
	if resp, err := e.client.Post(denyURL, "", nil); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("deny: got %d", resp.StatusCode)
		}
	}
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "x"}); !res.IsError {
		t.Fatal("after deny the call must stay blocked")
	}
	e.ntfy.waitFor(t, 2)

	// Approve with valid sig -> session granted without any code.
	approveURL := actionURL(t, e.ntfy, "Approve")
	if resp, err := e.client.Post(approveURL, "", nil); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("approve: got %d", resp.StatusCode)
		}
	}
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "x"}); res.IsError {
		t.Fatalf("after approve the call must succeed: %q", textOf(res))
	}
}

func TestRevokeKillsSessionAndChallenge(t *testing.T) {
	e := startEnv(t)
	key := e.createKey(t, "temp")
	sess := e.mcpClient(t, key["token"])

	callTool(t, sess, echoTool, map[string]any{textArg: "a"})
	e.ntfy.waitFor(t, 1)
	code := lastCode(t, e.ntfy)
	if res := callTool(t, sess, authTool, map[string]any{otpArg: code}); res.IsError {
		t.Fatalf("auth failed: %q", textOf(res))
	}
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "a"}); res.IsError {
		t.Fatal("pre-revoke call should be allowed")
	}

	e.revoke(t, key["id"])

	// The revoked path token is refused at the HTTP layer...
	if resp, err := e.client.Post(e.base+"/mcp/"+key["token"], "application/json", strings.NewReader(`{}`)); err != nil {
		t.Fatal(err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked token: want 401, got %d", resp.StatusCode)
		}
	}
	// ...and the MCP client session dies with it (no session, no challenge, no push).
	_, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: echoTool, Arguments: map[string]any{textArg: "a"}})
	if err == nil {
		t.Fatal("post-revoke tool call must fail")
	}
	if e.ntfy.count() != 1 {
		t.Fatalf("revoke must kill the pending challenge without a new push, pushes=%d", e.ntfy.count())
	}
	_ = code
}
