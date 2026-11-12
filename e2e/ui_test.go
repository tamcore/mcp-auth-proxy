//go:build e2e

package e2e

import (
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mxschmitt/playwright-go"
)

var launchBrowser = sync.OnceValues(func() (playwright.Browser, error) {
	opts := &playwright.RunOptions{Browsers: []string{"chromium"}, OnlyInstallShell: true, Verbose: false}
	if err := playwright.Install(opts); err != nil {
		return nil, err
	}
	pw, err := playwright.Run()
	if err != nil {
		return nil, err
	}
	return pw.Chromium.Launch()
})

var expect = playwright.NewPlaywrightAssertions()

// newPage opens a fresh browser context against the proxy.
func newPage(t *testing.T, e *env, opts playwright.BrowserNewContextOptions) playwright.Page {
	t.Helper()
	browser, err := launchBrowser()
	if err != nil {
		t.Fatalf("playwright: %v", err)
	}
	opts.BaseURL = playwright.String(e.base)
	ctx, err := browser.NewContext(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func gotoPath(t *testing.T, page playwright.Page, path string) {
	t.Helper()
	if _, err := page.Goto(path); err != nil {
		t.Fatal(err)
	}
}

// uiAcceptInvite opens the user's invite link from the server log and sets a
// password, leaving the page logged in on the portal.
func uiAcceptInvite(t *testing.T, page playwright.Page, logs *lockedBuffer, user string) {
	t.Helper()
	gotoPath(t, page, inviteURL(t, logs, user))
	must(t, page.Locator("#password").Fill(user+"-password-1"))
	must(t, page.Locator("#password2").Fill(user+"-password-1"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Set password and log in"}).Click())
	must(t, expect.Locator(page.GetByTestId("username")).ToHaveText(user))
}

func attr(t *testing.T, page playwright.Page, selector, name string) string {
	t.Helper()
	v, err := page.Locator(selector).GetAttribute(name)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestUIPortalFlow(t *testing.T) {
	e, logs := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{
		Permissions: []string{"clipboard-read", "clipboard-write"},
	})
	uiAcceptInvite(t, page, logs, "alice")
	must(t, expect.Locator(page.GetByRole("link", playwright.PageGetByRoleOptions{Name: "Admin"})).ToBeVisible())
	uiSetPushTarget(t, e, page)

	must(t, page.Locator("#label").Fill("laptop"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Create key"}).Click())
	token, err := page.GetByTestId("token").TextContent()
	must(t, err)
	if !strings.HasPrefix(token, "mak_") {
		t.Fatalf("token: %q", token)
	}
	copyBtn := page.GetByTestId("new-key").GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Copy"})
	must(t, copyBtn.First().Click())
	clip, err := page.Evaluate("navigator.clipboard.readText()")
	must(t, err)
	if clip != token {
		t.Fatalf("clipboard %q, want token", clip)
	}

	uiApproveFromPhone(t, e, page, token)

	key := page.GetByTestId("key").Filter(playwright.LocatorFilterOptions{HasText: "laptop"})
	activity, err := key.GetByTestId("key-activity").TextContent()
	must(t, err)
	if strings.Contains(activity, "never") {
		t.Fatalf("key activity after a successful call: %q", activity)
	}
	must(t, key.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Revoke"}).Click())
	must(t, expect.Locator(key.GetByText("revoked")).ToBeVisible())

	must(t, page.Locator("#up-name").Fill("mine"))
	must(t, page.Locator("#up-url").Fill("https://example.invalid/mcp"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Add server"}).Click())
	own := page.GetByTestId("server").Filter(playwright.LocatorFilterOptions{HasText: "mine"})
	must(t, own.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Tools"}).Click())
	dialog := page.Locator("#tools-dialog")
	must(t, expect.Locator(dialog).ToBeVisible())
	must(t, expect.Locator(dialog.Locator("[data-tools-status]")).ToContainText("Could not reach mine"))
	must(t, dialog.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Close"}).Click())
	echo := page.GetByTestId("server").Filter(playwright.LocatorFilterOptions{HasText: "global"}).First()
	must(t, echo.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Tools"}).Click())
	must(t, expect.Locator(dialog.Locator("[data-tools-list] li").First()).ToContainText("echo"))
	must(t, dialog.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Close"}).Click())
	must(t, own.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Delete"}).Click())
	must(t, expect.Locator(own).ToHaveCount(0))

	gotoPath(t, page, "/portal/audit")
	must(t, expect.Locator(page.GetByTestId("audit-row").First()).ToContainText("echo__echo"))

	gotoPath(t, page, "/admin")
	bob := page.GetByTestId("user-row").Filter(playwright.LocatorFilterOptions{HasText: "bob"})
	must(t, bob.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "New invite link"}).Click())
	must(t, expect.Locator(page.GetByTestId("new-invite")).ToContainText("/invite/"))
}

// uiSetPushTarget saves the fake ntfy as push target through the portal form.
func uiSetPushTarget(t *testing.T, e *env, page playwright.Page) {
	t.Helper()
	must(t, expect.Locator(page.GetByText("No push target set")).ToBeVisible())
	must(t, page.GetByRole("link", playwright.PageGetByRoleOptions{Name: "Set one in Settings"}).Click())
	must(t, page.Locator("#ntfy-url").Fill(e.ntfy.srv.URL))
	must(t, page.Locator("#ntfy-topic").Fill("e2etopic"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Save and send test push"}).Click())
	must(t, expect.Locator(page.GetByText("Codes for your keys go to")).ToBeVisible())
	gotoPath(t, page, "/")
}

// uiApproveFromPhone triggers a blocked call, checks the push and the portal's
// pending card (same code), and approves it there.
func uiApproveFromPhone(t *testing.T, e *env, page playwright.Page, token string) {
	t.Helper()
	gotoPath(t, page, "/")
	sess := e.mcpClient(t, token)
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "hi"}); !res.IsError {
		t.Fatal("first call must be blocked")
	}
	e.ntfy.waitFor(t, 1)
	pending := page.GetByTestId("pending")
	// No navigation: the portal's poll must reload the page by itself.
	must(t, expect.Locator(pending.GetByTestId("pending-code")).ToHaveText(lastCode(t, e.ntfy),
		playwright.LocatorAssertionsToHaveTextOptions{Timeout: playwright.Float(12000)}))
	must(t, pending.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Approve"}).Click())
	must(t, expect.Locator(page.GetByTestId("result")).ToHaveAttribute("data-tone", "ok"))
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "hi"}); res.IsError {
		t.Fatalf("after approve: %q", textOf(res))
	}
	must(t, page.GetByRole("link", playwright.PageGetByRoleOptions{Name: "Back to portal"}).Click())
	uiEndSession(t, page, sess)
}

// uiEndSession ends the laptop key's session in the portal; the next call is
// gated again.
func uiEndSession(t *testing.T, page playwright.Page, sess *mcp.ClientSession) {
	t.Helper()
	key := page.GetByTestId("key").Filter(playwright.LocatorFilterOptions{HasText: "laptop"})
	must(t, key.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "End session"}).Click())
	must(t, expect.Locator(key.GetByTestId("key-activity")).ToContainText("not authorized"))
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "hi"}); !res.IsError {
		t.Fatal("after End session the call must be gated again")
	}
}

func TestUINonAdminAndConsent(t *testing.T) {
	e, logs := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{})
	uiAcceptInvite(t, page, logs, "bob")
	must(t, expect.Locator(page.GetByRole("link", playwright.PageGetByRoleOptions{Name: "Admin"})).ToHaveCount(0))

	gotoPath(t, page, "/oauth/authorize?response_type=code&client_id=e2e&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2Fcb"+
		"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=s")
	heading := page.GetByRole("heading", playwright.PageGetByRoleOptions{Name: "Authorize identity"})
	must(t, expect.Locator(heading).ToBeVisible())
	must(t, expect.Locator(page.GetByRole("note")).ToContainText("Every tool call still requires a one-time code"))
}

func TestUIThemeAutoLightDark(t *testing.T) {
	e, _ := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{ColorScheme: playwright.ColorSchemeDark})
	gotoPath(t, page, "/login")
	html := page.Locator("html")
	must(t, expect.Locator(html).ToHaveAttribute("data-theme", "dark"))
	if got := attr(t, page, `[data-theme-set="auto"]`, "aria-pressed"); got != "true" {
		t.Fatalf("auto must be the default, aria-pressed=%q", got)
	}
	darkBG := bodyBackground(t, page)

	must(t, page.Locator(`[data-theme-set="light"]`).Click())
	must(t, expect.Locator(html).ToHaveAttribute("data-theme", "light"))
	_, err := page.Reload()
	must(t, err)
	must(t, expect.Locator(html).ToHaveAttribute("data-theme", "light"))
	if bodyBackground(t, page) == darkBG {
		t.Fatal("light and dark backgrounds are identical")
	}

	must(t, page.Locator(`[data-theme-set="auto"]`).Click())
	must(t, expect.Locator(html).ToHaveAttribute("data-theme", "dark"))
	must(t, page.EmulateMedia(playwright.PageEmulateMediaOptions{ColorScheme: playwright.ColorSchemeLight}))
	must(t, expect.Locator(html).ToHaveAttribute("data-theme", "light"))
}

func bodyBackground(t *testing.T, page playwright.Page) string {
	t.Helper()
	v, err := page.Evaluate("getComputedStyle(document.body).backgroundColor")
	must(t, err)
	return v.(string)
}

func TestUIMobileNoHorizontalScroll(t *testing.T) {
	e, logs := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 375, Height: 800},
	})
	uiAcceptInvite(t, page, logs, "alice")
	must(t, page.Locator("#label").Fill("phone"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Create key"}).Click())
	for _, path := range []string{"", "/portal/audit", "/admin"} {
		if path != "" {
			gotoPath(t, page, path)
		}
		overflow, err := page.Evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
		must(t, err)
		if overflow == true {
			t.Fatalf("%q scrolls horizontally at 375px", path)
		}
	}
}

// addVirtualAuthenticator gives the page a platform authenticator that
// always verifies the user.
func addVirtualAuthenticator(t *testing.T, page playwright.Page) {
	t.Helper()
	cdp, err := page.Context().NewCDPSession(page)
	must(t, err)
	_, err = cdp.Send("WebAuthn.enable", map[string]any{})
	must(t, err)
	_, err = cdp.Send("WebAuthn.addVirtualAuthenticator", map[string]any{"options": map[string]any{
		"protocol": "ctap2", "transport": "internal", "hasResidentKey": true,
		"hasUserVerification": true, "isUserVerified": true, "automaticPresenceSimulation": true,
	}})
	must(t, err)
}

func TestUISettingsPasswordAndPasskeys(t *testing.T) {
	e, logs := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{})
	addVirtualAuthenticator(t, page)
	uiAcceptInvite(t, page, logs, "alice")

	gotoPath(t, page, "/settings")
	must(t, page.Locator("#passkey-name").Fill("e2e key"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Add passkey"}).Click())
	must(t, expect.Locator(page.GetByText("Passkey added.")).ToBeVisible())
	must(t, expect.Locator(page.GetByTestId("passkey")).ToContainText("e2e key"))

	must(t, page.Locator("#current").Fill("alice-password-1"))
	must(t, page.Locator("#new-password").Fill("alice-password-2"))
	must(t, page.Locator("#new-password2").Fill("alice-password-2"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Change password"}).Click())
	must(t, expect.Locator(page.GetByText("Password changed.")).ToBeVisible())

	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Log out"}).Click())
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Sign in with a passkey"}).Click())
	must(t, expect.Locator(page.GetByTestId("username")).ToHaveText("alice"))

	gotoPath(t, page, "/settings")
	must(t, expect.Locator(page.GetByTestId("passkey")).ToContainText("last used 20"))
	must(t, page.GetByTestId("passkey").GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Delete"}).Click())
	must(t, expect.Locator(page.GetByText("Passkey removed.")).ToBeVisible())
	must(t, expect.Locator(page.GetByTestId("passkey")).ToHaveCount(0))
}

func TestUIPasskeysUnavailable(t *testing.T) {
	e, _ := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{})
	// Simulate a browser that offers no WebAuthn API (e.g. some iOS browsers).
	must(t, page.AddInitScript(playwright.Script{Content: playwright.String(
		`Object.defineProperty(navigator, "credentials", {value: undefined}); delete window.PublicKeyCredential;`)}))
	gotoPath(t, page, "/login")
	button := page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Sign in with a passkey"})
	must(t, expect.Locator(button).ToBeDisabled())
	must(t, expect.Locator(page.GetByText("This browser does not offer passkeys")).ToBeVisible())
}
