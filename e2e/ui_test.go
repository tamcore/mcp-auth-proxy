//go:build e2e

package e2e

import (
	"strings"
	"sync"
	"testing"

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

// uiAcceptInvite follows the user's invite link from the login page and sets
// a password, leaving the page logged in on the portal.
func uiAcceptInvite(t *testing.T, page playwright.Page, user string) {
	t.Helper()
	gotoPath(t, page, "/login")
	must(t, page.Locator("li", playwright.PageLocatorOptions{HasText: user}).
		GetByRole("link", playwright.LocatorGetByRoleOptions{Name: "set password"}).Click())
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
	e, _ := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{
		Permissions: []string{"clipboard-read", "clipboard-write"},
	})
	uiAcceptInvite(t, page, "alice")
	must(t, expect.Locator(page.GetByRole("link", playwright.PageGetByRoleOptions{Name: "Admin"})).ToBeVisible())

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
	must(t, key.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Revoke"}).Click())
	must(t, expect.Locator(key.GetByText("revoked")).ToBeVisible())

	must(t, page.Locator("#up-name").Fill("mine"))
	must(t, page.Locator("#up-url").Fill("https://example.invalid/mcp"))
	must(t, page.GetByRole("button", playwright.PageGetByRoleOptions{Name: "Add server"}).Click())
	own := page.GetByTestId("server").Filter(playwright.LocatorFilterOptions{HasText: "mine"})
	must(t, own.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "Delete"}).Click())
	must(t, expect.Locator(own).ToHaveCount(0))

	gotoPath(t, page, "/portal/audit")
	must(t, expect.Locator(page.GetByTestId("audit-row").First()).ToContainText("echo__echo"))

	gotoPath(t, page, "/admin")
	bob := page.GetByTestId("user-row").Filter(playwright.LocatorFilterOptions{HasText: "bob"})
	must(t, bob.GetByRole("button", playwright.LocatorGetByRoleOptions{Name: "New invite link"}).Click())
	must(t, expect.Locator(page.GetByTestId("new-invite")).ToContainText("/invite/"))
}

// uiApproveFromPhone triggers a blocked call and opens the ntfy Approve link
// in the browser, as the owner would on the phone.
func uiApproveFromPhone(t *testing.T, e *env, page playwright.Page, token string) {
	t.Helper()
	sess := e.mcpClient(t, token)
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "hi"}); !res.IsError {
		t.Fatal("first call must be blocked")
	}
	e.ntfy.waitFor(t, 1)
	gotoPath(t, page, actionURL(t, e.ntfy, "Approve"))
	must(t, expect.Locator(page.GetByTestId("result")).ToHaveAttribute("data-tone", "ok"))
	if res := callTool(t, sess, echoTool, map[string]any{textArg: "hi"}); res.IsError {
		t.Fatalf("after approve: %q", textOf(res))
	}
	gotoPath(t, page, "/")
}

func TestUINonAdminAndConsent(t *testing.T) {
	e, _ := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{})
	uiAcceptInvite(t, page, "bob")
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
	e, _ := startMultiUserEnv(t)
	page := newPage(t, e, playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 375, Height: 800},
	})
	uiAcceptInvite(t, page, "alice")
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
