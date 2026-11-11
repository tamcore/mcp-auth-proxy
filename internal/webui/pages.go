package webui

import (
	"html"
	"strings"

	"github.com/tamcore/mcp-auth-proxy/internal/config"
	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func esc(s string) string { return html.EscapeString(s) }

// baseCSS is the entire stylesheet, inlined into every page so the UI works
// air-gapped: system font stack, no external CSS, images, or fonts.
const baseCSS = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0;
  background: #f4f5f7; color: #1c1e21; line-height: 1.5; }
@media (prefers-color-scheme: dark) { body { background: #17181c; color: #e6e7ea; } }
main { max-width: 860px; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.4rem; margin: 0 0 1rem; }
h2 { font-size: 1.05rem; margin: 1.6rem 0 .5rem; }
a { color: #2563eb; }
@media (prefers-color-scheme: dark) { a { color: #7aa2f7; } }
.card { background: #fff; border: 1px solid #e2e4e9; border-radius: 10px;
  padding: 1rem 1.2rem; margin-bottom: 1rem; }
@media (prefers-color-scheme: dark) { .card { background: #1f2127; border-color: #33363f; } }
label { display: block; margin: .4rem 0; }
input[type=text], input[type=password], input[type=url] { padding: .4rem .5rem; border: 1px solid #c9ccd3;
  border-radius: 6px; min-width: 16rem; background: transparent; color: inherit; }
button { padding: .45rem .9rem; border: 0; border-radius: 6px; background: #2563eb; color: #fff;
  cursor: pointer; font-size: .9rem; }
button:hover { background: #1d4fd7; }
button.ghost { background: transparent; color: inherit; border: 1px solid #c9ccd3; }
code { background: rgba(127,127,127,.15); padding: .1rem .35rem; border-radius: 5px;
  word-break: break-all; font-size: .85rem; }
table { border-collapse: collapse; width: 100%; font-size: .85rem; }
th, td { border: 1px solid #e2e4e9; padding: .35rem .5rem; text-align: left; vertical-align: top; }
@media (prefers-color-scheme: dark) { th, td { border-color: #33363f; } }
th { background: rgba(127,127,127,.12); }
.err { color: #d33; }
.muted { color: #6b7280; font-size: .85rem; }
.row { display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
ul { padding-left: 1.2rem; }
form.inline { display: inline; }
`

func page(title, body string) string {
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + esc(title) + `</title><style>` + baseCSS + `</style></head>
<body><main>` + body + `</main></body></html>`
}

func portalPage(user *store.User, globals []config.UpstreamConfig, own []*store.UserUpstream,
	keys []*store.Key, cfg *config.Config, newToken string) string {
	var b strings.Builder
	b.WriteString(`<h1>mcp-auth-proxy</h1>
<div class="card row"><span>Logged in as <strong>` + esc(user.Username) + `</strong></span>
<a href="/portal/audit">audit log</a>{{if .}} · <a href="/admin">admin</a>{{end}}
<form class="inline" method="post" action="/logout"><button class="ghost">Log out</button></form></div>`)
	if newToken != "" {
		b.WriteString(`<div class="card"><strong>New key — token shown once:</strong><br><code>` + esc(newToken) +
			`</code><br><span class="muted">MCP URL:</span> <code>` + esc(strings.TrimRight(cfg.BaseURL, "/")) +
			`/mcp/` + esc(newToken) + `</code></div>`)
	}
	b.WriteString(`<div class="card"><h2>Available MCP servers</h2><ul>`)
	for _, u := range globals {
		src := u.URL
		if src == "" {
			src = "command: " + strings.Join(u.Command, " ")
		}
		tag := "global"
		if !u.Global() {
			tag = "shared with you"
		}
		b.WriteString("<li><strong>" + esc(u.Name) + "</strong> <span class=\"muted\">(" + tag + ")</span> — " +
			esc(src) + "</li>")
	}
	for _, u := range own {
		src := u.URL
		if src == "" {
			src = "command: " + strings.Join(u.Command, " ")
		}
		b.WriteString(`<li><strong>` + esc(u.Name) + `</strong> <span class="muted">(own)</span> — ` + esc(src) +
			` <form class="inline" method="post" action="/portal/upstream/delete">` +
			`<input type="hidden" name="id" value="` + esc(u.ID) + `"><button class="ghost">delete</button></form></li>`)
	}
	b.WriteString(`</ul></div>
<div class="card"><h2>Create an API key for an AI client</h2>
<form method="post" action="/portal/key">
<label>Label <input type="text" name="label" maxlength="80" placeholder="e.g. Claude on my laptop"></label>`)
	for _, u := range globals {
		b.WriteString(`<label><input type="checkbox" name="upstream" value="` + esc(u.Name) + `" checked> ` +
			esc(u.Name) + `</label>`)
	}
	for _, u := range own {
		b.WriteString(`<label><input type="checkbox" name="upstream" value="` + esc(u.Name) + `" checked> ` +
			esc(u.Name) + ` (own)</label>`)
	}
	b.WriteString(`<br><button type="submit">Create key</button></form></div>
<div class="card"><h2>Add your own MCP server</h2>
<form method="post" action="/portal/upstream">
<label>Name <input type="text" name="name" required maxlength="40"></label>
<label>URL <input type="url" name="url" placeholder="https://…/mcp"></label>
<label>or stdio command <input type="text" name="command" placeholder="binary arg…"></label>
<button type="submit">Add</button></form></div>
<div class="card"><h2>Your keys</h2>`)
	if len(keys) == 0 {
		b.WriteString(`<p class="muted">none yet</p>`)
	}
	b.WriteString("<ul>")
	for _, k := range keys {
		state := "active"
		if k.Revoked() {
			state = "revoked"
		}
		b.WriteString(`<li>` + esc(k.ID) + ` · <strong>` + esc(k.Label) + `</strong> · ` + esc(k.Kind) +
			` · upstreams: ` + esc(strings.Join(k.Upstreams, ",")) +
			` · <span class="muted">` + state + `</span>`)
		if !k.Revoked() {
			b.WriteString(` <form class="inline" method="post" action="/portal/key/revoke">` +
				`<input type="hidden" name="id" value="` + esc(k.ID) + `"><button class="ghost">revoke</button></form>`)
		}
		b.WriteString("</li>")
	}
	b.WriteString(`</ul></div>
<div class="card"><h2>Connect an OAuth client</h2><ul>`)
	for _, c := range cfg.OAuth.Clients {
		b.WriteString(`<li>` + esc(c.Name) +
			` — <span class="muted">start the OAuth flow from the client; it lands here after login</span></li>`)
	}
	if len(cfg.OAuth.Clients) == 0 {
		b.WriteString(`<li class="muted">no OAuth clients registered in config</li>`)
	}
	b.WriteString(`</ul></div>`)
	return page("mcp-auth-proxy", b.String())
}

func auditPage(user *store.User, entries []*store.AuditEntry, auditCfg config.AuditConfig) string {
	var b strings.Builder
	b.WriteString(`<h1>Audit log</h1>
<div class="card row"><span>user <strong>` + esc(user.Username) + `</strong></span>
<a href="/">back to portal</a>
<span class="muted">retention ` + auditCfg.Retention.String() +
		` · responses ` + responsesLabel(auditCfg) + `</span></div>`)
	if len(entries) == 0 {
		b.WriteString(`<div class="card"><p class="muted">no tool calls recorded yet</p></div>`)
		return page("audit log", b.String())
	}
	b.WriteString(`<div class="card"><table><tr><th>time (UTC)</th><th>key</th><th>tool</th>` +
		`<th>arguments</th><th>response</th></tr>`)
	for _, e := range entries {
		ts := esc(e.CreatedAt.Format("2006-01-02 15:04:05"))
		b.WriteString("<tr><td>" + ts + "</td><td>" + esc(e.KeyLabel) +
			"</td><td>" + esc(e.ToolName) + "</td><td><code>" + esc(e.Arguments) + "</code></td><td>")
		if e.Response != nil {
			b.WriteString("<code>" + esc(*e.Response) + "</code>")
		} else {
			b.WriteString(`<span class="muted">—</span>`)
		}
		b.WriteString("</td></tr>")
	}
	b.WriteString("</table></div>")
	return page("audit log", b.String())
}

func responsesLabel(c config.AuditConfig) string {
	if c.LogResponses {
		return "logged"
	}
	return "not logged"
}
