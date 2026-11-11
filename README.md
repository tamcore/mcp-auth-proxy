# mcp-auth-proxy

A personal [Model Context Protocol](https://modelcontextprotocol.io) auth proxy.
It fronts several MCP servers ("upstreams") behind **one endpoint**. Each AI
client (Claude, ChatGPT, Cursor, ...) gets its own key and MCP URL, and **every
tool call is gated behind a one-time code pushed to your phone via
[ntfy](https://ntfy.sh)**.

A blocked call never fails silently: it returns an LLM-readable message telling
the client to ask you for the code, call the `auth` tool with it, and then retry
the exact same call. A valid session allows unlimited calls for a configurable
TTL (default 8h, per-key override). The ntfy notification also carries
**Approve / Deny** buttons (HMAC-signed URLs) as an alternative to typing the
code.

## Multi-user

The instance is multi-user. Usernames are declared in the config (`users:`);
admins only via `admins:`. A configured user missing from the database is
created on start with a **single-use invite link** (`{base_url}/invite/{token}`,
logged on every start until used) through which they set their own password —
no passwords are handed over in plaintext. Only the newest link per user is
valid, invite tokens are stored as hashes only, and links never appear in the
web UI except once, right after an admin mints one.

At `{base_url}/login` a user logs in with username+password only and reaches a
self-contained portal (same-origin CSS and JS only, no external assets; light,
dark, or auto theme, auto follows the system and is the default) to: create API keys for
globally configured MCP servers available to them, run the OAuth flow for
registered clients, add their **own** MCP servers (stored in the database,
visible only to them), and view their **audit log** — which client called which
tool with which parameters (responses optional via `audit.log_responses`,
entries garbage-collected after `audit.retention`, default 30 days).

Config upstreams may be global or restricted via `users: [alice]`; a user's own
upstreams always win over same-named global ones. Admins (`/admin`) can
temporarily disable users (their keys stop working immediately), see which
users still have an invite pending, and mint new invite links.

## Security model: identity is never authorization

OAuth 2.x runs on both sides, but it only proves *who* is calling:

- **Client → proxy**: each client uses a static `mak_…` key or an OAuth `map_…`
  access token. This is its *identity*.
- **Proxy → upstream**: optionally an OAuth token per upstream, linked once by
  an admin at `/admin` ("Link") and refreshed automatically. Register
  `{base_url}/admin/upstream/callback` as redirect URI at the upstream's
  authorization server. The CLI `upstream link` (loopback redirect) still works
  where a browser and the database are on the same machine.

Logging in via OAuth grants an identity — the right to list tools and ask for
authorization. **Every tool call still requires the one-time code.** There is no
path from "authenticated" to "authorized".

Tokens are shown exactly once at creation; only sha256-hex hashes are stored or
logged.

## Quickstart

```sh
go build -o mcp-auth-proxy ./cmd/mcp-auth-proxy

# 1. Configure (see config.example.yaml)
cp config.example.yaml config.yaml
$EDITOR config.yaml        # set base_url, state_dir, ntfy topic, upstreams

# 2. Run the proxy
./mcp-auth-proxy serve --config config.yaml

# 3. Create a key for a client (token is printed exactly once)
./mcp-auth-proxy key create --label "claude-laptop" --config config.yaml
# Token (shown once): mak_…
# MCP URL:           http://127.0.0.1:8080/mcp/mak_…

# 4. Point the AI client at the MCP URL (or use the Bearer header on /mcp)
```

For push notifications, create an ntfy topic and set:

```yaml
ntfy:
  url: https://ntfy.sh
  topic: your-topic
  enabled: true
```

With `enabled: false` the code and the Approve/Deny URLs are only logged, which
is handy for local testing.

## The OTP contract (what your AI client sees)

1. The client calls a proxied tool (`{upstream}__{tool}`). `tools/list` is never
   gated; every `tools/call` is.
2. Without a live session the call returns an error-shaped result:

   > Blocked: tool "echo__echo" on key "claude-laptop" requires a one-time code.
   > Ask the owner for the 5-digit code from the phone notification (expires …).
   > Then call the `auth` tool with that code (argument `otp`) and retry this
   > exact tool call.

3. You get an ntfy push with the 5-digit code (3-minute expiry, 3 attempts) and
   Approve/Deny buttons. A new blocked call within 30s does not push again.
4. The client calls `auth` with `{"otp": "12345"}`. On success:

   > Session authorized until 2025-01-01T20:00:00Z. Retry the tool call you were
   > blocked on.

5. The client retries the original call — it now runs.

Instead of the code you can tap **Approve** in the notification; the button URL
is `{base_url}/approve/{id}?sig=hmac-sha256(id, sign.secret)` (the signing secret
lives at `{state_dir}/sign.secret`, mode 0600). A wrong or missing signature is
a 403.

## Commands

```
mcp-auth-proxy serve                          # run the proxy
mcp-auth-proxy key create --label L [--upstreams a,b] [--ttl 8h] [--json]
mcp-auth-proxy key list
mcp-auth-proxy key revoke <id>                # kills session + pending challenge
mcp-auth-proxy upstream list|status
mcp-auth-proxy upstream link <name>           # one-time OAuth linking flow
mcp-auth-proxy doctor                         # config/state/secret/ntfy checks
mcp-auth-proxy dev-echo                       # tiny stdio MCP echo server (fake upstream)
```

HTTP routes: `POST|GET /mcp` (Bearer auth), `/mcp/{token}` (path auth),
`/oauth/authorize`, `/oauth/consent`, `/oauth/token`, `/approve/{id}?sig=`,
`/deny/{id}?sig=`, `/metrics`.

## Configuration reference

See [config.example.yaml](config.example.yaml). Every key has an environment
override prefixed `MCP_PROXY_` (e.g. `MCP_PROXY_SESSION_TTL=4h`,
`MCP_PROXY_NTFY_TOPIC=…`).

| Key | Default | Meaning |
|-----|---------|---------|
| `base_url` | `http://127.0.0.1:8080` | canonical public URL (button URLs, MCP URL) |
| `listen_addr` | `127.0.0.1:8080` | HTTP listen address |
| `state_dir` | `./data` | holds `proxy.db` and `sign.secret` |
| `session_ttl` | `8h` | session lifetime after auth |
| `otp.digits` / `expiry` / `attempts` / `renotify_floor` | `5` / `3m` / `3` / `30s` | OTP gate tuning |
| `ntfy.url` / `topic` / `enabled` | `https://ntfy.sh` / – / `false` | push settings |
| `upstreams[]` | – | `name` + exactly one of `url` / `command`, optional `headers`, `oauth` |
| `oauth.token_ttl` | `24h` | `map_` access token lifetime (no refresh tokens in v1) |
| `oauth.authorize_code_ttl` | `10m` | single-use authorization code lifetime |
| `oauth.clients[]` | – | registered AS clients (`client_id`, `redirect_uris`, …) |

## Kubernetes

A Helm chart is in [charts/mcp-auth-proxy](charts/mcp-auth-proxy): a
single-replica `Recreate` deployment (one SQLite database, one signing secret)
with a PVC for `/data`, the config in a ConfigMap, and the ntfy topic in a
Secret. Released charts are published to `oci://ghcr.io/tamcore/charts`.

```sh
helm install mcp-auth-proxy oci://ghcr.io/tamcore/charts/mcp-auth-proxy \
  --set config.baseURL=https://mcp.example.com \
  --set ntfy.enabled=true --set ntfy.topic=your-topic
```

## Development

Quality gates (CI runs these plus `-race`, the live suite against a real
garmin-mcp over stdio, and `helm lint`/`helm template` on the chart):

```sh
gofmt -l .                                   # empty
go build ./...
go vet ./...  &&  go vet -tags e2e ./e2e/  &&  go vet -tags live ./live/
go test -count=1 ./...
go test -tags e2e -count=1 -timeout 300s ./e2e/   # includes playwright-go browser tests
LIVE_GARMIN_BIN=/path/to/garmin-mcp go test -tags live -count=1 -timeout 300s ./live/
go mod tidy
golangci-lint run
golangci-lint run --build-tags e2e ./e2e/
golangci-lint run --build-tags live ./live/
helm lint ./charts/mcp-auth-proxy --set config.baseURL=https://mcp.example --set 'config.users[0]=alice'
```

The e2e suite drives the web UI in headless Chromium via playwright-go. The
first run downloads the driver and Chromium; on Linux, install system
libraries once with
`go run github.com/mxschmitt/playwright-go/cmd/playwright install --with-deps --only-shell chromium`.

The stylesheet `internal/ui/assets/app.css` is generated by the Tailwind CSS
v4 standalone CLI and committed, so `go build` needs no Node toolchain. After
changing templates or `internal/ui/src/input.css`, put `tailwindcss` on `PATH`
and run `go generate ./internal/ui`; CI fails if the committed file is stale.

## License

MIT, copyright Philipp Born. See [LICENSE](LICENSE).
