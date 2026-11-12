# mcp-auth-proxy

A personal [Model Context Protocol](https://modelcontextprotocol.io) auth proxy. It fronts several MCP servers ("upstreams") behind **one endpoint**. Each AI client (Claude, ChatGPT, Cursor, ...) gets its own key and MCP URL, and **every proxied tool call is gated behind a one-time code**, pushed to your phone via [ntfy](https://ntfy.sh) and shown in the web portal.

- **One endpoint, many upstreams**: Streamable HTTP or stdio MCP servers, exposed to clients as `{upstream}__{tool}`.
- **Per-client keys**: revoke one client without touching the others; see when each key was last used.
- **A human in the loop**: a blocked call tells the client to ask you for the code. You type it, or tap **Approve** in the push or the web portal. The session then allows calls for a configurable TTL (default 8h).
- **Multi-user web portal**: invite links instead of shared passwords, passkeys, per-user push targets, per-user upstream OAuth accounts, and an audit log of proxied tool calls.

## Identity is never authorization

Clients authenticate with a static `mak_…` key or an OAuth `map_…` token, and upstreams can use OAuth too. That only proves *who* is calling: the right to list tools and ask for authorization. **Every proxied tool call still requires the one-time code.** There is no path from "authenticated" to "authorized".

## Quick start

Try it locally with the built-in echo upstream:

```sh
go install github.com/tamcore/mcp-auth-proxy/cmd/mcp-auth-proxy@latest

curl -fsSL -o config.yaml https://raw.githubusercontent.com/tamcore/mcp-auth-proxy/master/config.example.yaml
$EDITOR config.yaml        # base_url, users, upstreams

mcp-auth-proxy serve --config config.yaml
```

In a second terminal, create a key for a client. The token is printed exactly once:

```sh
mcp-auth-proxy key create --label claude-laptop --config config.yaml
# Token (shown once): mak_…
# MCP URL:           http://127.0.0.1:8080/mcp/mak_…
```

Point the AI client at the MCP URL, or at `/mcp` with `Authorization: Bearer mak_…`. Call `echo__echo`: the call is blocked, and because a CLI key without `--user` has no owner, the one-time code appears in the proxy's log. Give the code to the client; it calls the `auth` tool and retries.

For real use, sign in to the web portal with the invite link the proxy logs on start for each configured user, create keys there, and set your ntfy push target under **Settings**.

## Documentation

- [Usage](docs/usage.md): portal, invites, push notifications, passkeys, the OTP contract, upstream OAuth, commands.
- [Configuration](docs/configuration.md): every config key and its environment override.
- [Deployment](docs/deployment.md): release verification, container image, Helm chart, routes, logs, upgrades.
- [Development](docs/development.md): quality gates, browser tests, generated files, releases.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). It also lists what the proxy stores and a deployment checklist.

## License

MIT, copyright Philipp Born. See [LICENSE](LICENSE). Third-party licences of everything linked into the binary are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
