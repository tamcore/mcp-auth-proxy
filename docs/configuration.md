# Configuration

[config.example.yaml](../config.example.yaml) documents every key. Every scalar key has an environment override prefixed `MCP_PROXY_` (dots become underscores), e.g. `MCP_PROXY_SESSION_TTL=4h` or `MCP_PROXY_OTP_DIGITS=6`. `users` and `admins` take a space-separated list (`MCP_PROXY_USERS="alice bob"`). `upstreams` and `oauth.clients` are set in the file only.

| Key | Default | Meaning |
|-----|---------|---------|
| `base_url` | `http://127.0.0.1:8080` | canonical public URL (button URLs, MCP URL, passkey RP ID) |
| `listen_addr` | `127.0.0.1:8080` | HTTP listen address |
| `ops_listen_addr` | `127.0.0.1:9090` | ops listener: `/metrics`, `/healthz`, `/readyz` |
| `state_dir` | `./data` | holds `proxy.db` and `sign.secret` |
| `session_ttl` | `8h` | session lifetime after auth |
| `otp.digits` / `expiry` / `attempts` / `renotify_floor` | `5` / `3m` / `3` / `30s` | OTP gate tuning |
| `users` / `admins` | – | user names; the admin role is set only here |
| `audit.enabled` / `log_responses` / `retention` | `true` / `false` / `720h` | per-user audit log of tool calls |
| `upstreams[]` | – | `name` + exactly one of `url` / `command`, optional `users`, `headers`, `oauth` |
| `oauth.token_ttl` | `24h` | `map_` access token lifetime (no refresh tokens in v1) |
| `oauth.authorize_code_ttl` | `10m` | single-use authorization code lifetime |
| `oauth.clients[]` | – | registered AS clients (`client_id`, `redirect_uris`, …) |

## Upstreams

Each upstream has exactly one of `url` (Streamable HTTP) or `command` (stdio). Tools are exposed to clients as `{name}__{tool}`. `users` restricts an upstream to those users; omit it for a global upstream. With `oauth`, each user links their own account in the portal (see [usage](usage.md#upstream-oauth)).

## Client-facing OAuth

The proxy is an OAuth authorization server (authorization code + PKCE S256) for the clients in `oauth.clients`. A client either uses a static `mak_…` key or obtains a `map_…` access token through this flow. Either one is an identity only: every proxied tool call still needs the one-time code.
