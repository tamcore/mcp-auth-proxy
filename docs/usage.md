# Usage

## Users and invites

The instance is multi-user. Usernames are declared in the config (`users:`); admins only via `admins:`. A configured user missing from the database is created on start with a **single-use invite link** (`{base_url}/invite/{token}`, logged on every start until used) through which they set their own password — no passwords are handed over in plaintext. Only the newest link per user is valid, invite tokens are stored as hashes only, and links never appear in the web UI except once, right after an admin mints one.

Admins (`/admin`) can temporarily disable users (their keys stop working immediately), see which users still have an invite pending, and mint new invite links.

## Web portal

At `{base_url}/login` a user logs in with username and password, or with a passkey, and reaches a self-contained portal (same-origin CSS and JS only, no external assets; light, dark, or auto theme, auto follows the system and is the default) to:

- create API keys for the globally configured MCP servers available to them, and change a key's servers later; each key shows when it was last seen and last succeeded;
- run the OAuth flow for registered clients;
- add their **own** MCP servers (stored in the database, visible only to them); a URL server must answer MCP `initialize` and `tools/list` when it is added, so the proxy never talks to other URLs on a user's behalf;
- link their own account at an OAuth upstream ("Link my account");
- view their **audit log**: which client called which tool with which parameters (responses optional via `audit.log_responses`, entries garbage-collected after `audit.retention`, default 30 days).

Config upstreams may be global or restricted via `users: [alice]`; a user's own upstreams always win over same-named global ones.

Open requests are always listed at the top of the portal with their code and Approve/Deny buttons; the page reloads itself when requests appear or resolve. Approving in the portal is equivalent to the Approve button in the push.

## Push notifications

Push notifications are per user. Under **Settings** every user enters their own ntfy server, topic and optional access token. Saving checks that the URL is https (plain http only for loopback), that `/v1/health` reports a healthy ntfy server, and sends a test push. Without a push target, codes appear only in the portal. Keys created with the CLI without `--user` have no owner; their codes and Approve/Deny URLs are logged. A failed publish is logged at WARN.

## Settings and passkeys

Under **Settings** (`/settings`) users change their password (all their other browser sessions are logged out), manage **passkeys** (add, see last use, delete) and set their push target. The login page offers "Sign in with a passkey" (discoverable credentials, no username needed). The passkey relying party is derived from `base_url`: its host is the RP ID, so `base_url` must use https and a host name, and must not change once passkeys exist.

## The OTP contract (what your AI client sees)

1. The client calls a proxied tool (`{upstream}__{tool}`). `tools/list` and the `auth` tool are never gated; every proxied tool call is.
2. Without a live session the call returns an error-shaped result:

   > Blocked: tool "echo__echo" on key "claude-laptop" requires a one-time code. Ask the owner for the 5-digit code from their phone notification or the web portal (expires …). Then call the `auth` tool with that code (argument `otp`) and retry this exact tool call.

3. You get an ntfy push with the 5-digit code (3-minute expiry, 3 attempts) and Approve/Deny buttons; the portal shows the same request. A new blocked call within 30s does not push again.
4. The client calls `auth` with `{"otp": "12345"}`. On success:

   > Session authorized until 2025-01-01T20:00:00Z. Retry the tool call you were blocked on.

5. The client retries the original call — it now runs. The session allows further calls until it expires (`session_ttl`, default 8h, per-key override).

Instead of the code you can tap **Approve** in the notification; the button URL is `{base_url}/approve/{id}?sig=hmac-sha256(id, sign.secret)` (the signing secret lives at `{state_dir}/sign.secret`, mode 0600). A wrong or missing signature is a 403.

## Upstream OAuth

Every user links their **own** upstream account in the portal; tokens are stored and refreshed per user and never shared. A key only reaches an OAuth upstream with its owner's token. Register `{base_url}/portal/upstream/callback` as redirect URI at the upstream's authorization server. The CLI `upstream link` (loopback redirect) links the slot used by keys without a user.

## Commands

```
mcp-auth-proxy serve                          # run the proxy
mcp-auth-proxy key create --label L [--user U] [--upstreams a,b] [--ttl 8h] [--json]
mcp-auth-proxy key list
mcp-auth-proxy key revoke <id>                # kills session + pending challenge
mcp-auth-proxy upstream list|status
mcp-auth-proxy upstream link <name>           # one-time OAuth linking flow
mcp-auth-proxy doctor                         # config/state/secret/upstream/user checks
mcp-auth-proxy dev-echo                       # tiny stdio MCP echo server (fake upstream)
mcp-auth-proxy version
```
