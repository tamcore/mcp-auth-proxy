# Usage

## Users and invites

The instance is multi-user. Usernames are declared in the config (`users:`); admins only via `admins:`. A configured user missing from the database is created on start with a **single-use invite link** (`{base_url}/invite/{token}`, logged on every start until used) through which they set their own password — no passwords are handed over in plaintext. Only the newest link per user is valid, invite tokens are stored as hashes only, and links never appear in the web UI except once, right after an admin mints one.

Admins (`/admin`) can temporarily disable users (their keys stop working immediately), see which users still have an invite pending, and mint new invite links. The page also shows activity for the instance and per user: last active, last successful tool call, last granted and denied authorization, tool calls (audit log entries, so within `audit.retention`), granted/denied/expired authorization counts, pending requests, and active/revoked keys. The values come from the database and survive restarts.

## Web portal

At `{base_url}/login` a user logs in with username and password, or with a passkey, and reaches a self-contained portal (same-origin CSS and JS only, no external assets; light, dark, or auto theme, auto follows the system and is the default) to:

- create API keys for the globally configured MCP servers available to them, and change a key's servers later; optionally set a per-key session TTL (1m to 168h, empty follows `session_ttl`; a change applies from the next authorization); each key shows when it was last seen and last succeeded;
- run the OAuth flow for registered clients;
- add their **own** MCP servers (stored in the database, visible only to them); a URL server must answer MCP `initialize` and `tools/list` when it is added, so the proxy never talks to other URLs on a user's behalf;
- link their own account at an OAuth upstream ("Link my account");
- view their **audit log**: which client called which tool with which parameters (responses optional via `audit.log_responses`, entries garbage-collected after `audit.retention`, default 30 days).

Config upstreams may be global or restricted via `users: [alice]`; a user's own upstreams always win over same-named global ones.

Open requests are always listed at the top of the portal with their code and Approve/Deny buttons; the page reloads itself when requests appear or resolve. Approving in the portal is equivalent to the Approve button in the push.

## Push notifications

Push notifications are per user. Under **Settings** every user enters their own ntfy server, topic and optional access token. Saving checks that the URL is https (plain http only for loopback), that `/v1/health` reports a healthy ntfy server, and sends a test push. Without a push target, codes appear only in the portal. Keys created with the CLI without `--user` have no owner; their codes and Approve/Deny URLs are logged. A failed publish is logged at WARN.

Codes can also go **directly to browsers and phones** via Web Push, in addition to ntfy and without any app or account. Under **Settings → This browser and other devices**, "Enable on this device" asks for notification permission, subscribes the browser, and sends a test push through it; the device is stored only if that test push succeeds, so the endpoint is proven to be a real push service. Every auth request then goes to all subscribed devices, end-to-end encrypted (RFC 8291): the browser vendor's push service (Google, Mozilla, Apple) sees only ciphertext. Approve/Deny buttons in the notification work on Android and on desktop Chrome, Edge and Firefox; Safari shows the notification without buttons, and a tap opens the portal. The portal is an installable web app: where the browser supports it (Chrome, Edge, Android), an "Install as app" button appears next to it. On iPhone and iPad (iOS 16.4+), push works only in the Home Screen app; the page shows how to add it (Share, then Add to Home Screen). Devices the push service reports as gone are removed automatically; others are removed under Settings. The proxy signs its pushes with a VAPID key pair it creates once in `{state_dir}/vapid.json` (mode 0600); losing that file invalidates all subscriptions, and each device has to be enabled again.

## Settings and passkeys

Under **Settings** (`/settings`) users change their password (all their other browser sessions are logged out), manage **passkeys** (add, see last use, delete) and set their push target. The login page offers "Sign in with a passkey" (discoverable credentials, no username needed; the authenticator must verify the user with a PIN or biometric). Logging out ends every web session of the user, on all devices. Five failed password logins in a row lock that username for a minute. The passkey relying party is derived from `base_url`: its host is the RP ID, so `base_url` must use https and a host name, and must not change once passkeys exist.

## The OTP contract (what your AI client sees)

1. The client calls a proxied tool (`{upstream}__{tool}`). `tools/list` and the `auth` tool are never gated; every proxied tool call is.
2. Without a live session the call returns an error-shaped result:

   > Blocked: tool "echo__echo" on key "claude-laptop" requires a one-time code. Ask the owner for the 5-digit code from their phone notification or the web portal (expires …). Then call the `auth` tool with that code (argument `otp`) and retry this exact tool call.

3. You get an ntfy push with the 5-digit code (3-minute expiry, 3 attempts) and Approve/Deny buttons; the portal shows the same request. A new blocked call within 30s does not push again.
4. The client calls `auth` with `{"otp": "12345"}`. On success:

   > Session authorized until 2025-01-01T20:00:00Z. Retry the tool call you were blocked on.

5. The client retries the original call — it now runs. The session allows further calls until it expires (`session_ttl`, default 8h; per-key override in the portal or with `key create --ttl`).

Instead of the code you can tap **Approve** in the notification; the button URL is `{base_url}/approve/{id}?sig=hmac-sha256(id, sign.secret)` (the signing secret lives at `{state_dir}/sign.secret`, mode 0600). A wrong or missing signature is a 403. Opening the URL in a browser (GET) only shows a confirmation button; only the POST acts, so link previews cannot approve.

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

`key create` prints the token exactly once. If that output cannot be written (for example a closed pipe), the command fails and names the stored key: revoke it and create a new one.
