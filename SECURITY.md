# Security policy

## Reporting a vulnerability

Report privately. **Do not open a public issue, pull request, or discussion for a security problem.**

Use GitHub private vulnerability reporting: go to the repository's **Security** tab and choose **Report a vulnerability**. That opens a private advisory visible only to you and the maintainers.

Include, as far as you can:

- what an attacker gains, and what they need to start;
- the affected version or commit;
- reproduction steps, a minimal configuration, and the observed against the expected behavior;
- any log excerpt — with keys, tokens, one-time codes, and passwords removed.

**Never include a real credential, token, or key in a report.** If a report would only make sense with one, say so and send a synthetic equivalent.

Expect an acknowledgement within a few days and an assessment after that. Fixes are released before the advisory is published. Please allow a reasonable disclosure window. There is no bounty.

### In scope

- The tool-call gate: any path by which a `tools/call` reaches an upstream without a valid one-time code, or by which an authenticated identity (key, OAuth token, web session) skips the gate.
- Authentication and authorization: keys, the client-facing OAuth server (PKCE, redirect URI matching, consent), web login, passkeys, invites, and the signed approve/deny links.
- Cross-user exposure: any path by which one user reads, uses, or changes another user's keys, upstream links, push target, or audit entries.
- Credential handling: leakage of a key, an OAuth or upstream token, a one-time code, a password, an ntfy token, or the signing secret — through a log, an error, a response body, a page, metrics, or a file mode.
- Injection, request smuggling, SSRF, open redirects, and path traversal in this server's own code.
- Denial of service that one unauthenticated caller can cause.

### Out of scope

- Vulnerabilities in an upstream MCP server or in ntfy. Report those to their maintainers.
- Findings that need an already-compromised host or a readable state directory.
- An exposed ops listener (`/metrics`, `/healthz`, `/readyz`): it is documented as internal-only. `/metrics` names usernames, key labels and tool names, never arguments, results, codes or tokens.
- Results from automated scanners with no demonstrated impact.

## Supported versions

The most recent release receives security fixes. Older releases do not, and nothing is backported.

Dependency and base-image updates are part of a security fix: the container base image is pinned by multi-architecture index digest, GitHub Actions are pinned by commit SHA, and `govulncheck` and dependency review run in CI.

## What this server holds, and where

All state is under `state_dir`:

| Location | Contents | Mode |
|----------|----------|------|
| `proxy.db` (+ `-wal`, `-shm`) | SQLite database, see below | `0600` |
| `sign.secret` | HMAC key for approve/deny links and web sessions | `0600` |
| `proxy.db.pre-v<N>.bak` | Snapshot taken before a schema migration | as `proxy.db` |

The database stores:

- **Hashes only:** keys, client-facing OAuth access tokens, invite tokens, and one-time codes as SHA-256 hex; passwords as bcrypt. A stolen database yields none of them.
- **Plaintext, because the proxy must present them:** upstream OAuth access and refresh tokens, per-user upstream headers (for example a bearer token), and per-user ntfy tokens. Protect the database and its backups accordingly.
- **No secret:** passkey public keys and sign counts, users, and upstream definitions.
- **Whatever clients send:** audit entries store the full tool arguments (and, with `audit.log_responses`, the results) in the database and the service log. If a client passes a secret as a tool argument, it lands there. Disable `audit.enabled` if that is not acceptable.

Secrets are shown once at creation and never again. Logs are JSON, carry only hashes, and never carry a token or password. Exceptions, because there is no other place to deliver them: for a key without an owner (`key create` without `--user`), the one-time code and the signed Approve/Deny URLs are logged; and `serve` logs the invite URL of every configured user without a password on each start until the invite is used. Restrict who can read the service log.

## Deployment checklist

- [ ] `base_url` is `https` and is the URL users really reach. Passkeys need it; HSTS is sent only then.
- [ ] Plain http redirects to https at the edge.
- [ ] The ops listener is reachable only from the cluster or host, never from the internet.
- [ ] `state_dir` is on local, persistent storage, and exactly one replica runs against it.
- [ ] The database and its backups have owner-only access.
