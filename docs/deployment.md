# Deployment

Work through the checklist in [SECURITY.md](../SECURITY.md#deployment-checklist) before you expose an instance.

## Release artifacts

Each release has archives for linux and darwin (amd64, arm64), a multi-arch image `ghcr.io/tamcore/mcp-auth-proxy`, and the Helm chart at `oci://ghcr.io/tamcore/charts/mcp-auth-proxy`. The checksum file and every image are signed keylessly with cosign by the release workflow. Verify a download with:

```sh
cosign verify-blob --bundle mcp-auth-proxy_<version>_SHA256SUMS.bundle \
  --certificate-identity-regexp '^https://github\.com/tamcore/mcp-auth-proxy/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  mcp-auth-proxy_<version>_SHA256SUMS
sha256sum --ignore-missing -c mcp-auth-proxy_<version>_SHA256SUMS
```

Verify an image the same way, and deploy it by digest:

```sh
cosign verify ghcr.io/tamcore/mcp-auth-proxy:<version> \
  --certificate-identity-regexp '^https://github\.com/tamcore/mcp-auth-proxy/\.github/workflows/release\.yaml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Container image

The image is distroless, runs as `65532:65532`, has no shell, and works with a read-only root filesystem. All state lives in `/data`; mount a directory there that `65532` can write.

```sh
mkdir -p data && sudo chown 65532:65532 data
docker run -d -p 8080:8080 \
  -v "$PWD/config.yaml:/etc/mcp-auth-proxy/config.yaml:ro" \
  -v "$PWD/data:/data" \
  -e MCP_PROXY_LISTEN_ADDR=0.0.0.0:8080 -e MCP_PROXY_STATE_DIR=/data \
  ghcr.io/tamcore/mcp-auth-proxy:<version> \
  serve --config /etc/mcp-auth-proxy/config.yaml
```

## Kubernetes

The Helm chart in [charts/mcp-auth-proxy](../charts/mcp-auth-proxy) runs a single-replica `Recreate` deployment (one SQLite database, one signing secret) with a PVC for `/data` (an `emptyDir` with `persistence.enabled=false`, which loses all state on restart) and the config in a Secret, because upstream headers and OAuth client secrets in it are credentials.

```sh
helm install mcp-auth-proxy oci://ghcr.io/tamcore/charts/mcp-auth-proxy \
  --set config.baseURL=https://mcp.example.com \
  --set 'config.users[0]=alice' --set 'config.admins[0]=alice'
```

Passkeys need https. With `httpRoute.httpsRedirect.enabled` the chart adds a permanent http → https redirect on the gateway's http listener, and the proxy sends HSTS whenever `base_url` is https. Pin `httpRoute.parentRefs[].sectionName` to the https listener; otherwise the app route also serves plain http.

The image trusts only public CAs. If a user's ntfy server or an upstream uses a private CA, pass its root certificate: `--set-file extraCACerts=root-ca.crt` (added to the system roots via `SSL_CERT_DIR`).

## HTTP routes

App listener (`listen_addr`): `POST|GET /mcp` (Bearer auth), `/mcp/{token}` (path auth), `/oauth/authorize`, `/oauth/consent`, `/oauth/token`, `/approve/{id}?sig=`, `/deny/{id}?sig=`, and the web UI.

Ops listener (`ops_listen_addr`): `/metrics`, `/healthz`, and `/readyz` (database reachable) only. Never expose it.

## Metrics

`/metrics` carries the standard Go and process metrics, `mcp_proxy_build_info{version,commit}`, and per-key series. `user` is the key owner's username and `key` the key label, both lowercase; a key without an owner has `user=""`, and an owner that could not be read `user="unknown"`. Label values are cut at 64 characters, and invalid UTF-8 is replaced.

| Metric | Labels | Meaning |
|--------|--------|---------|
| `mcp_proxy_tool_calls_total` | `user`, `key`, `upstream`, `tool`, `outcome` | proxied calls; outcome `success`, `tool_error` (the upstream answered with an error), `upstream_error`, `blocked` |
| `mcp_proxy_tool_duration_seconds` | `upstream`, `tool` | latency of calls sent to the upstream (including transport errors), not of blocked calls |
| `mcp_proxy_auth_events_total` | `user`, `key`, `result` | `auth` tool calls; result `granted`, `wrong_code`, `expired`, `exhausted`, `no_challenge`, `error` |
| `mcp_proxy_challenges_total` | `user`, `key` | one-time-code challenges created |
| `mcp_proxy_key_last_seen_timestamp_seconds` | `user`, `key` | last authenticated request |
| `mcp_proxy_key_last_success_timestamp_seconds` | `user`, `key` | last successful tool call |
| `mcp_proxy_key_last_authorized_timestamp_seconds` | `user`, `key` | start of the current or last session |
| `mcp_proxy_key_authorized_until_timestamp_seconds` | `user`, `key` | end of the current or last session |
| `mcp_proxy_key_authorized` | `user`, `key` | 1 while a session is live |
| `mcp_proxy_key_auth_pending` | `user`, `key` | 1 while a one-time code is open |

The `mcp_proxy_key_*` gauges are read from the database on every scrape, so they are right after a restart; revoked keys are not reported, and a timestamp that never happened is left out. Keys of one user with the same label share their series. At most 500 distinct upstream/tool pairs get their own series; further ones count as `tool="other"`. Arguments, results, one-time codes and the proxy's tokens are never labels; key labels and names are whatever users and upstreams chose.

## Logs

`serve` logs JSON to stdout: one `http request` line per request (credential path segments redacted, no query string) and one `tool call` line per audit entry. Every other command logs to stderr.

## Upgrades and backups

Schema migrations run on start and are forward-only. Before it migrates an existing database, the proxy writes a snapshot `proxy.db.pre-v<N>.bak` next to it; prune old snapshots by hand. A build refuses a database newer than itself, and one whose recorded migrations (name and checksum) differ from its own. A leftover snapshot is reused only if it is a valid database at the expected version. Back up `proxy.db` and `sign.secret` together.
