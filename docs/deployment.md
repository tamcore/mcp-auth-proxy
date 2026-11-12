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

## Logs

`serve` logs JSON to stdout: one `http request` line per request (credential path segments redacted, no query string) and one `tool call` line per audit entry. Every other command logs to stderr.

## Upgrades and backups

Schema migrations run on start and are forward-only. Before it migrates an existing database, the proxy writes a snapshot `proxy.db.pre-v<N>.bak` next to it; prune old snapshots by hand. A build refuses a database newer than itself, and one whose recorded migrations (name and checksum) differ from its own. A leftover snapshot is reused only if it is a valid database at the expected version. Back up `proxy.db` and `sign.secret` together.
