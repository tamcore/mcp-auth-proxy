# AGENTS.md

Rules for humans and AI agents that contribute to mcp-auth-proxy. These rules are
binding. Where this file and the code disagree, the code is correct, and you must
fix this file in the same change.

## Project overview

mcp-auth-proxy is a personal MCP auth proxy written in Go. It fronts several MCP
servers ("upstreams") behind one endpoint. Each AI client gets its own key and
MCP URL; every tool call is gated behind a one-time code pushed to the owner's
phone via ntfy.

- Go module: `github.com/tamcore/mcp-auth-proxy`.
- MCP layer: the official `modelcontextprotocol/go-sdk` at the version in
  `go.mod`, on both the server and the client side.
- Storage: SQLite via `modernc.org/sqlite` (pure Go, CGO off) at
  `{state_dir}/proxy.db`, with embedded forward-only migrations.

### Identity is never authorization

OAuth 2.x exists on both sides, but it only grants an *identity*: the right to
list tools and ask for authorization. Every `tools/call` still requires the
one-time code. Do not add any path that lets an authenticated identity skip the
gate.

## Development workflow

1. Plan before you write code for a non-trivial change.
2. TDD for each behavior: failing test, smallest implementation, refactor.
3. Run `golangci-lint run` and `go vet ./...` before you commit.
4. Conventional commits (`feat:`, `fix:`, `test:`, `ci:`, `docs:`, `chore:`),
   one behavior per commit, in small reviewable chunks.

## Package layout

```
cmd/                     main packages only
internal/
  cmd/                   cobra commands and the composition root
  config/                viper parsing, precedence, validation
  store/                 SQLite: migrator, keys, sessions/challenges, oauth, sign secret
  gate/                  OTP challenge/session state machine
  identity/              mak_/map_ credential resolution
  ntfy/                  push publisher + log-only fallback
  mcpserver/             per-key MCP server, namespaced tools, auth tool
  oauthserver/           client-facing OAuth AS + consent page
  upstream/              MCP client pool + OAuth linking/refresh
  server/                HTTP mux: /mcp, /oauth, /approve, /deny, /metrics
  metrics/               prometheus with a closed label vocabulary
migrations/              embedded SQL, forward-only
e2e/                     end-to-end tests (build tag: e2e)
```

## Rules

- All real code under `internal/`; main packages are thin. Files < 400 lines,
  functions < 50 lines, gocyclo <= 15.
- slog JSON to stderr only; stdout carries only MCP frames in stdio contexts and
  machine-readable command output (e.g. `key create --json`).
- Secrets are unprintable: never in String(), MarshalJSON, errors, or logs. Only
  sha256-hex hashes are stored or logged. Tokens are shown exactly once at
  creation.
- No package-level mutable state; pass config, stores, clocks, loggers explicitly.
  Package-level vars only for sentinel errors and injected build values.
- context.Context end to end; inject http.Client, clock, and randomness for tests.
- Prefer the standard library; every direct dependency needs justification.
- Migrations are forward-only and monotonic; the migrator refuses a database
  newer than the build.

## Quality gates

```
gofmt -l .                                    # empty
go build ./...
go vet ./...  &&  go vet -tags e2e ./e2e/
go test -count=1 ./...
go test -tags e2e -count=1 -timeout 300s ./e2e/
go mod tidy                                   # clean
golangci-lint run                             # 0 issues
golangci-lint run --build-tags e2e ./e2e/     # 0 issues
```

CI additionally runs the test suite with `-race` (the local sandbox may lack
gcc; see `.github/workflows/ci.yaml`).
