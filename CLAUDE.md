# CLAUDE.md — registry-auth-proxy

## Identity

This service is an internal convenience proxy. It sits between joxit/docker-registry-ui
and the CNCF Distribution registry, transparently handling Bearer token auth. It is not
security-critical in the same way as the token service — it only ever holds the
`registry-browser` client credentials, which have read-only pull + catalog permissions.

## Architectural invariants

1. **Fail closed on token fetch error.** If the internal token service is unreachable or
   returns a non-200, return 502 to joxit. Never pass through a naked 401 or fabricate
   a response — joxit must not show a login dialog.

2. **The client secret lives only in `CLIENT_SECRET_FILE`.** It is never logged,
   never exposed as an environment variable, and never included in error messages.
   The file is mounted from a Kubernetes Secret (mode 0440). It is read at startup and again,
   once per fetch, when the token service answers `401` (`Fetcher.WithSecretReload`): a changed
   value is retried at once, an unchanged or unreadable file leaves the failure closed (502). That
   makes rotation restart-free; it is not a background watcher (see "What not to do").

3. **Strip inbound Authorization headers.** joxit may send stale credentials from its
   localStorage. Always replace the Authorization header with our own Bearer token;
   never forward a client-supplied Authorization header to the upstream registry. Also
   strip hop-by-hop headers (RFC 7230 §6.1) in both directions, **and every field named in
   `Connection`** — copying upstream `Connection`/`Transfer-Encoding` to the client produces
   malformed responses. Cookies are not forwarded upstream; `Set-Cookie` and `Access-Control-*` are
   not passed to the UI (it is same-origin behind nginx). The proxy adds `Via: 1.1 registry-auth-proxy`
   and refuses (508) a request that already carries it, so a misrouted upstream cannot loop.

   **Remap 401→403 after a token is attached.** The whole point of the proxy is that
   joxit never sees a 401 (a 401 triggers its login dialog). If a request is still 401
   *after* we attached a valid Bearer token, the identity is authenticated but not
   authorized — remap it to 403. Only the unauthenticated probe path may branch on 401
   (to trigger a token fetch); a token-bearing 401 is always remapped.

4. **Read-only, no request bodies, read routes only.** Only `GET` and `HEAD` are forwarded; every other
   method is `405` before the upstream or the token service is contacted. No request body
   is read or forwarded (the old 32 MiB replay buffer is gone). A token is requested only
   for `registry:catalog:*` or `repository:<name>:pull`; a challenge for anything else
   (push, delete, `*`, a malformed scope) is answered `403` without a token request.
   Challenge parsing is quote-aware (`challenge.go`).

   **Route allowlist (`scope.go`, `Route`).** Only `/v2/`, `/v2`, `/v2/_catalog` and
   `/v2/<name>/{tags/list,manifests/<ref>,blobs/<digest>,referrers/<digest>}` are forwarded, with the
   registry's own name/tag/digest grammars; another canonical path is `404`, a path with an empty, `.` or
   `..` segment or a trailing slash is `400`, both before any token or upstream call. The path is never
   rewritten, so the path the registry receives is the path that was checked. `X-Forwarded-*`,
   `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop` and `Cf-*` (incl. the Access JWT) are not
   forwarded upstream. A failed token fetch is logged by class (`token.FailureClass`), never with the
   error text or endpoint.

   **A token is cached only under the scope it was issued for** — never under the scope
   predicted from the path — and the cache is bounded (512 entries; expired entries are
   swept, then the one closest to expiry is dropped). Concurrent misses for one scope
   share a single token request (`token.Flight`). A token the registry refuses is evicted.

   **Limits.** At most 64 forwards are in flight (`DefaultMaxInFlight`; beyond that, 503 with
   `Retry-After`); the upstream connection has a 5 s dial and a 30 s response-header deadline (no total
   deadline, so blob downloads stream); request headers are capped at 32 KiB (all
   pinned by tests: `limits_test.go`, `dial_linux_test.go`, `cmd/server/main_test.go`). A failed upstream is logged
   by class (`timeout` / `canceled` / `unreachable`), never with the error text, which carries the
   upstream address.

5. **Do not buffer response bodies.** Responses (especially blob downloads) are streamed
   directly from upstream to joxit. Buffering would break large responses and
   significantly increase memory use.

## Request flow

```text
Browser -> joxit nginx -> registry-auth-proxy -> Distribution registry
                               |  ^ (internal, cluster-only)
                               v  |
                        registry token service

Per request:
  0. Method is not GET/HEAD -> 405. Path is not a canonical registry read route -> 404 / 400 (no token, no upstream call).
  1. Predict scope from the URL path.
  2. Cache hit  -> forward with the cached Bearer token (no probe).
  3. Cache miss -> probe upstream unauthenticated.
       non-401 -> stream back unchanged.
       401     -> parse the WWW-Authenticate challenge (quote-aware); scope not pull/catalog -> 403, no token request;
                  GET token-service /token (Basic auth; one request shared by concurrent misses; on a 401 the secret file is
                  re-read once and, if changed, the request retried); cache the token under the ISSUED scope only
                  (expiry - refresh margin; 512-entry bound); retry with the Bearer token.
  4. Still 401 after a token was attached -> remap to 403 (no login dialog).
```

Scope prediction is a cache-key optimisation, not an authorisation decision: a mispredict costs at most an unnecessary probe, and
a token is cached only under the scope it was issued for, so a mispredicted key can never be served another scope's token.

## Layout, configuration and commands

```text
cmd/server/main.go            HTTP server, routing, graceful shutdown, -healthcheck
internal/config/config.go     env config; client secret loaded from CLIENT_SECRET_FILE
internal/proxy/handler.go     reverse proxy: method allowlist, probe/retry, hop-by-hop stripping, 401->403 remap
internal/proxy/challenge.go   quote-aware Bearer challenge parser; read-only scope filter
internal/proxy/scope.go       route allowlist (`Route`) and OCI scope prediction
internal/token/cache.go       thread-safe, bounded per-scope token cache (margin-based expiry)
internal/token/flight.go      collapses concurrent token fetches for one scope into one request
internal/token/fetcher.go     fetches tokens from the internal token service (Basic auth)
internal/loadtest/            load harness (build tag `load`, test code only; not built into the image or run by `go test ./...`)
```

Endpoints: `GET /healthz` (liveness/readiness, `200 {"status":"ok"}`), `/v2/...` read routes proxied to `UPSTREAM_URL`, anything else
`404` / `400`.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PORT` | no | `8181` | HTTP listen port |
| `UPSTREAM_URL` | yes | none | Distribution registry base URL |
| `TOKEN_ENDPOINT` | yes | none | Token service `GET /token` URL (internal) |
| `CLIENT_ID` | no | `registry-browser` | Hydra `client_id` for Basic auth to the token service |
| `CLIENT_SECRET_FILE` | yes | none | File containing the client secret (mounted from a Secret) |
| `TOKEN_REFRESH_MARGIN` | no | `30s` | Evict cached tokens this early before expiry |
| `LOG_LEVEL` | no | `info` | `debug\|info\|warn\|error` |

```bash
go build -o auth-proxy ./cmd/server
PORT=8181 UPSTREAM_URL=http://localhost:5000 TOKEN_ENDPOINT=http://localhost:8080/token \
  CLIENT_ID=registry-browser CLIENT_SECRET_FILE=./client-secret ./auth-proxy
go test -race ./...
curl -s http://localhost:8181/v2/_catalog          # end-to-end smoke: browse with no credentials
docker build --build-arg VERSION=dev -t registry-auth-proxy:dev .
sh scripts/check-image-notices.sh                  # CONTAINER_CLI=podman for rootless podman
```

Tests are standard-library `testing` only (route allowlist, field policy and deadlines against stalling local servers, secret
re-read, header cap, wiring, rotation end to end).

Load harness: `internal/loadtest` builds the binary, runs it as its own process against a stub registry and token service, and drives
it at increasing concurrency (requests/s, p50/p99, the 200/503 mix, CPU per request, peak resident memory).
`LOAD_CPU_QUOTA=20% LOAD_MEM_MAX=128M` runs it in a systemd user scope with a container-like limit; the recipe is in the header of
`load_test.go`.

Known limitation (intentional): no server read/write timeout. `ReadHeaderTimeout` (10 s), `IdleTimeout` (120 s) and the 32 KiB header
cap are set so large blob downloads stream without being cut off; the token fetcher has its own 10 s timeout.

## Code style

- Match the pattern in `registry-token-service/cmd/server/main.go`: no global state,
  structured logging via `log/slog`, graceful shutdown, `envOr` for optional config.
- Keep `cmd/server/main.go` thin — routing and server setup only.
- Proxy logic (401 intercept, retry, route allowlist and scope prediction) lives in `internal/proxy/`; the token cache and fetcher in `internal/token/`.
- `scripts/third-party-licenses.sh` and `scripts/check-image-notices.sh` produce and check the licence
  notices shipped in the image (`/usr/share/doc/registry-auth-proxy/`); CI runs the check.

## What not to do

- Do not add push support. This proxy is read-only (pull + catalog).
- Do not add authentication of the joxit → proxy connection. joxit and the proxy are
  in the same namespace; network policy prevents external access.
- Do not upgrade CLIENT_SECRET to an env var for "convenience". Kubernetes Secrets
  mounted as files are the correct pattern for credentials.
- Do not cache a token under any key but the scope it was issued for, and do not forward a
  request body or a method other than GET/HEAD.
- Do not watch `CLIENT_SECRET_FILE` with a goroutine or poll it: the re-read on a `401` is the whole
  mechanism.
- Do not widen the route allowlist to "everything under /v2" or forward `X-Forwarded-*`/`Cf-*` headers.
- Do not implement token refresh via background goroutine. The lazy cache-miss approach
  is simpler and correct — the extra latency on cache miss is negligible.
