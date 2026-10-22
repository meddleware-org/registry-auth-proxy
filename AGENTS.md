# AGENTS.md — registry-auth-proxy

## Purpose

A pre-authenticating reverse proxy that lets joxit/docker-registry-ui browse a
token-authenticated CNCF Distribution registry **without a login dialog**. joxit cannot
pre-store Bearer credentials, so this proxy holds one read-only machine identity
(`registry-browser`) and performs the Bearer token dance transparently for every request
the UI makes.

## Request flow

```
Browser → joxit nginx → registry-auth-proxy → Distribution registry
                              │  ▲
                              ▼  │  (internal, cluster-only)
                       registry token service

Per request:
  0. Method is not GET/HEAD → 405 (nothing else happens). No body is forwarded.
     Path is not a canonical registry read route → 404 / 400 (no token, no upstream call).
  1. Predict scope from URL path.
  2. Cache hit  → forward with cached Bearer token (no probe).
  3. Cache miss → probe upstream unauthenticated.
                    non-401 → stream back unchanged.
                    401     → parse WWW-Authenticate challenge (quote-aware);
                              scope not pull/catalog → 403, no token request;
                              GET token-service /token (Basic auth, one request
                              shared by concurrent misses; on a 401 the secret file is
                              re-read once and, if changed, the request is retried),
                              cache token under the ISSUED scope only
                              (expiry − refresh margin; 512-entry bound),
                              retry with Bearer token.
  4. Still 401 after a token was attached → remap to 403 (no login dialog).
```

## Package layout

```
cmd/server/main.go            HTTP server, routing, graceful shutdown, -healthcheck
internal/config/config.go     Env config; client secret loaded from CLIENT_SECRET_FILE
internal/proxy/handler.go     Reverse proxy: method allowlist, probe/retry, hop-by-hop stripping, 401→403 remap
internal/proxy/challenge.go   Quote-aware Bearer challenge parser; read-only scope filter
internal/proxy/scope.go       Route allowlist (`Route`) and OCI scope prediction from the request path
scripts/                      third-party-licenses.sh (image notices), check-image-notices.sh (CI image job)
internal/token/cache.go       Thread-safe, bounded per-scope token cache (margin-based expiry)
internal/token/flight.go      Collapses concurrent token fetches for one scope into one request
internal/token/fetcher.go     Fetch tokens from the internal token service (Basic auth)
```

Tests (all standard-library `testing`, no extra deps): `internal/proxy/{scope,handler,forwarding,limits}_test.go`
and `dial_linux_test.go` (route allowlist, field policy, deadlines against stalling local servers),
`internal/token/{cache,flight,fetcher}_test.go` (incl. secret re-read), `internal/config/config_test.go`,
`cmd/server/main_test.go` (header cap, wiring, rotation end to end).

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /healthz` | Liveness/readiness probe (`200 {"status":"ok"}`) |
| `/v2/…` read routes | Reverse-proxied to `UPSTREAM_URL` with transparent Bearer auth (see `Route`) |
| anything else | `404` / `400` |

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PORT` | no | `8181` | HTTP listen port |
| `UPSTREAM_URL` | yes | — | Distribution registry base URL |
| `TOKEN_ENDPOINT` | yes | — | Token service `GET /token` URL (internal) |
| `CLIENT_ID` | no | `registry-browser` | Hydra `client_id` for Basic auth to the token service |
| `CLIENT_SECRET_FILE` | yes | — | File containing the client secret (mounted from a Secret) |
| `TOKEN_REFRESH_MARGIN` | no | `30s` | Evict cached tokens this early before expiry |
| `LOG_LEVEL` | no | `info` | `debug\|info\|warn\|error` |

## Build and run

```bash
# build binary
go build -o auth-proxy ./cmd/server

# run locally against a registry + token service
PORT=8181 \
UPSTREAM_URL=http://localhost:5000 \
TOKEN_ENDPOINT=http://localhost:8080/token \
CLIENT_ID=registry-browser \
CLIENT_SECRET_FILE=./client-secret \
./auth-proxy

# build Docker image
docker build --build-arg VERSION=dev -t registry-auth-proxy:dev .
sh scripts/check-image-notices.sh   # CONTAINER_CLI=podman for rootless podman
```

## Testing locally

```bash
go test -race ./...

# End-to-end smoke against a running proxy: browse the catalog with no credentials.
curl -s http://localhost:8181/v2/_catalog
curl -s http://localhost:8181/v2/<repo>/tags/list
```

## Load harness

`internal/loadtest` (build tag `load`, test code only; not built into the image or run by `go test ./...`)
builds the binary, runs it as its own process against a stub registry and token service, and drives it at
increasing concurrency, reporting requests/s, p50/p99, the 200/503 mix, CPU per request and peak resident
memory. `LOAD_CPU_QUOTA=20% LOAD_MEM_MAX=128M` runs the proxy in a systemd user scope with a container-like
limit. The recipe and the environment variables are in the header of `load_test.go`; the audit (F20)
records the numbers behind the manifest's resources.

## Scope prediction

Prediction is a cache-key optimisation, not an authorisation decision. It maps read
paths to a `pull`/`catalog` scope so a cache hit can skip the unauthenticated probe. A
mispredict is always safe: the worst case is an unnecessary probe. A token is cached only
under the scope it was issued for, so a mispredicted key can never be served another
scope's token. All predicted scopes are read-only, and the challenge scope is vetted the
same way before any token is requested.

## Known limitations (intentional)

- **No server read/write timeout.** `ReadHeaderTimeout` (10 s), `IdleTimeout` (120 s) and a 32 KiB
  header cap are set, so large blob downloads can stream without being cut off. The upstream has
  a 5 s dial and 30 s response-header deadline and no total deadline. The token fetcher has its own
  10s timeout.

## Invariants

- The client secret comes **only** from `CLIENT_SECRET_FILE`; it is never an env var and
  is never logged. Bearer tokens are never logged either.
- Fail **closed**: a token-fetch error returns `502`, never a naked `401` (which would
  trigger joxit's login dialog).
- Inbound `Authorization` headers are stripped; the proxy owns that header. So are cookies,
  `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop` and `Cf-*`.
- Only canonical registry read routes are forwarded (`Route`); the path is never rewritten.
- A token-fetch failure is logged by class, never with the endpoint URL or error text.
- Hop-by-hop headers (RFC 7230 §6.1) are stripped in both directions.
- Response bodies are **streamed**, never fully buffered (constant memory for blobs).
- The proxy is read-only by construction: GET/HEAD only, no request body, and it never
  requests a write/delete scope (such a challenge is a 403).
