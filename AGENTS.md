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
  1. Predict scope from URL path.
  2. Cache hit  → forward with cached Bearer token (no probe).
  3. Cache miss → probe upstream unauthenticated.
                    non-401 → stream back unchanged.
                    401     → parse WWW-Authenticate challenge,
                              GET token-service /token (Basic auth),
                              cache token (expiry − refresh margin),
                              retry with Bearer token.
  4. Still 401 after a token was attached → remap to 403 (no login dialog).
```

## Package layout

```
cmd/server/main.go            HTTP server, routing, graceful shutdown, -healthcheck
internal/config/config.go     Env config; client secret loaded from CLIENT_SECRET_FILE
internal/proxy/handler.go     Reverse proxy: probe/retry, hop-by-hop stripping, 401→403 remap
internal/proxy/scope.go       Predict OCI scope string from request URL path
internal/token/cache.go       Thread-safe per-scope token cache (margin-based expiry)
internal/token/fetcher.go     Fetch tokens from the internal token service (Basic auth)
```

Tests: `internal/proxy/scope_test.go`, `internal/proxy/handler_test.go`,
`internal/token/cache_test.go` (all standard-library `testing`, no extra deps).

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /healthz` | Liveness/readiness probe (`200 {"status":"ok"}`) |
| `*` | Reverse-proxied to `UPSTREAM_URL` with transparent Bearer auth |

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
docker build --build-arg VERSION=v0.1.0 -t quay.io/meddleware-org/registry-auth-proxy:v0.1.0 .
```

## Testing locally

```bash
go test -race ./...

# End-to-end smoke against a running proxy: browse the catalog with no credentials.
curl -s http://localhost:8181/v2/_catalog
curl -s http://localhost:8181/v2/<repo>/tags/list
```

## Scope prediction

Prediction is a cache-key optimisation, not an authorisation decision. It maps read
paths to a `pull`/`catalog` scope so a cache hit can skip the unauthenticated probe. A
mispredict is always safe: the worst case is an unnecessary probe or a pull token
attached to a write path, which the registry rejects and the handler remaps to 403. All
predicted scopes are read-only; write/delete scopes are never predicted.

## Known limitations (intentional)

- **No singleflight.** On a cold cache, concurrent requests for the same scope each fetch
  their own token. Negligible for a single-user browser UI; not worth the complexity.
- **No server read/write timeout.** Only `ReadHeaderTimeout` is set, so large blob
  downloads can stream without being cut off. The token fetcher has its own 10s timeout.

## Invariants

- The client secret comes **only** from `CLIENT_SECRET_FILE`; it is never an env var and
  is never logged. Bearer tokens are never logged either.
- Fail **closed**: a token-fetch error returns `502`, never a naked `401` (which would
  trigger joxit's login dialog).
- Inbound `Authorization` headers are stripped; the proxy owns that header.
- Hop-by-hop headers (RFC 7230 §6.1) are stripped in both directions.
- Response bodies are **streamed**, never fully buffered (constant memory for blobs).
- The proxy is read-only by identity; it never predicts or requests write/delete scopes.
