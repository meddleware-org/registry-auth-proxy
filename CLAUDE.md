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
   The file is mounted from a Kubernetes Secret (mode 0440).

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

4. **Read-only, no request bodies.** Only `GET` and `HEAD` are forwarded; every other
   method is `405` before the upstream or the token service is contacted. No request body
   is read or forwarded (the old 32 MiB replay buffer is gone). A token is requested only
   for `registry:catalog:*` or `repository:<name>:pull`; a challenge for anything else
   (push, delete, `*`, a malformed scope) is answered `403` without a token request.
   Challenge parsing is quote-aware (`challenge.go`).

   **A token is cached only under the scope it was issued for** — never under the scope
   predicted from the path — and the cache is bounded (512 entries; expired entries are
   swept, then the one closest to expiry is dropped). Concurrent misses for one scope
   share a single token request (`token.Flight`). A token the registry refuses is evicted.

   **Limits.** At most 64 forwards are in flight (`DefaultMaxInFlight`; beyond that, 503 with
   `Retry-After`); the upstream connection has a 5 s dial and a 30 s response-header deadline (no total
   deadline, so blob downloads stream); request headers are capped at 32 KiB. A failed upstream is logged
   by class (`timeout` / `canceled` / `unreachable`), never with the error text, which carries the
   upstream address.

5. **Do not buffer response bodies.** Responses (especially blob downloads) are streamed
   directly from upstream to joxit. Buffering would break large responses and
   significantly increase memory use.

## Code style

- Match the pattern in `registry-token-service/cmd/server/main.go`: no global state,
  structured logging via `log/slog`, graceful shutdown, `envOr` for optional config.
- Keep `cmd/server/main.go` thin — routing and server setup only.
- Token cache lives in `internal/token/cache.go`; token fetching in `internal/token/fetcher.go`.
- Proxy logic (401 intercept, retry, scope prediction) lives in `internal/proxy/`.

## What not to do

- Do not add push support. This proxy is read-only (pull + catalog).
- Do not add authentication of the joxit → proxy connection. joxit and the proxy are
  in the same namespace; network policy prevents external access.
- Do not upgrade CLIENT_SECRET to an env var for "convenience". Kubernetes Secrets
  mounted as files are the correct pattern for credentials.
- Do not cache a token under any key but the scope it was issued for, and do not forward a
  request body or a method other than GET/HEAD.
- Do not implement token refresh via background goroutine. The lazy cache-miss approach
  is simpler and correct — the extra latency on cache miss is negligible.
