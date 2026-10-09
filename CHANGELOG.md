# Changelog

All notable changes to registry-auth-proxy are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-10-09

### Security

- Forwarding follows the PROXY lens: every field named in `Connection` is stripped in both directions, cookies are not sent upstream, `Set-Cookie` and `Access-Control-*` are not passed to the UI, the proxy marks its hop with `Via` and refuses (508) a looped request, at most 64 forwards are in flight (503 + Retry-After beyond that), the upstream has dial and response-header deadlines, request headers are capped at 32 KiB, and an upstream failure is logged by class without the upstream address

## [0.1.5] - 2026-10-09

### Security

- Built with Go 1.26.9: govulncheck found eleven net/http and net/textproto advisories in 1.26.7 (GO-2026-6607 to GO-2026-6617). go.mod names the toolchain and the Dockerfile builder is pinned to the same patch and checks it.

## [0.1.4] - 2026-10-08

### Security

- Read-only by construction: only `GET` and `HEAD` are forwarded (other methods are `405` before
  the upstream or the token service is contacted) and no request body is read or forwarded; the
  32 MiB replay buffer is removed.
- A token is requested only for `registry:catalog:*` or `repository:<name>:pull`. A challenge for
  push, delete, `*` or a malformed scope is answered `403` without a token request. The challenge
  parser is quote-aware (commas and escaped quotes inside values, case-insensitive scheme).
- A token is cached only under the scope it was issued for; it was also stored under the scope
  predicted from the path, so a challenge naming a different resource could poison that key.
- The token cache is bounded (512 entries; expired entries swept, then the one closest to expiry
  dropped) and no longer stores a token already inside the refresh margin.

### Changed

- Concurrent cache misses for one scope share a single token request.
- A token the registry refuses (401 with the token attached) is evicted, so the next request
  fetches a fresh one instead of failing until the old token expires.
- Release gate: the tag workflow runs the same checks as CI (reusable workflow: lint, race tests,
  govulncheck, Trivy filesystem scan), scans the published image before signing, and prints a
  `cosign verify` command pinned to the workflow identity. `go.mod` names a `toolchain` and the
  Dockerfile refuses a builder on another patch.

## [0.1.3] - 2026-10-03

### Fixed

- Token expiry: a missing or non-positive `expires_in` now means 60 s (Distribution token spec)
  instead of 0, and the issue time is the earlier of `issued_at` and the local clock, so a token
  service whose clock runs ahead cannot keep a token cached past its real expiry.

### Added

- Tests for the token fetcher (credentials and query, fail-closed answers, 64 KiB cap, expiry rules)
  and for the handler's 502-on-token-failure and 32 MiB body cap.
- CI pins `govulncheck` (v1.8.0).

## [0.1.0] - 2026-08-23

### Added
- Initial pre-authenticating reverse proxy for the CNCF Distribution registry: predicts
  the OCI scope from the request path, probes on cache miss, exchanges the registry's 401
  Bearer challenge for a token at the internal token service, caches it, and retries.
- Per-scope in-memory token cache with a configurable refresh margin
  (`TOKEN_REFRESH_MARGIN`, default 30s).
- 401→403 hardening: a request that is still unauthorized after a valid token is attached
  is remapped to `403`, so the browser UI never displays a login dialog.
- Inbound `Authorization` header stripping and hop-by-hop header stripping (RFC 7230
  §6.1) in both directions.
- `-healthcheck` CLI flag and container `HEALTHCHECK` for non-Kubernetes runtimes.
- Reproducible Dockerfile (base image pinned by digest) with full OCI image labels;
  `scratch` runtime, non-root UID 65534.
- Standard-library unit tests: scope prediction, Bearer-challenge parsing, hop-by-hop
  detection, token cache, and an httptest end-to-end (happy path, cache hit, 401→403).
- CI (golangci-lint, `go vet`, race tests, govulncheck, Trivy) and a signed, multi-arch,
  multi-registry release pipeline (cosign + SBOM + SLSA provenance).
- Operator documentation: `README.md`, `AGENTS.md`, `CLAUDE.md`, `SECURITY.md`,
  `.env.example`, `llms.txt`.
