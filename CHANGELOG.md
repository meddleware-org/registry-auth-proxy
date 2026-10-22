# Changelog

All notable changes to registry-auth-proxy are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.9] - 2026-10-22

### Security

- **Go toolchain 1.26.10.** `govulncheck` (v1.8.0) reports GO-2026-6809 (distrusted intermediate certificates
  in `crypto/x509`, fixed in 1.26.10) as reachable from `Handler.ServeHTTP` on the 1.26.9 stdlib. `go.mod` now
  names `toolchain go1.26.10` and the Dockerfile builder is `golang:1.26.10-bookworm` pinned by digest
  (`sha256:632dff73…a21af`; the method reproduces the 1.26.9 pin `sha256:d9c68c2c…641453c` from the same
  registry). The Dockerfile's guard that the builder's `go version` equals the `go.mod` toolchain passes
  (`scripts/check-image-notices.sh` under rootless podman: `image notices OK`). No source change.

### Added

- **Load harness** (`internal/loadtest`, build tag `load`; test code only, not built into the image and not run
  by `go test ./...`). It builds the binary, runs it as its own process against a stub registry and token
  service, and reports requests/s, p50/p99, the 200/503 mix, CPU per request and peak resident memory at
  increasing concurrency (cache hit with and without keep-alive, upstream latency, 64 MiB blob streams, a storm
  of never-seen repository names), optionally under a systemd-scope CPU and memory limit. The numbers and the
  resource sizing they led to are in the audit (F20).
- `TestWiredDeleteIsRefused`: through the wired server, `DELETE` on the paths joxit sends when image deletion is
  enabled (manifest by digest and by tag, blob, catalog), with and without a stale `Authorization`, is `405` with
  `Allow: GET, HEAD` and reaches neither the registry nor the token service; the `HEAD` that precedes a UI delete
  is still forwarded (audit F8, OQ6).

## [0.1.8] - 2026-10-20

### Changed

- **Image build: native cross-compile, no QEMU.** The builder stage is `FROM --platform=$BUILDPLATFORM` and
  compiles for the target with `GOOS=$TARGETOS GOARCH=$TARGETARCH` (`CGO_ENABLED=0`, `-trimpath` and the
  ldflags unchanged), so the release no longer emulates arm64 and `docker-publish.yml` no longer has the
  `docker/setup-qemu-action` step (a privileged binfmt step). `TARGETOS`/`TARGETARCH` have no default any more:
  a builder that does not set them fails the build instead of silently producing the wrong architecture.
  A build step also asserts, with `go version -m` (it reads the binary without running it), that the compiled
  binary's `GOARCH` equals the target architecture.
  Proof (rootless podman, builder pinned by digest): the new `linux/amd64` image built from the 0.1.7 sources with
  `VERSION=v0.1.7` is **byte-identical to the published 0.1.7** (`/auth-proxy` `9dd2208c…`; the CA bundle and
  the `THIRD_PARTY_LICENSES` and `LICENSE` notices are byte-identical too). No behaviour change on amd64, the
  architecture the cluster runs.

### Fixed

- **The published `linux/arm64` image carried an x86-64 binary.** The Dockerfile declared `ARG TARGETARCH=amd64`,
  and that default overrode the platform value, so 0.1.7 and earlier compiled `GOARCH=amd64` in the arm64 build
  too: the arm64 image's `/auth-proxy` is byte-identical to the amd64 one (`9dd2208c…`, ELF x86-64) and would
  not start on an arm64 node. With no default the arm64 image now contains an ELF aarch64 binary (`e1bb9d11…`).
  The cluster is amd64, so nothing deployed was affected.

## [0.1.7] - 2026-10-18

### Security

- Only the registry's read routes are forwarded, in canonical form: `/v2/`, `/v2/_catalog` and
  `/v2/<name>/{tags/list,manifests/<ref>,blobs/<digest>,referrers/<digest>}` with the registry's own
  name, tag and digest grammars. Any other canonical path is `404`; a path with an empty, `.` or `..`
  segment or a trailing slash is `400`; both are answered before the token service or the registry is
  contacted. The path the registry receives is exactly the path that was checked (it was cleaned for
  scope prediction but forwarded as sent before).
- `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop` and every `Cf-*` field (including
  the Cloudflare Access assertion `Cf-Access-Jwt-Assertion`) are no longer forwarded to the registry.
- A token-fetch failure is logged by class (`timeout`, `canceled`, `unreachable`, `status` with the status
  code, `malformed`) instead of the error text, which carried the token endpoint URL and so an internal
  hostname. `token.FetchError` never contains the endpoint or the secret.
- The image ships licence notices in `/usr/share/doc/registry-auth-proxy/` (`LICENSE`, and
  `THIRD_PARTY_LICENSES` with the Go standard library licence and the Debian ca-certificates copyright file
  that carries the Mozilla CA bundle's MPL-2.0 text); the build fails if they cannot be produced.

### Changed

- Client-secret rotation needs no restart: when the token service answers `401`, the proxy re-reads
  `CLIENT_SECRET_FILE` and, if the value changed, retries the fetch once. An unchanged or unreadable
  file leaves the request failing closed (`502`). The secret is still read only from the file and is never
  logged. The rotation and compromise procedure is documented in `SECURITY.md`.
- `.dockerignore` no longer excludes `LICENSE` (the image ships it) and excludes `docs/`; `.git` is
  matched as a file or directory.

### Added

- Tests for the limits that were configured but not exercised: the 30 s response-header deadline (stalled
  upstream, both the probe and the credentialed leg, with the in-flight slot released), the 5 s dial
  deadline (a local listener whose accept queue is full), no total deadline for a slow body, the in-flight
  bound following its limit, the 32 KiB request-header cap (`431`) and the server timeouts; plus tests for
  the route allowlist, the edge-field policy, the token-failure log, secret re-read (including a
  concurrent rotation and an end-to-end rotation through the wired proxy), and `ReadSecret`.
- CI job `image` (`scripts/check-image-notices.sh`) builds the image and checks the shipped notices.
- `SECURITY.md`: forwarding policy, the transport to the token service and registry (plain in-cluster HTTP,
  no mutual authentication per decision D18, bounded by NetworkPolicy and client-secret authentication on a
  single node) and the rotation and compromise procedure.

### Fixed

- The token request URL is built with `url.Parse` and a merged query, so a `TOKEN_ENDPOINT` that already
  carries a query parameter stays well-formed (it produced `?a=b?service=…` before).
- README `cosign verify` is pinned to the publish workflow (`docker-publish.yml@refs/tags/v*`); the build
  example no longer names `v0.1.0`.

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
