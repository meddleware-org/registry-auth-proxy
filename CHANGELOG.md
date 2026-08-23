# Changelog

All notable changes to registry-auth-proxy are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
