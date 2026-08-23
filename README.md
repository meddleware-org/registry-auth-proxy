# registry-auth-proxy

A small, stateless **pre-authenticating reverse proxy** for the
[CNCF Distribution registry](https://distribution.github.io/distribution/). It sits
between [joxit/docker-registry-ui](https://github.com/Joxit/docker-registry-ui) and a
token-authenticated registry and handles the entire Bearer-token dance on the UI's
behalf, so the browser UI **never shows a login dialog**.

- **Runtime base:** `scratch` (zero OS footprint, no shell, no package manager)
- **Language:** Go (standard library only — no third-party dependencies)
- **Non-root:** runs as UID/GID `65534`
- **License:** BSD Zero Clause ([0BSD](LICENSE))

> This is internal infrastructure glue with a small security surface. Read
> [SECURITY.md](SECURITY.md) before deploying — the invariants there are load-bearing.

## Why this exists

joxit/docker-registry-ui cannot pre-store credentials for a registry that uses Bearer
token authentication. Pointed at such a registry it prompts the operator for a username
and password on first use and stashes them in `localStorage`. That is awkward to
provision declaratively and leaks a shared credential into every browser.

This proxy removes the prompt entirely. It holds one machine identity
(`registry-browser`, read-only pull + catalog) and transparently authenticates every
request the UI makes, so joxit can be configured with **no credentials at all**.

## How it works

```
Browser ──▶ joxit nginx ──▶ registry-auth-proxy ──▶ Distribution registry
                                     │  ▲
                                     ▼  │ (internal, cluster-only)
                              registry token service
```

For each request the proxy:

1. **Predicts the scope** from the URL path (`/v2/_catalog` → `registry:catalog:*`,
   `/v2/<name>/tags/list` → `repository:<name>:pull`, etc.). On a **cache hit** it
   forwards immediately with the cached token — no extra round trip.
2. On a **cache miss**, probes the registry unauthenticated. Any non-401 response is
   streamed straight back.
3. On **401**, parses the `WWW-Authenticate: Bearer …` challenge, fetches a token from
   the internal token service (HTTP Basic auth with the `registry-browser` credentials),
   caches it (minus a refresh margin), and **retries** with the Bearer token attached.

Two properties guarantee joxit never sees a 401:

- Any inbound `Authorization` header is **stripped** before the request is forwarded, so
  stale credentials in the UI's `localStorage` are never used.
- If a request is **still 401 after a valid token was attached** (e.g. a delete attempt
  the read-only identity is not granted), the proxy **remaps the status to 403**. joxit
  treats 403 as "not allowed" and does not prompt; a raw 401 would trigger the dialog.

The proxy is **stateless** apart from an in-memory per-scope token cache; restarting it
simply re-warms the cache on demand.

## Quick start

The proxy needs a reachable Distribution registry, the registry's token service, and the
`registry-browser` client secret in a file.

```bash
printf '%s' "$REGISTRY_BROWSER_SECRET" > /tmp/client-secret

docker run --rm -p 8181:8181 \
  -e UPSTREAM_URL=http://registry:5000 \
  -e TOKEN_ENDPOINT=http://token-service:8080/token \
  -e CLIENT_ID=registry-browser \
  -e CLIENT_SECRET_FILE=/etc/registry-auth-proxy/client-secret \
  -v /tmp/client-secret:/etc/registry-auth-proxy/client-secret:ro \
  quay.io/meddleware-org/registry-auth-proxy:latest
```

Then point joxit's `NGINX_PROXY_PASS_URL` at the proxy instead of the registry:

```
NGINX_PROXY_PASS_URL=http://registry-auth-proxy:8181
```

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PORT` | no | `8181` | HTTP listen port |
| `UPSTREAM_URL` | **yes** | — | Distribution registry base URL (e.g. `http://registry:5000`) |
| `TOKEN_ENDPOINT` | **yes** | — | Registry token service `GET /token` URL (internal; bypasses any public tunnel) |
| `CLIENT_ID` | no | `registry-browser` | Hydra `client_id` used for Basic auth to the token service |
| `CLIENT_SECRET_FILE` | **yes** | — | Path to a file containing the client secret (mounted from a Secret; never an inline env var) |
| `TOKEN_REFRESH_MARGIN` | no | `30s` | Evict cached tokens this long before their stated expiry |
| `LOG_LEVEL` | no | `info` | `debug \| info \| warn \| error` |

See [.env.example](.env.example) for a copy-paste template.

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /healthz` | Liveness/readiness probe (`200 {"status":"ok"}`) |
| `*` (any other path) | Reverse-proxied to `UPSTREAM_URL` with transparent Bearer auth |

The binary also supports `-healthcheck`, which dials `/healthz` and exits `0`/`1` (used
by the container `HEALTHCHECK` on Docker/Compose; Kubernetes uses its own probes).

## Verifying published images

Images are multi-arch, carry an SBOM + SLSA provenance, and are signed with keyless
[cosign](https://docs.sigstore.dev/):

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/meddleware-org/registry-auth-proxy/.*' \
  quay.io/meddleware-org/registry-auth-proxy:<tag>

# Inspect provenance / SBOM attestations:
cosign download attestation quay.io/meddleware-org/registry-auth-proxy:<tag>
```

## Building

```bash
# Local binary
go build -o auth-proxy ./cmd/server

# Run the test suite (race detector)
go test -race ./...

# Container image (reproducible; base pinned by digest)
docker build --build-arg VERSION=v0.1.0 \
  -t quay.io/meddleware-org/registry-auth-proxy:v0.1.0 .
```

## Contributing / development

See [AGENTS.md](AGENTS.md) for the package layout, request-flow detail, and testing
recipes, and [CLAUDE.md](CLAUDE.md) for the architectural invariants. CI runs
`golangci-lint`, `go vet`, race tests, `govulncheck`, and a Trivy filesystem scan; all
must pass before a `v*` tag triggers a signed multi-registry release.
