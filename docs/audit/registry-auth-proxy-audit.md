# Security Audit — `registry-auth-proxy`

**Classification:** Internal security review (re-verified 2026-10-09 — awaiting external review)
**Project:** `registry-auth-proxy` — a pre-authenticating, read-only registry reverse proxy (Go).

- It sits between joxit/docker-registry-ui and the CNCF Distribution registry.
- It owns the Bearer-token dance with the `registry-browser` client credentials, so the UI never shows
  a login.

**Project type:** Go service + container image + credential-injecting reverse proxy (OAuth client-credentials consumer)
**Template:**

- AUDIT_TEMPLATE.md (2026-10-08)
- AUDIT_TEMPLATE_GO.md (2026-10-08)
- AUDIT_TEMPLATE_IMG.md (2026-10-08)
- AUDIT_TEMPLATE_AUTH.md (2026-10-08) — mandatory: names registry-auth-proxy as a "client-credentials
  consumer with a per-scope token cache"
- AUDIT_TEMPLATE_PROXY.md (2026-10-08) — mandatory: names registry-auth-proxy as a "credential-injecting
  proxy for the registry UI"

The 2026-09-18 baseline predates the lens set; the PROXY lens is new in this pass (2026-10-09). Not
triggered: SUI, SUI_CLIENT, SEAL, WALRUS, VUE, TS, RUST, WORKERS, OPS, SITE, and PLATFORM (the project
is not the cluster or edge itself; the manifests it runs under are read for the transport and
origin-lock rows only).

**Deployment status:**

- Release `v0.1.6` = `7928960` (2026-10-09), which is `main` HEAD. The image is
  `quay.io/meddleware-org/registry-auth-proxy:0.1.6@sha256:d98c347c…1581`. Docker Hub
  `meddleware/registry-auth-proxy:0.1.6` and the quay.io tag both resolve to that digest (checked
  2026-10-10), and `config/images.yaml` and the `k8s/clusters/meddleware-org/registry` overlay pin it.
  All deployed images were cosign-verified 2026-10-09 (`bootstrap/images/verify-digests.sh`, 16/16
  valid).
- Running in namespace `registry` (`k8s/base/registry/auth-proxy`, one replica, ClusterIP `:8181`, no
  Ingress). It is an internal cluster service, reached by joxit's nginx in the same namespace; joxit is
  published as `registry-ui.meddleware.co.uk` behind Cloudflare Access.
- Fix wave 2026-10-18: **0.1.7**, released and deployed 2026-10-18: tag `v0.1.7` = `a3678e4` (fix commit
  `de46a96`), image `quay.io/meddleware-org/registry-auth-proxy:0.1.7@sha256:150382016712b23b60c991996b5b69293b6dde5f481447d4c0574197ef2f097e`
  (Docker Hub, same digest). The cosign keyless signature was verified 2026-10-18 against the
  workflow-anchored identity (`docker-publish.yml@refs/tags/v*`, `verify-digests.sh`, 16/16 valid) and the
  rollout (`kubectl apply -k`, registry overlay) succeeded. What this audit says about 0.1.7 is live. on-node route checks after the rollout (2026-10-18, from the release facts; run against the in-cluster service, not re-run by this audit pass): allowed routes answered `200`, write methods `405`, non-routes `404` and non-canonical paths `400`, as the route allowlist (F18) specifies. The 0.1.6 digest `sha256:d98c347c…1581` above is the
  superseded 2026-10-09 deployment. `docs/` (this audit) is committed with it.

**Review date:** 2026-10-03 (second pass; baseline 2026-09-18) · re-verified 2026-10-09 · fix wave 2026-10-18
**Reviewer:** Internal review
**Severity ceiling:** Medium.

- The proxy holds one read-only identity (`registry-browser`, pull + catalog) and authenticates
  nothing inbound, by design.
- The real authorization decision lives in registry-token-service + Keto and the registry.
- A defect can deny registry browsing, amplify load on the token service and IdP, or widen what the
  proxy *requests*. It cannot exceed what Keto grants the identity.
- Realised ceiling at this pass: **Low** (every open item is Low or Info and none widens access).

**Status:** re-verified 2026-10-09; fix wave 2026-10-18 (0.1.7, released and deployed 2026-10-18; signature verified, rollout succeeded, route checks passed).

- The baseline was supplied to this review; this file is committed with the 0.1.7 fix wave (F12).
- **Corpus IDs F1–F13 are preserved.** New findings start at F14.
- Two internal inconsistencies in the baseline were settled in the 2026-10-03 pass:
  - F1's header said RESOLVED while its body still said DEFERRED;
  - I14 was marked GAP although F4's redirect half was resolved.

**GO lens front matter:**

| Field | Value |
| --- | --- |
| Go | `go 1.26.6` with `toolchain go1.26.9` (go.mod); CI `go-version-file: go.mod`; image builder `golang:1.26.9-bookworm@sha256:d9c68c2c…641453c`, and the Dockerfile fails the build when the builder's `go version` differs from the `go.mod` toolchain |
| Modules | none (stdlib only, no `go.sum`) |
| Entry points | `/auth-proxy` (`cmd/server`), listen `:$PORT` (default 8181); `-healthcheck` mode |
| Upstreams | `UPSTREAM_URL` (the Distribution registry, in-cluster http; Bearer injected); `TOKEN_ENDPOINT` (registry-token-service `GET /token`, in-cluster http; Basic auth with the client secret) |

**IMG lens front matter:**

| Field | Value |
| --- | --- |
| Images | `quay.io/meddleware-org/registry-auth-proxy:0.1.7@sha256:150382016712b23b60c991996b5b69293b6dde5f481447d4c0574197ef2f097e`; `docker.io/meddleware/registry-auth-proxy:0.1.7` (same digest; cosign-verified 2026-10-18; superseded 0.1.6 was `sha256:d98c347c…1581`); best-effort mirror on the self-hosted registry |
| Base images | builder `golang:1.26.9-bookworm@sha256:d9c68c2c…641453c`; runtime `scratch` (+ the CA bundle copied from the builder) |
| Runtime user | `65534:65534` (`USER` in the image; pod `runAsNonRoot`) |
| Runtime FS | read-only root; no writable mount; the secret mounted read-only at `/etc/registry-auth-proxy` (`CLIENT_SECRET_FILE`) |
| Deployed by | `k8s/base/registry/auth-proxy`, through the `k8s/clusters/meddleware-org/registry` overlay (digest stamped from `config/images.yaml`) |
| Build args | `VERSION`, `TARGETOS`/`TARGETARCH`, label args (`VENDOR`, `DESCRIPTION`, `SOURCE_URL`, `DOCUMENTATION_URL`, `IMAGE_URL`) — no secrets |

**AUTH lens front matter:**

| Field | Value |
| --- | --- |
| Auth role(s) | OAuth client (confidential, client credentials, through registry-token-service) and a credential-injecting proxy; it never issues or verifies tokens |
| Identity provider | Ory Hydra and Keto, reached only through registry-token-service `GET /token` (in-cluster http, Basic auth) |
| Token formats | Distribution registry Bearer JWT, opaque to the proxy (`token`, `expires_in`, `issued_at`) |
| Signing / client credentials | `registry-browser` client secret — mounted file `CLIENT_SECRET_FILE` (Secret `registry-auth-proxy-secret`, mode 0440) — re-read after a token-service refusal since 0.1.7, no rotation cadence fixed (F10); no signing key |
| Authorization model | Keto namespace `Registry`: `registry-browser` is `pullers` of `meddleware-org` and `listers` of `catalog`; the proxy adds its own request-side limit (read scopes only, F8) |

**PROXY lens front matter:**

| Field | Value |
| --- | --- |
| Upstreams | one origin, `UPSTREAM_URL` (`http://registry.registry.svc.cluster.local:5000`), set in the manifest and validated at startup (F1); the registry authenticates every request itself (Bearer), so there is no origin lock to enforce (F19) |
| Public paths | the registry read routes only (`/v2/`, `/v2/_catalog`, `/v2/<name>/{tags/list,manifests,blobs,referrers}`; any other path is `404`/`400`, F18), no inbound credential, `GET` and `HEAD` only (anything else is `405`); `/healthz` is local |
| Body cap / timeouts | no request body is read or forwarded; `ReadHeaderTimeout` 10 s; `IdleTimeout` 120 s; `MaxHeaderBytes` 32 KiB; no `WriteTimeout` (blobs stream); upstream dial 5 s and response-header 30 s, no total deadline; 64 forwards in flight (B.PX-2); the deadlines, the header cap and the bound are pinned by tests (F20) |
| Trusted forwarding hops | one: joxit's nginx in the same namespace; the proxy uses no client address, sets no `X-Forwarded-*` of its own, and drops the ones it receives, with `Cf-*` (F18) |

**Location:** `registry-auth-proxy/docs/audit/registry-auth-proxy-audit.md` (committed with the 0.1.7 fix
wave, F12).

> **Access note:** the review ran against the workspace checkout `repos/registry-auth-proxy` at `main`
> = `v0.1.6` (`7928960`) and the read-only manifests under `k8s/`; nothing was changed in that pass. The
> 2026-10-18 fix wave changed this repository only (0.1.7, a local commit at the time of that pass; it
> was tagged and released later the same day) and left `k8s/` and the workspace documents untouched (the items for them are named in
> F10, F12, F19, F21).

---

## Executive summary

A small, stdlib-only proxy (about 1,300 lines of Go plus 2,100 lines of tests).

**Every finding of the 2026-10-03 pass was fixed in 0.1.4–0.1.6 and verified against `v0.1.6`
(`7928960`); the 2026-10-18 fix wave (0.1.7, released and deployed 2026-10-18) then closed the lens items F17, F18, F20
and F22 and the documentation and rotation gaps F10 and F12.** Coverage on the 0.1.7 tree is
**96.9 / 95.5 / 86.7 / 38.6%** for proxy / token / config / `cmd/server` (59 test functions, 142 runs with
subtests). Verified in code and tests:

- **Read-only by construction (F7, F8; 0.1.4).** Only `GET` and `HEAD` are forwarded (`405` before
  any upstream or token-service call) and no request body is read, so the 32 MiB replay buffer is
  gone. A token is requested only for `registry:catalog:*` or `repository:<name>:pull`; a challenge
  for anything else is `403` with no token request. The challenge parser is quote-aware.
- **Scope-exact, bounded cache (F3, F7; 0.1.4).** A token is cached only under the scope it was
  issued for, in a cache of at most 512 entries (expired entries swept, then the one closest to
  expiry dropped); concurrent misses share one token request; a token the registry refuses is evicted.
- **PROXY-lens forwarding policy (F14, F15, F16; 0.1.6).** Every field named in `Connection` is
  stripped in both directions; cookies are not sent upstream and `Set-Cookie` and `Access-Control-*`
  are not passed to the UI; the proxy adds `Via` and refuses a looped request (`508`); at most 64
  forwards are in flight (`503` with `Retry-After` beyond that); the upstream has a 5 s dial and a
  30 s response-header deadline; request headers are capped at 32 KiB; an upstream failure is logged
  by class without the upstream address.
- **Release and image (F9; 0.1.4–0.1.6).** The tag workflow runs the same checks as CI through the
  reusable workflow, scans the published image with Trivy before cosign signs it, and prints a pinned
  `cosign verify`; `go.mod` names `toolchain go1.26.9`, the Dockerfile builder is pinned to that patch
  and fails on a mismatch (the 1.26.7 stdlib had eleven advisories, GO-2026-6607…6617).
- **0.1.7 (2026-10-18).**
  - *Route allowlist (F18).* Only `/v2/`, `/v2/_catalog` and the four per-repository read routes
    (`tags/list`, `manifests`, `blobs`, `referrers`), with the registry's own name, tag and digest
    grammars, are forwarded, in canonical form and never rewritten; everything else is `404` or `400`
    before any token or upstream call. `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`,
    `Cdn-Loop` and `Cf-*` (the Access assertion) no longer reach the registry.
  - *Limits exercised (F20).* A stalled upstream, a dial that never completes, a slow body, the
    in-flight bound and the 32 KiB header cap are driven against local servers; the production values
    are pinned.
  - *Rotation (F10).* `CLIENT_SECRET_FILE` is read again, once, after a token-service `401`; a changed
    value is retried, so a rotation needs no restart. Procedure and compromise steps are in `SECURITY.md`.
  - *Logs (F17).* A token-fetch failure is logged by class and status, never with the endpoint URL.
  - *Image and docs (F22, F12).* Licence notices (Go standard library, the CA bundle's MPL-2.0 copyright
    file, `LICENSE`) ship in `/usr/share/doc/registry-auth-proxy/` and an `image` CI job checks them;
    `SECURITY.md` states the transport (decision D18) and the rotation procedure; the README `cosign
    verify` is pinned to the publish workflow.
- Unchanged and still holding: inbound `Authorization` stripped, fail-closed `502` on a token-fetch
  error, `401→403` remap after a token is attached, a file-only client secret never logged, upstream
  redirects not followed, `..` traversal rejected, config URL validation, and spec-conformant token
  expiry (default 60 s; issue time = min(`issued_at`, local clock)).

**Findings after this pass: 22 — 13 RESOLVED, 7 MITIGATED, 0 ACCEPTED-RISK, 0 DEFERRED, 2 Positive.**
Nothing is Medium or higher; every open item is Low or Info and none widens access.

- **F5 corrected (Low, MITIGATED).** The baseline called the plaintext hop to the token service
  RESOLVED by "WireGuard + SPIFFE mutual authentication". The platform no longer runs mutual
  authentication (decision D18) and WireGuard protects only inter-node traffic; the cluster is one
  node. The hop is plain in-cluster HTTP bounded by NetworkPolicy, client-secret authentication at the
  token service and Cloudflare Access in front of the UI. `SECURITY.md` now says so (0.1.7).
- **Closed by the 0.1.7 fix wave:** F17, F18, F20, F22 (RESOLVED).
- **Still MITIGATED, with the remainder outside this repository or a maintainer task:**
  - F10: the procedure is documented and rotation is restart-free; the rehearsal, a cadence and a
    last-rotation record are maintainer tasks, and `SECRETS.md` / `docs/auth/OPERATIONS.md` need the
    proxy's Secret added (named in F10);
  - F12: the base Deployment manifest still names tag `0.1.1` (`k8s/`, platform);
  - F19: the proxy's own door is bounded by NetworkPolicy and Access; narrowing `:8181` to the
    `registry-ui` pod and a scheduled negative check are platform items;
  - F21: the Hydra client is registered with a `registry:push` scope that only Keto and the proxy
    withhold (platform manifest).
- **Still deferred to the pre-mainnet gate:** the rotation rehearsal and cadence (F10), limits sized and
  measured for the plan tier (F20 remainder), and external review.

**Posture:**

- Credential handling is exemplary for its size, and the proxy now enforces what it claims: pull-only
  scopes and methods, scope-exact caching, a bounded cache and a bounded forwarding surface.
- None of this escalates privilege beyond Keto's grants.
- The registry credential inventory (quay and Docker Hub tokens) is a maintainer item
  (`OPERATOR_TASKS.md` "Image registry credentials"), deferred to launch.

---

## Threat model / trust boundaries

| Actor | Holds / proves | Can do | Bounded by |
| --- | --- | --- | --- |
| Browser UI / same-namespace client (joxit's nginx; anyone who can drive the UI) | reachability to :8181; no credential. The public UI is behind Cloudflare Access | send `GET`/`HEAD` for a registry read route with any headers; drive scope prediction and cache keys | read-only upstream identity; `405` for other methods, no body forwarded (F8); scope-exact bounded cache (F3, F7); 64 in flight (F15); `ReadHeaderTimeout` and 32 KiB headers; 401→403 remap; route allowlist and canonical-path check (F18); `X-Forwarded-*`/`Cf-*` dropped (F18) |
| On-path attacker (proxy ↔ token service) | plaintext in-cluster HTTP on one node | observe the Basic-auth secret and issued tokens | NetworkPolicy, one node, WireGuard between nodes only; no mutual authentication (F5) |
| Malicious / compromised upstream registry | operator config, or MITM | craft `WWW-Authenticate` (`service`, `scope`); huge bodies; cookies, CORS grants, `Connection`-named fields, redirects | fetcher 10 s timeout + 64 KiB cap; redirects not followed (F4); streamed responses; quote-aware parse and a read-only scope filter (F8); response filtering (F14); 30 s response-header deadline (F15) |
| Token service / IdP (registry-token-service → Hydra, Keto) | the authority | issue tokens with the granted intersection | fail-closed 502 here; its own audit |
| Operator | env + mounted Secret | misconfigure URLs or identity scope; rotate the secret | URL validation at startup (F1). Rotation: `SECURITY.md` procedure, restart-free (F10) |

### Forwarding matrix (PROXY lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Client | method, path, query, every header (body is never read) | §A route policy (`GET`/`HEAD` only; the read-route allowlist and canonical paths, F18), header policy (F14, F18), limits (F15, F20) |
| Upstream (the registry) | status, headers, body, redirects, timing | response filtering (F14), redirects not followed (F4), deadlines (F15), streamed bodies |
| A party on the path to the upstream | the same, on plain in-cluster HTTP | NetworkPolicy and a single node (F5); the registry's own Bearer check |
| State store behind the gate | none: the token cache is in process memory | — |
| Whoever can reach the registry directly | the registry's own token authentication applies to them; there is no bypass of this hop to protect | the registry (F19) |

### Identity & credential matrix (AUTH lens)

| Authority / credential | Holder | What it confers | Misuse / compromise impact | Rotation / revocation plan |
| --- | --- | --- | --- | --- |
| OAuth client secret (`registry-browser`, confidential client, client credentials) | this service (`CLIENT_SECRET_FILE`, read at startup and again after a token-service refusal); the same value sits in `hydra-client-secrets` | tokens for the identity's Keto grants (pull + catalog) | registry read access as `registry-browser` | `SECURITY.md` "Client-secret rotation and compromise" (both Secrets, then the `hydra-client-setup` Job per `docs/auth/OPERATIONS.md`; the proxy re-reads the file on the resulting `401`, restart as fallback); no cadence or rehearsal record (F10) |
| Registry Bearer token (Distribution JWT) | in-memory per-scope cache | the token's `access` claim for its TTL | replay within the TTL | short TTL from the token service; scope-exact key (F7); margin `TOKEN_REFRESH_MARGIN` (30 s); evicted when the registry refuses it |
| Keto relations for `registry-browser` | platform | which repositories and actions | widening them no longer widens the proxy: it requests only read scopes (F8) | registry-token-service audit |
| Cloudflare Access session of the human using the UI | the browser, then joxit's nginx | reaching the UI at all | a leaked Access JWT header is no longer forwarded to the registry (F18, 0.1.7) | Cloudflare Access (PLATFORM lens) |

---

## Severity scale

Critical / High / Medium / Low / Info / Positive.

## Scope

- **In scope (`v0.1.6` = `7928960`; the 0.1.7 working tree for the fix wave):**
  - `cmd/server/main.go`, `internal/{config,proxy,token}/**` and tests
  - `Dockerfile`, `.dockerignore`, `go.mod`, `.env.example`, `scripts/*.sh` (image notices)
  - `.github/workflows/{go-ci,docker-publish}.yml`, `.github/dependabot.yml`
  - `README.md`, `CLAUDE.md`, `AGENTS.md`, `SECURITY.md`, `CHANGELOG.md`, `llms.txt`
  - read-only: `k8s/base/registry/{auth-proxy,networkpolicy.yaml,registry-ui}`,
    `k8s/clusters/meddleware-org/registry` (digest pin), `k8s/base/auth/jobs/*` (the `registry-browser`
    client and tuples), `config/images.yaml`, `docs/auth/OPERATIONS.md`
- **Out of scope:**
  - registry-token-service, Hydra, Keto and the Distribution registry (their own audits / upstream);
  - the Cloudflare Access policy and the cluster network itself (PLATFORM lens);
  - the registry credential inventory (maintainer item, `OPERATOR_TASKS.md` "Image registry
    credentials", before mainnet);
  - the Go stdlib.
- **Environment (2026-10-18, 0.1.7 tree, `GOTOOLCHAIN=go1.26.9`, the toolchain `go.mod` names; the 2026-10-09
  pass used local Go 1.27.1):**

| Command | Result |
| --- | --- |
| `go vet ./...`, `gofmt -l` | clean |
| `go test -race -cover ./...` | ok — `internal/proxy` **96.9%**, `internal/token` **95.5%**, `internal/config` **86.7%**, `cmd/server` **38.6%**; 59 test functions (142 runs with subtests), none skipped; the limit tests take about 4 s in all |
| golangci-lint v2.13.0, govulncheck v1.8.0 | `0 issues`; `No vulnerabilities found` |
| `CONTAINER_CLI=podman sh scripts/check-image-notices.sh` | `image notices OK` (rootless podman build of the Dockerfile; the notices and `LICENSE` are present in the image) |
| Registries (2026-10-10) | quay.io and Docker Hub tag `0.1.6` both resolve to `sha256:d98c347c…1581`, equal to `config/images.yaml` and the overlay pin |
| Live (2026-10-10) | `GET` and `POST https://registry-ui.meddleware.co.uk/v2/_catalog` without a session answer `302` to the Cloudflare Access login: the UI that fronts the proxy is not anonymous |
| Registries (2026-10-18) | 0.1.7 released and deployed 2026-10-18: `sha256:15038201…f097e`, cosign-verified against the workflow-anchored identity (`verify-digests.sh` 16/16); quay.io and Docker Hub tags were not re-queried by this audit pass |
| On-node route checks (2026-10-18, after the rollout) | allowed routes `200`, write methods `405`, non-routes `404`, non-canonical paths `400` (from the release facts; not re-run by this pass) |
| 2026-10-03 scratch probes (F3, F7, F8, F11) | superseded: each scenario is now a committed test (see the findings) |

  The 2026-10-09 results above are kept as the baseline of the 0.1.6 review; the 2026-10-18 rows are the
  0.1.7 tree.

---

## Findings

### F1 — `UPSTREAM_URL` / `TOKEN_ENDPOINT` validated at config time
**Severity:** Low   **Disposition:** RESOLVED (re-verified 2026-10-03 and 2026-10-09)
**Where:** `internal/config/config.go:490-495, 519-533` (`validateHTTPURL`: parse, scheme ∈
{http, https}, non-empty host); `internal/config/config_test.go` (`TestValidateHTTPURL`,
`TestLoadRejectsMalformedUpstreamURL`).
**History:**
- A scheme-less or mistyped `UPSTREAM_URL` was accepted, and every request then failed at round trip
  as an opaque 502 instead of failing fast at startup.
- Fixed by `validateHTTPURL` in `config.Load`.
- *The baseline text kept a stale "Status: DEFERRED" line under a RESOLVED header; the 2026-10-03 pass
  removed the contradiction.*
**Remediation / evidence (2026-10-09):** unchanged at `v0.1.6`; every required value missing, or a
non-http(s) or host-less URL, exits non-zero at startup (PX-M9). A query string in `TOKEN_ENDPOINT` is
still accepted and, since 0.1.7, merged correctly into the request URL (F11).

### F2 — Scope prediction emitted malformed scopes from crafted paths
**Severity:** Low–Medium   **Disposition:** RESOLVED (re-verified 2026-10-09; strengthened 2026-10-18)
**Where (0.1.6):** `NormalizePath` cleaned the path, rejected any `..` segment and kept `/v2` requests
under `/v2`; the handler answered `400 invalid path`; `PredictScope` normalised first. Tested by
`TestNormalizePath` and `TestPredictScope`.
**Where (0.1.7):** `Route` in `internal/proxy/scope.go` replaces `NormalizePath`: it rejects any empty,
`.` or `..` segment (and a trailing slash) with `400 invalid path`, and the repository name that becomes
the cache key must match the registry's name grammar (F18). Tested by `TestRoute`, `TestPredictScope`,
`TestForward_OnlyRegistryReadRoutes`, `TestWiredRoutePolicy`.
**Note:** unique repository names still mint keys, now bounded by the cache cap (F3). Empty and `.`
segments are no longer cleaned for prediction and forwarded as sent: they are refused (F18).

### F3 — Token cache has no size bound (memory and amplification) — **re-opened**
**Severity:** Low   **Disposition:** MITIGATED (re-opened 2026-10-03; the bound and single-flight
landed in 0.1.4, `e1ed1c8`; the load-amplification residual is accepted, S3)
**Where (at 2026-10-03):** `internal/token/cache.go:39-65`. `Get` deleted an expired entry only when
**that key** was read again, and `Set` never evicted.

**Issue (probe-verified):**

- The baseline resolution ("a crafted-path walk still adds entries on `Set` but they are pruned on
  the next `Get` miss for that key") assumes the same key is read again.
- A client requesting distinct repository names (`/v2/r0/tags/list` … `/v2/r499/tags/list`; no `..`
  needed, so F2 does not apply) creates one entry per name that is never read again. Probe: 500
  requests → **502 entries, 500 token-service calls**.
- **Amplification.** Each such request also costs:
  - an unauthenticated upstream probe;
  - a client-credentials exchange at the token service, which validates the secret at Hydra and
    checks Keto.

  There is no single-flight and no rate limit.
- **Callers.** Same-namespace callers only (joxit's nginx). In practice, that means anyone who can
  drive the UI or reach the pod network.

**Impact:**

- Memory growth bounded only by request volume over the token TTL (entries expire but are never
  removed unless re-read).
- Load amplification onto the IdP path.

**Remediation / evidence (2026-10-09):**

- **Bound.** `maxCacheEntries = 512` (`cache.go:177`); `Set` (`:236-249`) sweeps expired entries and,
  if none was expired, drops the one closest to expiry (`evictLocked`, `:253-270`); a token already
  inside the refresh margin is not stored. Tests: `TestCacheIsBounded`, `TestCacheEvictionKeepsEmptyScope`,
  `TestCacheSkipsTokenAlreadyInsideMargin`, `TestCacheExpiredEntryDeleted`.
- **Single flight.** `token.Flight` (`flight.go`) collapses concurrent misses for one `service`+scope
  into one token request, detached from any one caller's context (`handler.go:281-294`). Tests:
  `TestFlightSharesOneFetch`, `TestFlightDoesNotCacheResultsOrErrors`, `TestFlightKeysAreIndependent`,
  `TestServeHTTP_ConcurrentMissesShareOneTokenRequest`.
- **Residual (accepted).** Distinct repository names still each cost one probe and one token request;
  there is no negative cache (S3). The cost is bounded by the 64-forward cap (F15), the nginx limit of
  20 requests per second per visitor on `registry-ui` (`k8s/base/registry/registry-ui/ingress.yaml`),
  Cloudflare Access in front of the UI, and the token service's own limits. Each cache entry is one
  scope string and one token, so 512 entries is a small fixed memory cost.

### F4 — Upstream redirects no longer auto-followed
**Severity:** Low   **Disposition:** RESOLVED (redirect half, re-verified 2026-10-09 —
`handler.go:163-165` `CheckRedirect` → `http.ErrUseLastResponse`; `TestServeHTTP_DoesNotFollowUpstreamRedirect`).
The `service`/`scope` forwarding half the baseline left open is now resolved as **F8**.
**Note (2026-10-18):** `TestServeHTTP_DoesNotFollowUpstreamRedirect` pins the probe leg; the credentialed leg is now
pinned by `TestForward_NoCredentialReachesAForeignRedirectTarget` (a recording second server receives no
request, and the redirect is returned unchanged).

### F5 — Plaintext HTTP to the token service carries the Basic-auth secret and Bearer tokens
**Severity:** Low (deployment-dependent)   **Disposition:** MITIGATED (corrected 2026-10-09; the
baseline marked it RESOLVED on "Cilium WireGuard transparent encryption + SPIFFE mutual
authentication", which the platform no longer provides)
**Original text:** per the baseline, Cilium WireGuard transparent encryption + SPIFFE mutual
authentication on proxy → token service; `k8s/base/kube-system/cilium/values.yaml`,
`k8s/base/auth/mutual-auth-ciliumnetworkpolicy.yaml` — **not re-verified at 2026-10-03**.

**Remediation / evidence (2026-10-09):**

- `k8s/base/auth/mutual-auth-ciliumnetworkpolicy.yaml` does not exist, and `cilium/values.yaml`
  records that `authentication.mutual` (SPIRE) is not enabled (Cilium 1.20 deprecated it, decision
  D18). WireGuard has been live since 2026-10-01 but encrypts traffic **between nodes**; the cluster
  has one node, so the proxy → token-service hop is plain in-cluster HTTP on the node.
- What bounds it: the `registry` namespace's `default-deny-ingress` plus `allow-registry-ingress`
  (`k8s/base/registry/networkpolicy.yaml`), the single node, and the fact that the proxy has no Ingress
  (the token service's public route, `token.meddleware.co.uk`, is a different path: the proxy dials its
  ClusterIP). The residual risk is a hostile pod on the node, as in the registry-token-service
  audit (its F4 and F17).
- The AUTH lens requires an encrypted, mutually authenticated path or a finding; this entry records the
  honest state. Moving to a second node adds WireGuard but not mutual authentication.

**Correction (2026-10-03):** the baseline said this is "Documented in `SECURITY.md`". It is not:
SECURITY.md contained no WireGuard, SPIFFE, mTLS or NetworkPolicy text (F12). SECURITY.md also made
no false claim about it.

**Documentation (2026-10-18, 0.1.7):** `SECURITY.md` now has "Transport to the token service and the
registry": plaintext in-cluster HTTP, **not mutually authenticated** (decision D18), bounded by the
`registry` namespace NetworkPolicy (whole-namespace admission stated, F19), client-secret authentication
at the token service, the read-only grants, and the single node (WireGuard between nodes only). Written
consistently with the registry-token-service wording. The disposition stays MITIGATED: the hop is still
plaintext.

### F6 — Response splitting / header injection not exploitable
**Severity:** Positive (re-verified 2026-10-09) — header copy uses `Header().Add`. Go rejects CR/LF in
header values, and `service`/`scope` flow only into `url.Values.Encode`. Fields named in `Connection`
are now filtered in both directions as well (F14).

### F7 — A non-pull challenge poisons the pull-scope cache entry (read denial per repository)

**Severity:** Low (availability of registry browsing; any UI user can trigger it)
**Disposition:** RESOLVED (0.1.4, `e1ed1c8`)
**Where (at 2026-10-03):** `internal/proxy/handler.go:204-223`.

- `resolvedScope` is the challenge scope.
- `h.cache.Set(resolvedScope, …)` **and** `h.cache.Set(predictedScope, tok, …)` when they differ.
- `PredictScope` always predicts `:pull` (`scope.go:8-36`).

**Issue (probe-verified with a Keto-like token service that grants only pull):**

1. `DELETE /v2/app/manifests/sha256:abc` on a cold cache: predicted `repository:app:pull`; the probe
   gets `401` with `scope="repository:app:delete"`. The token service returns a token **without**
   pull (intersection: delete ∉ grants), and that token is stored under **both**
   `repository:app:delete` and `repository:app:pull`. The response is 403 (expected).
2. `GET /v2/app/tags/list` hits the cache under `repository:app:pull` and is served the no-pull
   token. The registry says `401`, remapped to **403**.
3. Browsing of `app` stays forbidden until the poisoned entry expires (the token TTL minus a 30-second
   margin). Each new `DELETE` re-poisons it.

- The README describes this exact request as normal ("e.g. a delete attempt the read-only identity is
  not granted").
- joxit issues `DELETE` when image deletion is enabled in its config.
- The AUTH lens requires "the cache key includes everything the token is scoped to"; this is the
  violation.

**Impact:** any user of the registry UI (or any same-namespace client) can deny read access to any
repository's pages, repeatedly. There is no privilege gain.

**Remediation / evidence (2026-10-09):**

- `Handler.token` (`handler.go:281-294`) caches only under the scope it fetched for; the second `Set`
  under the predicted alias is gone. `proxyWithToken` evicts a token the registry refuses
  (`:275`), so a wrong-scope token cannot linger.
- `DELETE` can no longer start the sequence at all: it is `405` before any probe (F8).
- Tests: `TestServeHTTP_TokenCachedOnlyUnderIssuedScope` (the registry challenges for
  `repository:a:pull` on a `/v2/b/…` path; the token is not served from `b`'s key),
  `TestServeHTTP_RefusedTokenIsDropped`, `TestServeHTTP_RefusesNonReadChallenge`.

### F8 — Read-only is not enforced by the proxy: all methods forwarded, and any challenge scope requested

**Severity:** Low (defence in depth; Keto remains the authority)   **Disposition:** RESOLVED (0.1.4,
`e1ed1c8`)
**Where (at 2026-10-03):** `internal/proxy/handler.go:133-154` (bodies buffered for any method),
`:157-169` (the challenge scope is used verbatim), `:219-251` (the method is forwarded);
`cmd/server/main.go:186-188` (no method guard); SECURITY.md invariant 4; CLAUDE.md "This proxy is
read-only (pull + catalog)".

**Issue (probe-verified):**

- **Methods.** `DELETE` and `PUT` reached the registry. Every method is forwarded, with up to 32 MiB
  of body buffered per request.
- **Scopes.** The token service was asked for `repository:app:delete` with `registry-browser`
  credentials. SECURITY.md invariant 4 says the proxy "predicts **and requests** only `pull` and
  `catalog` scopes". Prediction is pull-only, but requests follow the registry's challenge.
- **Accidental narrowing.** `parseBearerChallenge` splits on commas without honouring quotes, so a
  push challenge `scope="repository:app:pull,push"` is truncated to `repository:app:pull` (probe).
  This happens to prevent push-scope requests, but not `delete` or `*`, and only by accident.
- **Where read-only actually comes from.** If Keto ever grants `registry-browser` more than pull and
  catalog (operator error, or an org-level fallback grant in registry-token-service), the proxy would
  obtain and use write or delete tokens. Its own read-only claim provides no defence.

**Impact:** read-only rests entirely on the identity's Keto grants. A mis-grant becomes write or
delete access through the UI. The proxy's stated invariant does not hold.

**Remediation / evidence (2026-10-09):**

- **Methods.** `ServeHTTP` answers anything but `GET`/`HEAD` with `405` and `Allow: GET, HEAD` as its
  first step (`handler.go:176-180`); `roundTrip` builds the upstream request with no body (`:292`), so
  nothing is read or buffered and the 32 MiB cap is gone. Test: `TestServeHTTP_OnlyGetAndHead`
  (PUT, POST, DELETE, PATCH, OPTIONS → 405; neither the upstream nor the token service is hit),
  `TestServeHTTP_HeadIsForwarded`.
- **Scopes.** `readOnlyScope` (`challenge.go:455-473`) admits only `registry:catalog:*` and
  `repository:<name>:pull`, checking every space-separated entry; anything else, including
  `pull,push`, `delete`, `*`, an unknown type or a malformed entry, is `403` with no token request
  (`handler.go:248-255`). Tests: `TestServeHTTP_RefusesNonReadChallenge` (seven refused scopes, token
  service never called), `TestReadOnlyScope`.
- **Parser.** Quote-aware (F11), so the accidental `pull,push` truncation no longer decides anything.
- **Read-only no longer rests on Keto alone**: the Keto tuples (`pullers`, `listers`), the proxy's
  method and scope filters, and the token service's intersection are independent layers. The Hydra
  client registration is still broader than needed (F21).
- **Product effect (OQ6):** the `registry-ui` manifest sets `DELETE_IMAGES: "true"`, so the UI's delete
  action now fails with `405` by design.

### F9 — The release gate is weaker than CI, and the image toolchain differs from the checked one

**Severity:** Low   **Disposition:** RESOLVED (0.1.4 `e1ed1c8`, 0.1.5 `9eb475f`)
**Where (at 2026-10-03):** `.github/workflows/docker-publish.yml:31-45` (`verify`: `go vet` + `go test -race`
only); `go-ci.yml` (golangci-lint, govulncheck, Trivy on branches); `Dockerfile:4` (builder digest);
`go.mod` (`go 1.26.6`).

**Issue / Impact:**

- **Tag-time checks.** A `v*` tag publishes without golangci-lint, govulncheck or Trivy on the tagged
  commit, and without an image scan.
- **Toolchain mismatch.** The builder digest is the one static-server uses, whose SBOM shows
  `stdlib go1.26.7`, while CI checks 1.26.6. The shipped stdlib is not the one govulncheck evaluated.

This is the same pattern as static-server F2.

**Remediation / evidence (2026-10-09):**

- **Gate parity.** `docker-publish.yml` `verify` now calls `./.github/workflows/go-ci.yml` as a
  reusable workflow (`workflow_call`), so lint, vet and race tests, govulncheck (pinned v1.8.0) and the
  Trivy filesystem scan run on the tagged commit; both publish jobs `need: verify`.
- **Scan before sign.** `publish-public` runs Trivy on the pushed digest
  (`CRITICAL,HIGH`, `exit-code: 1`, `ignore-unfixed`) before `cosign sign`; the SBOM is a signed SPDX
  attestation and provenance is attested for both registries, none with `continue-on-error`. Only the
  self-hosted mirror job is best-effort (`continue-on-error`, fails without credentials — a maintainer
  item) and is not signed.
- **Toolchain.** `go.mod` carries `toolchain go1.26.9`; `Dockerfile:4` pins `golang:1.26.9-bookworm`
  by digest and `:19` fails the build when `go env GOVERSION` differs from the `go.mod` toolchain.
  0.1.5 moved off 1.26.7, whose `net/http` and `net/textproto` carried eleven advisories
  (GO-2026-6607…6617).
- **Pinning.** Actions are pinned by full SHA; Dependabot (`e70bb2e`) updates the Docker builder and
  the actions weekly in grouped pull requests (there is no Go module to track).
- The published `cosign verify` command is pinned to this repository's publish workflow in the job
  summary; the README's own example is not (F12).

### F10 — Client-secret rotation is undocumented, and the secret is read only at startup

**Severity:** Info (AUTH B.AUTH-1: "a credential without a rotation plan is a finding")
**Disposition:** MITIGATED (0.1.7, commit `de46a96`: the procedure and the compromise steps are documented
and the proxy re-reads the secret file after a refusal, so a rotation needs no restart; the rotation
rehearsal, a cadence and a last-rotation record are maintainer tasks, Section D)
**Where (0.1.6):** `internal/config/config.go` (read once); README, SECURITY.md and CLAUDE.md (no
"rotat…" anywhere).
**Where (0.1.7):** `internal/token/fetcher.go` (`WithSecretReload`, `Fetch`, `refreshSecret`),
`internal/config/config.go` (`ReadSecret`, `Config.SecretFile`), `cmd/server/main.go` (`newMux`);
`SECURITY.md` "Client-secret rotation and compromise"; README "Secret rotation"; `.env.example`.

**Issue / Impact (0.1.6):**

- Rotating the `registry-browser` secret in Hydra makes every token fetch fail (fail-closed `502`)
  until the pod restarts with the new Secret.
- There was no documented sequence and no compromise procedure.

**Remediation / evidence (2026-10-18):**

- **Decision rule.** Re-reading the file on a `401` is the small, safe change S4 named, and it is
  consistent with the invariants: the secret stays in `CLIENT_SECRET_FILE` and in process memory only,
  is never logged and never an environment variable; there is no watcher or background goroutine
  (CLAUDE.md "What not to do" now says so).
- **Mechanism.** On a `401` from the token service the fetcher calls the reload function, which reads
  the file; if the value differs from the one the request used, the fetch is retried **once** with it
  (concurrent fetches that find the secret already replaced retry without another read); an unchanged
  or unreadable file leaves the original `401` failure, so the request still fails closed (`502`).
  Only `401` triggers a read: a `5xx` or a transport failure does not. The log lines name no value
  and no path (`client secret reloaded after the token service refused the credentials`; on a read
  failure `cause: unreadable`).
- **Tests:** `TestFetchRereadsRotatedSecret` (no read on success; one read and one retry after the
  rotation; the next fetch needs neither; no secret in the log), `TestFetchRotationFailsClosed` (file
  unchanged, file unreadable, no reloader: one request and at most one read), `TestFetchOtherFailuresDoNotReload`,
  `TestFetchConcurrentRotation` (16 concurrent fetches across a rotation, race-clean),
  `TestReadSecret`, `TestLoadRecordsSecretFile`, and end to end through the wired proxy
  `TestSecretRotationWithoutRestart` (fake registry and token service, a real file: closed `502` while the
  file is stale, `200` after it changes, no restart).
- **Procedure.** `SECURITY.md`: generate; update **both** `hydra-client-secrets`
  (`browser-client-secret`) and `registry-auth-proxy-secret` (`client-secret`); wait for the kubelet to
  refresh the mounted file (not a `subPath` mount, so it updates in place); re-run the
  `hydra-client-setup` Job (the old secret stops working at once); the proxy recovers on the next token
  request, with `kubectl -n registry rollout restart deployment/registry-auth-proxy` as the fallback.
  The compromise procedure is the same steps with the new value at once, then a review of the token
  service and registry logs. Hydra holds one secret per client, so there is no overlap window to
  rehearse beyond the Secrets-first ordering.
- **Outside this repository (mention only, not edited):**
  - `SECRETS.md` should list `registry-auth-proxy-secret` (namespace `registry`, key `client-secret`,
    SOPS source `registry/auth-proxy-secret.enc.yaml`, written by `bootstrap/profiles/single-node.sh`
    and `recover-secrets.sh`) and say it must equal `browser-client-secret` in `hydra-client-secrets`;
  - `docs/auth/OPERATIONS.md` "Rotate a client secret" step 4 should name that Secret and say the proxy
    needs no restart if the Secret is updated before the Job runs (restart as the fallback).
- **Maintainer:** a rotation cadence, a recorded last-rotation date, and one rehearsal against the live
  cluster (`OPERATOR_TASKS.md`).

### F11 — Challenge parsing and fetch-URL details

**Severity:** Info   **Disposition:** MITIGATED (parser and body-read halves RESOLVED in 0.1.4, the
query-string half in 0.1.7; the multiple-scope behaviour is by design and the health endpoint is
process liveness only)
**Where (at 2026-10-03):** `handler.go:323-348`, `fetcher.go:204-209`.

- **Not quote-aware.** `parseBearerChallenge` splits on `,` without honouring quoted strings:
  `pull,push` is truncated (F8), and a `realm` containing a comma shifts parsing.
- **Multiple scopes.** Space-separated scopes are passed through as one `scope` value (probe). The
  Distribution spec allows repeated `scope` parameters, so behaviour depends on the token service.
- **Endpoint query string.** `f.endpoint + "?" + params.Encode()` produces a malformed URL if
  `TOKEN_ENDPOINT` already carries a query (`?a=b?service=…`). F1's validation does not reject a
  query.
- **Liveness.** `/healthz` is static (process liveness only), which is acceptable but undocumented.
  No `ReadTimeout` means a slow request body (up to 32 MiB) can hold a connection indefinitely (GO-M1
  partial). The missing `WriteTimeout` is intentional for streaming blobs.

**Remediation / evidence:** a quote-aware challenge parser (RFC 7235 auth-param grammar) with
tests; build the fetch URL with `url.Parse` + `Query().Set`; add `ReadTimeout` or a per-request body
deadline.

**Status (2026-10-09):**

- **Parser — RESOLVED (0.1.4).** `parseBearerChallenge` / `readParamValue` (`challenge.go:401-449`)
  scan quoted strings with escapes and match the scheme case-insensitively. `TestParseBearerChallenge`
  pins a comma inside a quoted scope, a space-separated list, an escaped quote, a lowercase scheme, a
  `service=` string inside another parameter, and a non-Bearer challenge.
- **Multiple scopes — unchanged by design.** `readOnlyScope` now vets every entry, but the list still
  goes to the token service as one `scope` value (`fetcher.go:368-372`); how it is read is the token
  service's (registry-token-service F16). The registry's challenges for the UI's requests name one scope each, so this is dormant.
- **Endpoint query string — RESOLVED (0.1.7, commit `de46a96`).** The fetch URL is now built with
  `url.Parse` and `Query().Set`, so an endpoint that already carries a query stays well-formed (its
  parameters are kept, a stray `scope` does not survive an empty scope). Test:
  `TestFetchKeepsEndpointQuery`. The deployed `TOKEN_ENDPOINT` has no query; this removes the footgun.
- **Body hold — moot.** No request body is read (F8); `ReadHeaderTimeout` is 10 s, so there is nothing
  for a `ReadTimeout` to bound. The missing `WriteTimeout` stays intentional (blobs stream).
- **`/healthz`** is process liveness only and is documented as such in the README endpoint table; it
  does not check the registry or the token service, so a downstream outage does not restart the pod.

### F12 — Documentation drift

**Severity:** Info   **Disposition:** MITIGATED (0.1.7, commit `de46a96`: every item that lives in this
repository is fixed; the base Deployment manifest tag is in `k8s/`, outside it)

- SECURITY.md invariant 4 ("predicts and requests only `pull` and `catalog`") was false for requests
  (F8). CLAUDE.md "read-only" described the identity, not the proxy (F8).
- SECURITY.md did not document the transport protection F5 relies on. The baseline claimed it did.
- No secret-rotation procedure anywhere (F10).
- The baseline audit (2026-09-18) was not committed. It also contained the F1 and I14 contradictions
  noted above.

**Status (2026-10-18, 0.1.7):**

- **Fixed in 0.1.4:** SECURITY.md invariants 4 and 5, CLAUDE.md invariants 3–4 and the README /
  AGENTS.md request flow describe the code (read-only by construction, scope-exact bounded cache);
  CLAUDE.md also records the 0.1.6 forwarding rules.
- **Fixed in 0.1.7:**
  - SECURITY.md has "Transport to the token service and the registry" (plaintext in-cluster HTTP, no
    mutual authentication per decision D18, NetworkPolicy, client-secret authentication, single node;
    consistent with F5 and with registry-token-service) and "Client-secret rotation and compromise"
    (F10); invariant 1 mentions the re-read; a new invariant 7 and a "Forwarding policy" section state
    the route allowlist, the stripped fields and the limits (F18, F15);
  - the README `cosign verify` example now pins `docker-publish.yml@refs/tags/v*` (the same regexp the
    publish job summary prints), and the build example no longer names `v0.1.0`;
  - CLAUDE.md, AGENTS.md, `llms.txt`, the README and `.env.example` describe the route allowlist, the
    re-read, the notices and the new tests;
  - `docs/` (this audit) is committed with the release commit.
- **Still open, outside this repository:** `k8s/base/registry/auth-proxy/deployment.yaml` names tag
  `0.1.1` (the cluster overlay replaces it with the 0.1.7 digest since 2026-10-18 (0.1.6 before), so the cluster is correct; the base
  alone would run 0.1.1). Platform item: bump or remove the tag in the base, or make the base reference
  the placeholder the overlay already replaces. Not edited here.

### F13 — Positive: credential handling and fail-closed behaviour are implemented and tested

**Severity:** Positive (re-verified 2026-10-09)

- **Secret custody.** The client secret is read only from `CLIENT_SECRET_FILE` (non-empty, trimmed),
  never from env, never logged (since 0.1.7 it is also re-read from that file after a token-service
  refusal, F10). Error messages never contain credentials.
  `.dockerignore` excludes `client-secret`, `*.key`, `*.pem` and `.env*` (AUTH-M2).
- **Fail closed.** A token-service error or non-200 → `502` (`TestServeHTTP_TokenFailureIsBadGateway`),
  never a naked `401` (AUTH-M4).
- **Inbound credentials.** `Authorization` is stripped (plus `Proxy-Authorization` as hop-by-hop),
  the Bearer is injected only toward the configured upstream, redirects are not followed
  (`TestServeHTTP_DoesNotFollowUpstreamRedirect`), and `401→403` is remapped after injection (AUTH-M8).
- **Spec-conformant expiry (0.1.3).** A default of 60 s when `expires_in` is absent or ≤ 0, and an
  issue time of min(`issued_at`, now), so a fast IdP clock cannot extend caching. The refresh margin
  is subtracted (`TestFetchExpiry`).
- **Bounded fetches.** The token fetch has a 10-second timeout and a 64 KiB response cap
  (`TestFetchFailsClosed`). No request body is read or forwarded since 0.1.4 (the 32 MiB cap and its
  test were removed with the buffer). `ReadHeaderTimeout` is 10 s.
- **Image and release.** Stdlib only; `scratch`, nonroot 65534; digest-pinned builder checked against
  the `go.mod` toolchain (Go 1.26.9); multi-arch; keyless cosign, signed SPDX SBOM and provenance
  attestations; the release runs CI-equivalent checks and scans the image before signing (F9).

### F14 — Forwarding policy follows the PROXY lens: `Connection`-named fields, cookies, CORS, `Via` loop check

**Severity:** Low (hardening of a credential-injecting hop)   **Disposition:** RESOLVED (0.1.6,
`7928960`)
**Where:** `internal/proxy/handler.go:55-103` (hop-by-hop set, `viaToken`, `requestDropped`,
`responseDropped`), `:148-154` (loop check), `:297-311` (request policy), `:321-347` (response policy
and `connectionNamed`), `:358-361` (`isCORS`); `internal/proxy/forwarding_test.go`.
**Issue (before 0.1.6):** only the fixed RFC 9110 hop-by-hop set was removed. A field named in the
client's or the upstream's `Connection` header was forwarded, client cookies (for example the
Cloudflare Access session cookie the browser sends to the UI host, which joxit's nginx passes on) could
reach the registry, an upstream
`Set-Cookie` or `Access-Control-*` field reached the UI, and nothing stopped a request that had
already passed through the proxy (for example an upstream that resolves back to it) from looping.
**Remediation / evidence:**

- **Request side.** `roundTrip` drops `Authorization` (replaced, never appended: the proxy's Bearer is
  set with `Header.Set`), the fixed hop-by-hop set, `Cookie`/`Cookie2`, and every field the client named
  in `Connection`; it adds `Via: 1.1 registry-auth-proxy` and sets `Host` to the upstream.
- **Response side.** `copyResponse` drops the hop-by-hop set, every `Connection`-named field,
  `Set-Cookie`/`Set-Cookie2` and every `Access-Control-*` field (the UI is same-origin behind nginx,
  so an upstream grant would only widen who may read the response).
- **Loop.** A request already carrying a `Via` with `registry-auth-proxy` is `508` before any upstream
  or token-service call.
- Tests: `TestForward_RequestFieldPolicy` (a client `Authorization` is replaced, not appended; `Cookie`,
  `Proxy-Authorization` and two `Connection`-named fields never reach the registry; an ordinary
  `Accept` does; `Via` is added), `TestForward_ResponseFieldPolicy` (`Access-Control-*`, `Set-Cookie`,
  `Connection` and its named field are dropped; `Content-Type` and the Distribution version field pass),
  `TestForward_LoopIsRefusedBeforeAnyUpstreamCall` (508, zero upstream hits), `TestIsHopByHop`.
- Not covered by this finding: the request policy was a denylist (F18, resolved in 0.1.7).

### F15 — Concurrency bound, upstream deadlines and header cap

**Severity:** Low (availability)   **Disposition:** RESOLVED (0.1.6, `7928960`; the values are exercised
by tests since 0.1.7, F20)
**Where:** `internal/proxy/handler.go` (`limits`, `defaultLimits`, `newHandler`, the in-flight semaphore
in `ServeHTTP`); `cmd/server/main.go` (`newServer` and its constants);
`internal/proxy/forwarding_test.go`, `limits_test.go`.
**Issue (before 0.1.6):** the proxy accepted unlimited concurrent forwards, the upstream transport had
no dial or response-header deadline (a stalled registry held a connection until the client gave up),
and request headers were allowed the net/http default of 1 MiB.
**Remediation / evidence:**

- **In flight.** `DefaultMaxInFlight = 64` forwards, a non-blocking counting semaphore; the 65th
  concurrent request is answered at once with `503` and `Retry-After: 1`, and the slot is released on
  return. Test: `TestForward_ConcurrencyIsBounded` (64 held open, the next is refused, and a request
  after the burst succeeds).
- **Upstream.** Dial 5 s and response-header 30 s on the transport; no total deadline, so blob
  downloads stream for as long as the client reads. `Proxy: nil` keeps the in-cluster hop off any
  environment proxy.
- **Inbound.** `ReadHeaderTimeout` 10 s, `IdleTimeout` 120 s, `MaxHeaderBytes` 32 KiB (net/http answers
  `431` beyond it); no `WriteTimeout`, intentionally.
- **Memory.** Streaming with `io.Copy`: 64 in flight × the copy buffer, not a body cap; the pod limit
  is 128 Mi.

### F16 — Upstream failures are logged by class, without the upstream address

**Severity:** Info   **Disposition:** RESOLVED (0.1.6, `7928960`)
**Where:** `internal/proxy/handler.go:221-226, 301-306, 405-419` (`errorKind`);
`TestForward_UpstreamFailureLogsNoHostname`.
**Issue (before 0.1.6):** the probe and forward errors were logged with the error text, which carries
the upstream URL and so an internal hostname.
**Remediation / evidence:** the log line carries `cause` = `timeout`, `canceled` or `unreachable`
only, and the client sees the fixed body `upstream unavailable` with `502`. The test closes the
upstream, then asserts the host and port appear in neither the log nor the response body and that
`"cause":"unreachable"` is logged. The token-fetch path is covered since 0.1.7 (F17).

### F17 — A token-service failure still logs the token endpoint URL

**Severity:** Info   **Disposition:** RESOLVED (0.1.7, commit `de46a96`)
**Where (0.1.6):** the handler logged `slog.Error("token fetch error", …, "err", err)`, and the error
(`fmt.Errorf("token endpoint: %w", err)`) wrapped the `*url.Error` carrying the full request URL.
**Where (0.1.7):** `internal/token/fetcher.go` (`FetchError`, `FailureClass`, `FailureStatus`,
`transportError`) and the `token fetch error` log in `internal/proxy/handler.go`.
**Issue (before 0.1.7):** when the fetch failed at the transport level, the logged error included
`http://token-service.registry.svc.cluster.local:8080/token?scope=…&service=…`: an internal hostname in
the default-level log, which the PROXY lens *Error mapping* row forbids. Not a secret (the Basic
credential travels in a header), and the client saw only `auth service error` with `502`.
**Remediation / evidence:** every fetch failure is a `*FetchError` whose text never carries the endpoint
or an address (a transport failure reads `token endpoint unreachable|timeout|canceled`); the handler logs
`cause` = `timeout`, `canceled`, `unreachable`, `status`, `malformed` or `request`, plus the `status`
code when the token service answered with one. The cause stays reachable through `errors.Is` (a cancelled
context is still `context.Canceled`). Tests: `TestForward_TokenFailureLogsClassWithoutEndpoint` (endpoint
closed, answering 503, answering garbage: `502 auth service error`, the class in the log, and neither the
host, the path, `service=`, the secret nor `Basic ` in the log or the body), `TestFetchErrorsCarryNoEndpoint`
(six failure kinds, class and status, no host or URL in the text).

### F18 — Forwarding policy is a denylist: any path is forwarded, and some client fields pass through

**Severity:** Low   **Disposition:** RESOLVED (0.1.7, commit `de46a96`)
**Where (0.1.6):** `internal/proxy/handler.go` (`roundTrip`), `internal/proxy/scope.go`
(`NormalizePath`).
**Where (0.1.7):** `Route` and `routeRules` in `internal/proxy/scope.go`; the route check at the top of
`ServeHTTP`; `isEdgeField` and `forwardingDropped` in `internal/proxy/handler.go`.
**Issue (before 0.1.7):** three related gaps against the PROXY lens *Route & method policy* and
*Request header policy* rows:

1. **No route allowlist.** Any `GET`/`HEAD` path was forwarded, not only the `/v2` read routes the
   scope predictor knew.
2. **Path forwarded as sent.** `NormalizePath` cleaned the path for scope prediction but `roundTrip`
   forwarded `r.URL.Path` unchanged, so a trailing slash and the decoded form of an encoded slash
   (OQ3) reached the registry while the cache key came from the cleaned path.
3. **Denylist for client fields.** `X-Forwarded-*`, `Forwarded`, `X-Real-IP` and the Cloudflare-added
   `Cf-Access-Jwt-Assertion` passed to the registry as joxit's nginx received them; a Distribution
   registry can build absolute `Location` URLs from `X-Forwarded-Host`/`-Proto`, and an Access
   assertion is a bearer for the UI application.

**Correction (2026-10-18):** the 0.1.6 text of point 2 also said `//` and `.` segments were forwarded as
sent. In the wired server that was not so: `net/http`'s `ServeMux` answers `307` to the cleaned path for a
raw path with an empty, `.` or `..` segment before the handler runs (checked and now pinned by
`TestWiredRoutePolicy`). It was true of the `Handler` used directly, and for the decoded forms
(`%2F..%2F`, which the mux does not see as unclean) only the `..` check applied.
**Remediation / evidence (0.1.7):**

- **Route allowlist.** Only `/v2/`, `/v2`, `/v2/_catalog` and
  `/v2/<name>/{tags/list,manifests/<ref>,blobs/<digest>,referrers/<digest>}` are forwarded. `<name>` must
  match the registry's repository-name grammar (lower-case components joined by `.`, `_`, `__` or
  dashes, at most 255 characters), `<ref>` a tag or an OCI digest, `<digest>` an OCI digest. Any other
  canonical path is `404` (answered here, as the registry would, without a token request); a path with an
  empty, `.` or `..` segment or a trailing slash is `400 invalid path`. Both are answered before the
  in-flight slot, the token service and the registry. What the UI needs was checked against
  joxit/docker-registry-ui 2.6.0 (the pinned image): its nginx proxies only `location /v2`, and its
  script calls `/v2/`, `/v2/_catalog?n=`, `/v2/<name>/tags/list` and `/v2/<name>/manifests/<ref>` (the
  config blob is `blobs/<digest>`); `referrers` is the OCI read route the registry also serves.
- **Path forwarded exactly as checked.** `Route` never rewrites: an accepted path is built only from the
  name, tag and digest grammars plus `/` and `:`, so an encoded slash that decodes to a separator is a
  legal hierarchical name, and NUL, newline, space, `%`, a second `:` or any other smuggled byte fails the
  grammar (OQ3 decided). The scope used as the cache key is built from the validated name, so a crafted
  path cannot mint a malformed scope.
- **Edge fields.** `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop` and every
  `Cf-*` field (including `Cf-Access-Jwt-Assertion`, `Cf-Connecting-Ip`) are not forwarded upstream.
- **Why the other request fields remain a denylist.** `Accept` (manifest media types), `Range`,
  `If-None-Match`, `User-Agent` and the like are what the UI needs and the registry defines; an
  allowlist of them would break registry features for no gain once the credential-bearing and
  forwarding fields are removed. This is the PROXY lens's accepted shape for a read-only pass-through.
- Tests: `TestRoute` (allowed shapes; 400 for traversal, `//`, `.`, trailing slash, relative path; 404
  for the root, lookalike prefixes, upload sessions, upper case, spaces, NUL, newline, scope injection,
  names over 255), `TestPredictScope`, `TestForward_OnlyRegistryReadRoutes` (no upstream or token hit for
  refused paths; an allowed route reaches the registry at exactly the checked path),
  `TestForward_EdgeFieldsAreNotForwarded` (twelve edge fields dropped; `Accept`, `Range`, `User-Agent`
  forwarded), `TestWiredRoutePolicy` (the real server and mux).

### F19 — The proxy's own door: NetworkPolicy breadth, no origin to lock, no scheduled negative check

**Severity:** Info   **Disposition:** MITIGATED (a scheduled negative check is a pre-mainnet item,
Section D)
**Where:** `k8s/base/registry/networkpolicy.yaml`; `k8s/base/registry/auth-proxy/{deployment,service}.yaml`;
`k8s/base/registry/registry-ui/{deployment,ingress}.yaml`; `CLAUDE.md` ("network policy prevents
external access").
**Issue / evidence:**

- **No origin lock is needed, and none exists.** The PROXY lens *Origin lock* row presumes an upstream
  reachable only through the gate. The registry is public by design behind its own Bearer
  authentication (`registry.meddleware.co.uk`), so this hop is a convenience, not the gate; there is no
  bypass of it to prevent.
- **What does need a lock is the proxy itself**, because it confers the `registry-browser` identity to
  anyone who can reach `:8181` with no credential. The `registry` namespace is default-deny ingress;
  `allow-registry-ingress` applies to every pod in the namespace and admits the `nginx-ingress`,
  `monitoring` and `registry` namespaces, and `platform-probe` (apps) on `8181`/`8080`. So any pod in
  those namespaces can reach the proxy, not only joxit's pod. There is no Ingress for the proxy
  (`registry-ui` proxies to it internally), egress is open, and no per-pod selector narrows `8181` to
  the `registry-ui` pod.
- **The human door is authenticated.** `registry-ui.meddleware.co.uk` answers `302` to the Cloudflare
  Access login without a session (checked 2026-10-10) and carries an nginx per-visitor limit
  (20 requests per second, burst 80).
- **No scheduled negative check** that a direct request from a pod outside the allowed set is
  refused; the platform-probe catalogue check is the positive path only.
**Why mitigated, not resolved:** the exposure needs a hostile pod in an admitted namespace; the
identity is read-only and the proxy's request surface is now bounded (F8, F14, F15). Narrowing the
policy to the `registry-ui` pod and probing it is a platform change (PLATFORM lens).
**Note (2026-10-18):** `SECURITY.md` now states the whole-namespace admission and that the proxy confers
the read-only identity to any pod that reaches it. Platform item, not edited here: in
`k8s/base/registry/networkpolicy.yaml`, narrow the `8181` ingress to the `registry-ui` pod (plus
`platform-probe`) with a `namespaceSelector` and `podSelector` in one peer, and add the scheduled negative
probe.

### F20 — The new deadlines and header cap are configured but not exercised by tests

**Severity:** Info   **Disposition:** RESOLVED (0.1.7, commit `de46a96`; sizing and measuring the limits for
the plan tier stays a pre-mainnet measurement, Section D)
**Where (0.1.6):** the values were constants in `NewHandler` and `main`; `cmd/server` had 0% coverage.
**Where (0.1.7):** `limits`/`defaultLimits`/`newHandler` in `internal/proxy/handler.go` (the constants
become fields a test can shorten); `newServer` and its constants in `cmd/server/main.go`;
`internal/proxy/limits_test.go`, `dial_linux_test.go`; `cmd/server/main_test.go`.
**Issue (before 0.1.7):** the PROXY lens *Limits* tests require "a stalled upstream ends with the stated
status and releases any admission state" and an oversize request to be refused. Only the in-flight bound
was tested; nothing stalled an upstream past the response-header deadline, closed a slow dial, or sent a
header block over 32 KiB, and a mistaken edit of a constant would have passed the suite.
**Remediation / evidence (all local `httptest` servers or loopback listeners; no external network, short
deadlines, the stalling upstreams are released at the end of each test; 0 skips, three consecutive runs
under `-race`):**

- `TestDefaultLimits` pins the production values (dial 5 s, response-header 30 s, 64 in flight; the
  handler's transport has the 30 s deadline, no environment proxy and no total deadline).
- `TestLimits_StalledUpstreamEndsInBadGatewayAndReleasesSlot` (probe leg and credentialed leg): an
  upstream that accepts and never answers ends in `502` at the (shortened, 200 ms) response-header
  deadline, the log carries `cause: timeout` and no upstream address, the in-flight slot is released (the
  bound is 1, so the follow-up `200` proves it).
- `TestLimits_DialDeadlineEndsInBadGateway` (Linux): a loopback listener with a full accept queue
  stalls `connect()`; the 150 ms dial deadline ends it in `502`, `cause: timeout`. It skips, rather than
  fails, on a host that completes connections to a full queue; it did not skip here.
- `TestLimits_SlowBodyStreamsPastTheHeaderDeadline`: a body that outlasts the response-header deadline
  streams in full (no total deadline).
- `TestLimits_InFlightBoundFollowsTheLimit`: the third request against a bound of 2 is `503` with
  `Retry-After`; the bound comes back after the held forwards finish.
- `TestServerLimits` (32 KiB header cap, 10 s header read, 120 s idle, no read or write timeout) and
  `TestServerRefusesOversizeHeaders` (a 40 KiB header is `431` and never reaches the handler; 16 KiB is
  served), `TestHealth`, `TestSecretRotationWithoutRestart`, `TestWiredRoutePolicy`: `cmd/server` coverage
  0% to 38.6% (`main` itself, which needs a signal, is the rest).
- **Remainder (maintainer, pre-mainnet):** limits sized for the plan tier and measured under load.

### F21 — The `registry-browser` Hydra client is registered with a `registry:push` scope

**Severity:** Low   **Disposition:** MITIGATED (three independent layers withhold push; the
registration is a platform manifest)
**Where:** `k8s/base/auth/jobs/hydra-client-setup.yaml:92-94`
(`registry-browser` … `"registry:push registry:pull registry:catalog"`);
`k8s/base/auth/jobs/keto-relations-setup.yaml:107-123`.
**Issue:** the AUTH lens *OAuth client configuration* row requires minimal scopes. The browser client
is registered with the same scope set as the CI client, although it is pull-and-catalog only; the job's
own comment says so. The restriction comes from Keto (`pullers` on `meddleware-org` and `listers` on
`catalog` only, with a verification phase that aborts the job if they do not resolve), from the token
service (granted = requested ∩ Keto), and, since 0.1.4, from the proxy, which never asks for a push
scope (F8). The client scope is not what the token service enforces.
**Why mitigated, not resolved:** the fix (drop `registry:push` from the client registration, re-run
the setup Job) is a one-line platform change outside this repository (2026-10-18: not edited here; the
Hydra client registration and its Job are platform manifests — OQ7). A mis-edit of the Keto tuples
alone no longer widens the browser.

### F22 — No licence or notice text for the compiled-in stdlib and the CA bundle ships in the image

**Severity:** Info   **Disposition:** RESOLVED (0.1.7, commit `de46a96`; the same finding as
registry-token-service F18, fixed the same way)
**Where (0.1.6):** `Dockerfile` (`scratch` plus `/auth-proxy` and `/etc/ssl/certs/ca-certificates.crt`).
**Where (0.1.7):** `Dockerfile` (notices stage and `COPY`), `scripts/third-party-licenses.sh`,
`scripts/check-image-notices.sh`, `.github/workflows/go-ci.yml` (job `image`), `.dockerignore`.
**Issue (before 0.1.7):** the IMG lens *SBOM & notices* row asks that code redistributed in the image
ships its licence texts. The binary contains the Go standard library (BSD-3-Clause) and the image
carries the Mozilla CA bundle copied from the builder (MPL-2.0); the project's own licence is 0BSD (label
and `LICENSE`), and no notice for any of them was in the image. `.dockerignore` even excluded `LICENSE`.
**Remediation / evidence:** the builder stage runs `scripts/third-party-licenses.sh`, which writes
`THIRD_PARTY_LICENSES` (the Go standard library licence of the building toolchain, the Debian
`ca-certificates` copyright file, which carries the MPL-2.0 text for the Mozilla bundle, and the licence of
any third-party module in the build graph, none today) and fails the build if a module has no licence
file, the Go licence or the MPL text is missing, or the file is implausibly short. The runtime stage
copies it and the repository `LICENSE` to `/usr/share/doc/registry-auth-proxy/`. `.dockerignore` no
longer excludes `LICENSE` and now matches `.git` as a file or directory and excludes `docs/`. The new CI
job `image` runs `scripts/check-image-notices.sh` (builds the image, copies the files out of a created
container, and checks that both files are non-empty, that the standard library, the CA bundle, BSD and
MPL-2.0 text are present, every module in the graph is named, and the image `LICENSE` equals the
repository's); the release workflow's `verify` job runs the same `go-ci.yml`, so the gate covers a tag.
Checked locally with rootless podman: `image notices OK`.

---

## Section A — Invariant verification matrix

| # | Invariant | Enforced at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | Inbound `Authorization` stripped, replaced (never appended) by the proxy's own token | `handler.go:343, 352` | `TestForward_RequestFieldPolicy`, `TestServeHTTP_HappyPath` | HOLDS |
| I2 | Fail closed on a token-fetch error → 502, never a naked 401 | `handler.go:259-271` | `TestServeHTTP_TokenFailureIsBadGateway` | HOLDS |
| I3 | 401→403 remap after a token is attached | `handler.go:309-319` | `TestServeHTTP_RemapUnauthorized`, `TestServeHTTP_RefusedTokenIsDropped` | HOLDS |
| I4 | Only pull/catalog scopes predicted **and requested** (read-only) | `scope.go:8-36`; `challenge.go:455-473`; `handler.go:248-255` | `TestPredictScope`, `TestReadOnlyScope`, `TestServeHTTP_RefusesNonReadChallenge` | HOLDS (F8) |
| I5 | Hop-by-hop and `Connection`-named fields stripped both directions | `handler.go:55-64, 341-349, 363-389` | `TestIsHopByHop`, `TestForward_RequestFieldPolicy`, `TestForward_ResponseFieldPolicy` | HOLDS (F14) |
| I6 | No body tampering; responses streamed | `handler.go:373-374` | happy path | HOLDS |
| I7 | Only `GET`/`HEAD` forwarded; no request body read or forwarded | `handler.go:176-180, 334` | `TestServeHTTP_OnlyGetAndHead`, `TestServeHTTP_HeadIsForwarded` | HOLDS (F8; the 32 MiB cap was removed with the buffer) |
| I8 | Client secret file-only (read at startup and again after a token-service `401`), never env, never logged | `config.go` (`ReadSecret`); `fetcher.go` (`refreshSecret`) | config tests; `TestFetchRereadsRotatedSecret`, `TestFetchRotationFailsClosed` (no secret value or path in the log); grep of every `slog` call | HOLDS (F10) |
| I9 | Non-root scratch UID 65534 | `Dockerfile:33, 57`; pod `securityContext` | Dockerfile; manifest | HOLDS |
| I10 | Only canonical registry read routes are forwarded; the path is never rewritten (traversal, empty and `.` segments, trailing slash → `400`; any other route → `404`) | `scope.go` (`Route`, `routeRules`); `ServeHTTP` | `TestRoute`, `TestPredictScope`, `TestForward_OnlyRegistryReadRoutes`, `TestWiredRoutePolicy` | HOLDS (F2, F18) |
| I11 | Upstream URL validated at config time | `config.go` `validateHTTPURL` | `config_test.go` | HOLDS (F1) |
| I12 | Cache bounded (512); expired entries evicted | `cache.go:177, 236-270` | `TestCacheIsBounded`, `TestCacheEvictionKeepsEmptyScope` | HOLDS (F3) |
| I13 | Refresh margin subtracted before store; spec expiry | `cache.go:236-249`; `fetcher.go:403-416` | `TestCacheMarginExpiry`, `TestCacheSkipsTokenAlreadyInsideMargin`, `TestFetchExpiry` | HOLDS |
| I14 | Upstream redirects not followed | `handler.go:163-165` | `TestServeHTTP_DoesNotFollowUpstreamRedirect` | HOLDS (F4; probe leg tested, credentialed leg shares the client) |
| I15 | Cache key = the scope the token was issued for (AUTH lens) | `handler.go:281-294` | `TestServeHTTP_TokenCachedOnlyUnderIssuedScope` | HOLDS (F7) |
| I16 | Proxy requests only pull/catalog scopes and forwards only read methods (SECURITY.md 4; CLAUDE.md) | I4 + I7 | the tests of I4 and I7 | HOLDS (F8) |
| I17 | Cookies are not sent upstream; `Set-Cookie` and `Access-Control-*` are not passed to the UI | `handler.go:99-103, 343, 366` | `TestForward_RequestFieldPolicy`, `TestForward_ResponseFieldPolicy` | HOLDS (F14) |
| I18 | A request that already passed through the proxy is refused (`508`) before any upstream call | `handler.go:182-188` | `TestForward_LoopIsRefusedBeforeAnyUpstreamCall` | HOLDS (F14) |
| I19 | At most 64 forwards in flight; `503` with `Retry-After` beyond | `handler.go:203-211` | `TestForward_ConcurrencyIsBounded` | HOLDS (F15) |
| I20 | Upstream dial 5 s and response-header 30 s deadlines, no total deadline; request headers ≤ 32 KiB | `handler.go` (`limits`, `newHandler`); `main.go` (`newServer`) | `TestDefaultLimits`, `TestLimits_StalledUpstreamEndsInBadGatewayAndReleasesSlot`, `TestLimits_DialDeadlineEndsInBadGateway`, `TestLimits_SlowBodyStreamsPastTheHeaderDeadline`, `TestServerLimits`, `TestServerRefusesOversizeHeaders` | HOLDS (F20) |
| I21 | An upstream or token-service failure is logged by class, without the address or URL | `handler.go:223, 303, 405-419` (`errorKind`); the `token fetch error` log with `token.FailureClass`; `fetcher.go` (`FetchError`) | `TestForward_UpstreamFailureLogsNoHostname`, `TestForward_TokenFailureLogsClassWithoutEndpoint`, `TestFetchErrorsCarryNoEndpoint` | HOLDS (F16, F17) |
| I22 | Concurrent misses for one scope share one token request; a refused token is evicted | `flight.go`; `handler.go:281-294, 317` | `TestFlight*`, `TestServeHTTP_ConcurrentMissesShareOneTokenRequest`, `TestServeHTTP_RefusedTokenIsDropped` | HOLDS (F3, F7) |
| I23 | `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop` and `Cf-*` (incl. the Access assertion) are not forwarded upstream | `handler.go` (`isEdgeField`, `forwardingDropped`, `roundTrip`) | `TestForward_EdgeFieldsAreNotForwarded` | HOLDS (F18) |
| I24 | A rotated client secret takes effect without a restart: one re-read and one retry after a token-service `401`; an unchanged or unreadable file fails closed | `fetcher.go` (`Fetch`, `refreshSecret`); `main.go` (`newMux`) | `TestFetchRereadsRotatedSecret`, `TestFetchRotationFailsClosed`, `TestFetchOtherFailuresDoNotReload`, `TestFetchConcurrentRotation`, `TestSecretRotationWithoutRestart` | HOLDS (F10) |
| I25 | A redirect from the registry is returned, never followed, on the credentialed leg too | `handler.go` (`CheckRedirect`) | `TestForward_NoCredentialReachesAForeignRedirectTarget` | HOLDS (F4) |

### Lens category coverage

| Lens | Category | Status |
| --- | --- | --- |
| GO | HTTP server hygiene | HOLDS — `ReadHeaderTimeout` 10 s, `IdleTimeout` 120 s, `MaxHeaderBytes` 32 KiB (`431` beyond, tested), no `WriteTimeout` (blobs stream, intentional); methods allow-listed (`405` with `Allow: GET, HEAD`); no body is read; a handler panic is recovered per connection by net/http |
| GO | Outbound calls | HOLDS — token fetcher `Timeout` 10 s and 64 KiB body cap; upstream client dial 5 s and response-header 30 s with streamed bodies (all three tested, F20); no `InsecureSkipVerify`/`TLSClientConfig` anywhere; redirects: PROXY row |
| GO | Input & path handling | HOLDS — route allowlist with the registry's name, tag and digest grammars; the path is never rewritten (F18) |
| GO | AuthN / AuthZ | N/A inbound (by design); no secret comparison exists; token rules: AUTH rows |
| GO | Secrets | HOLDS — I8 |
| GO | Client identity | N/A — the proxy keys nothing on an address; the per-visitor limit is nginx's (20 r/s, F3) |
| GO | Concurrency | HOLDS — `go test -race` green; the cache and `Flight` are mutex-guarded; no goroutine is started per request |
| GO | Graceful shutdown | HOLDS (code-only; `main` needs a signal) — SIGTERM and SIGINT call `Server.Shutdown` with 10 s (`main.go:78-87`) |
| GO | Health & version | HOLDS — `/healthz` returns `{"status":"ok"}`; no `/version` |
| GO | Error handling | HOLDS — fixed text bodies (`upstream unavailable`, `auth service error`, `scope not permitted`, `busy`, `loop detected`, `invalid path`, `not found`); the token-fetch log carries a class, not the URL (F17) |
| GO | CI (B.GO-1) | HOLDS — `go vet`, golangci-lint v2.13.0, race tests, govulncheck v1.8.0 (pinned), Trivy filesystem scan; no `go.sum` (stdlib only); `-trimpath`, `CGO_ENABLED=0`, version injected with `-X main.version` |
| IMG | Base images | HOLDS — builder digest-pinned and checked against the `go.mod` toolchain; runtime `scratch` |
| IMG | Build context | HOLDS — `.dockerignore` excludes `.git`, `docs/`, `.env*`, `client-secret`, `*.key`, `*.pem` |
| IMG | Reproducible build stage | HOLDS — `go.mod` only, no dependency to resolve; only the binary and the CA bundle reach the runtime stage |
| IMG | No secrets in layers | HOLDS — build args are OCI label strings |
| IMG | Runtime user & filesystem | HOLDS — `USER 65534:65534`; pod: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities dropped, `RuntimeDefault` seccomp, `automountServiceAccountToken: false` |
| IMG | Runtime configuration | HOLDS — the image sets only `PORT`; the manifest sets `UPSTREAM_URL`, `TOKEN_ENDPOINT`, `CLIENT_ID`, `CLIENT_SECRET_FILE`, `TOKEN_REFRESH_MARGIN`, `LOG_LEVEL` |
| IMG | Health & resources | HOLDS — readiness and liveness on `/healthz`; requests 20m/32Mi, limits 200m/128Mi |
| IMG | SBOM & notices | HOLDS — SPDX attestation generated from the pushed image; licence notices (Go standard library, CA bundle copyright, `LICENSE`) in `/usr/share/doc/registry-auth-proxy/`, checked in CI (F22, 0.1.7) |
| IMG | Scan before sign | HOLDS — Trivy on the pushed digest before `cosign sign` (F9) |
| IMG | Verification command | HOLDS — the README example and the job summary print the same workflow-pinned regexp (F12, 0.1.7) |
| IMG | Deployment pinning | HOLDS — digest from `config/images.yaml` stamped into the `registry` overlay and cosign-verified 2026-10-09; the base manifest's stale tag `0.1.1` is overridden (F12, a platform item) |
| AUTH | Issuer keys & signing | N/A — the proxy issues nothing |
| AUTH | Token claims & lifetime | N/A (issued by the token service); the proxy honours `expires_in`/`issued_at` conservatively (I13) |
| AUTH | Token verification | N/A — the registry verifies; the proxy treats the token as opaque |
| AUTH | Credential validation is delegated | HOLDS — the secret is verified by Hydra through the token service; no local store or allowlist |
| AUTH | Fail closed | HOLDS — token service unreachable, slow, non-200, malformed or empty → `502` (`TestServeHTTP_TokenFailureIsBadGateway`, `TestFetchFailsClosed`); fetch timeout 10 s |
| AUTH | Authorization model | HOLDS by layers — the proxy requests read scopes only (F8), the token service grants requested ∩ Keto, Keto holds `pullers`/`listers` only; F21 for the client registration |
| AUTH | OAuth client configuration | MITIGATED — confidential client, `client_credentials`, `client_secret_basic`, no redirect URIs; scope registration broader than use (F21) |
| AUTH | Browser authentication (BFF) | N/A — no browser token exists; joxit never sees a credential and the human session is Cloudflare Access's |
| AUTH | Client-side token caching | HOLDS — key = the issued scope (F7), margin 30 s, bounded at 512 and evicting (F3), process memory only, never logged |
| AUTH | Inbound credential handling | HOLDS — client `Authorization` stripped, the Bearer goes only to `UPSTREAM_URL`, redirects not followed, a credentialed `401` is remapped to `403` so no login dialog appears (I1, I3, I14) |
| AUTH | User-supplied third-party tokens | N/A |
| AUTH | Identity-provider configuration | N/A in this repository (PLATFORM lens) |
| AUTH | Error & enumeration hygiene | HOLDS — fixed bodies; `403` for a refused scope or a refused token, `502` for a token-service failure; no token or IdP body is logged |
| AUTH | Abuse limits | at the edge — Cloudflare Access and nginx per-visitor limit on the UI; the proxy adds the 64-forward bound (F15); the token path has no limit of its own (F3 residual) |
| AUTH | Transport to identity services | MITIGATED — plain in-cluster HTTP on one node, NetworkPolicy, no mutual authentication (F5) |
| AUTH | Signed-challenge protocols | N/A |
| AUTH | Audit trail | HOLDS by delegation — the token service logs each issuance with requested and granted scope; the proxy logs a refused challenge scope (warn) and a remapped `401` (info), never a credential; per-request access lines are debug-level only |
| PROXY | Route & method policy | HOLDS — `GET`/`HEAD` only, an allowlist of the registry read routes, canonical paths only and never rewritten, upstream URL from configuration (F18) |
| PROXY | Request header policy | HOLDS — `Authorization`, cookies, hop-by-hop and `Connection`-named fields, `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop` and `Cf-*` removed, `Host` set, `Via` added (F14, F18); the remaining fields are the ones the registry API defines (F18) |
| PROXY | Response header policy | HOLDS — hop-by-hop, `Connection`-named, `Set-Cookie` and `Access-Control-*` dropped (F14) |
| PROXY | Redirects | HOLDS — `ErrUseLastResponse` on the one client (F4) |
| PROXY | Limits & timing | HOLDS (F15, tested in F20) — 10 s header read, 120 s idle, 32 KiB headers, no body, 64 in flight, upstream dial 5 s and response-header 30 s; no total deadline by design; no cap on idle connections |
| PROXY | Error mapping | HOLDS (F16, F17): fixed `502`/`503`/`508`/`404`/`400` bodies, class-only logs for forwards and for the token fetch |
| PROXY | Admission state | N/A — no claim/forward/commit sequence; the token cache is a cache, not a ledger (single replica, in-process) |
| PROXY | Origin lock | N/A for the upstream (the registry is its own gate); the proxy's own door is F19 |
| PROXY | Loop & self-reference | HOLDS — `Via` check, `508` (F14) |
| PROXY | Configuration | HOLDS — invalid or missing values fail startup (F1); the defaults are the strict ones |
| PROXY | Sibling parity | N/A — one implementation |

---

## Section B — Supply-chain, publish-authority & capability matrix

### B.1 Dependency & CVE risk

| Dependency | Pinned version | Liveness dependency? | CVE / audit status | Notes |
| --- | --- | --- | --- | --- |
| Go toolchain (stdlib only, no modules) | `go 1.26.6`, `toolchain go1.26.9`; builder `golang:1.26.9-bookworm@sha256:d9c68c2c…641453c` | build | govulncheck v1.8.0 in CI; 1.26.7's eleven advisories (GO-2026-6607…6617) closed in 0.1.5 | the Dockerfile fails if the builder differs from `go.mod` (F9) |
| registry-token-service → Hydra, Keto | runtime | **yes** — unreachable or non-200 ⇒ 502 | own audit | **fails closed**; amplification bounded (F3) |
| Distribution registry (upstream) | runtime | **yes** — probe error ⇒ 502 | upstream | redirects not followed; deadlines (F15) |
| Trivy / govulncheck / golangci-lint | v0.74.0 / v1.8.0 / v2.13.0 (pinned in `go-ci.yml`) | CI | | Trivy action pinned by SHA |
| joxit/docker-registry-ui (the only caller) | 2.6.0 (`registry-ui` manifest) | runtime caller | upstream | `DELETE_IMAGES: "true"` makes its delete action fail with `405` (F8, OQ6) |

### B.2 Publish authority, capabilities & secret custody

| Authority / secret | Where held | Custody | Gates | Rotation |
| --- | --- | --- | --- | --- |
| Image publish | CI `docker-publish.yml` | registry tokens in GitHub secrets; keyless cosign + signed SPDX SBOM + SLSA `mode=max` + GitHub build-provenance attestation | `verify` = the full `go-ci.yml` (lint, race tests, govulncheck, Trivy), then Trivy on the pushed image before signing (F9) | quay/Docker Hub token scope, holder and rotation date: maintainer item, `OPERATOR_TASKS.md` "Image registry credentials" (before mainnet); the self-hosted mirror job is best-effort (`continue-on-error`, unsigned, fails without credentials) |
| `CLIENT_SECRET_FILE` | mounted k8s Secret `registry-auth-proxy-secret` (0440; SOPS at rest) | read at startup and again after a token-service `401`; unexported; never env or logs | Basic auth to the token service | `SECURITY.md` procedure (both Secrets, then the `hydra-client-setup` Job; the proxy re-reads, restart as fallback); no cadence or rehearsal record (F10) |

CI and release integrity (base §B.2): actions pinned by full SHA; explicit `permissions:` (`contents:
read`; `id-token` and `attestations` only on `publish-public`); tag-gated release (`v*`); release gate
equals CI; Dependabot weekly and grouped for Docker and GitHub Actions; no `set -x` or secret echo; no
real-funds job; no test-only build mode.

### B.IMG-1 Publish & attestation

Each pushed image (quay.io and Docker Hub, multi-arch, signed at the index digest) carries a keyless
cosign signature, an SPDX SBOM attached as a signed attestation (`cosign attest --type spdxjson`) and a
GitHub build-provenance attestation, plus BuildKit `provenance: mode=max` (`sbom: false` because the
BuildKit scanner pull is unreliable); none of these steps uses `continue-on-error`. The self-hosted
registry push (`publish-private`) is a best-effort, unsigned mirror. From 0.1.7 the image also carries
its licence notices (F22) and the `verify` job includes the `image` check. The 0.1.6 digest
`sha256:d98c347c…1581` was the same on quay.io, Docker Hub and in `config/images.yaml`, and was
cosign-verified on 2026-10-09; the 0.1.7 digest `sha256:15038201…f097e` is the deployed one and was cosign-verified on 2026-10-18.

### B.AUTH-1 Key & credential inventory

| Key / credential | Type / algorithm | Where held | Who can read it | Rotation cadence · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| `registry-browser` client secret | OAuth 2 client secret (client credentials; HTTP Basic to the token service) | k8s Secret `registry-auth-proxy-secret` mounted at `CLIENT_SECRET_FILE`; the same value in `hydra-client-secrets` (`browser-client-secret`); SOPS-encrypted sources in the cluster directory | the pod; cluster admins; the age-key holder | no cadence fixed · set at bootstrap, no rotation date recorded (maintainer, F10) | `SECURITY.md` "Client-secret rotation and compromise" (the compromise steps are the rotation steps with the new value at once, then a log review); `docs/auth/OPERATIONS.md` for the Hydra side (F10) |
| Cached registry Bearer tokens | Distribution JWT (opaque to the proxy) | process memory | the process | TTL from the token service; margin 30 s; max 512 entries | expire; a refused token is evicted; restart clears |
| quay.io / Docker Hub push tokens | registry robot/access tokens | GitHub repository secrets | maintainers | not recorded — maintainer item, `OPERATOR_TASKS.md` "Image registry credentials" (before mainnet) | revoke at the registry |

### B.AUTH-2 Client & authorization inventory

| OAuth client / relation | Type, grant types, auth method | Redirect URIs | Scopes / relations granted | Owner | Last reviewed |
| --- | --- | --- | --- | --- | --- |
| `registry-browser` | confidential; `client_credentials`; `client_secret_basic` (through registry-token-service) | n/a | Hydra registration: `registry:push registry:pull registry:catalog` (broader than use, F21, platform); Keto: `pullers` on `meddleware-org`, `listers` on `catalog`; the proxy requests only pull and catalog (F8) | platform (`hydra-client-setup`, `keto-relations-setup` Jobs) | 2026-10-09 (this audit; tuples read-only) |
| Keto `Registry` / `meddleware-org` / `pullers` | relation | n/a | `registry-browser` (and `registry-ci-push`, `registry-node-pull`) | platform; written only by the setup Job inside `auth` | see the registry-token-service audit |
| Keto `Registry` / `catalog` / `listers` | relation | n/a | `registry-browser` | platform | see the registry-token-service audit |

### B.AUTH-3 Protocol conformance

| Protocol | Version / source | Deviations | Pinning test |
| --- | --- | --- | --- |
| Distribution token authentication (`WWW-Authenticate: Bearer realm,service,scope`; `GET /token`; `expires_in`/`issued_at`) | Distribution token spec; RFC 9110 §11.2 auth-param grammar | quote-aware parse (F11); a multi-scope challenge is sent to the token service as one space-separated `scope` value (F11); `realm` is ignored — the fixed `TOKEN_ENDPOINT` is used; absent `expires_in` ⇒ 60 s; `issued_at` capped at the local clock | `TestParseBearerChallenge`, `TestReadOnlyScope`, `TestFetchSendsCredentialsAndScope`, `TestFetchFailsClosed`, `TestFetchExpiry`, `TestServeHTTP_TokenCachedOnlyUnderIssuedScope` |

### B.PX-1 Route & header policy

| Route / path | Methods | Auth | Forwarded request fields | Stripped (both ways) | Response fields kept | Cache |
| --- | --- | --- | --- | --- | --- | --- |
| `/healthz` | any (local handler) | none | n/a | n/a | fixed JSON body | none |
| `/v2/_catalog`, `/v2/<name>/tags/list`, `/v2/<name>/manifests/<ref>`, `/v2/<name>/blobs/<digest>`, `/v2/<name>/referrers/<digest>`, `/v2/` and `/v2` (names, tags and digests in the registry's grammars) | `GET`, `HEAD` (others `405`) | none inbound; the proxy's Bearer outbound | every field except those stripped, plus `Via` and the proxy's `Authorization`; `Host` = the upstream's; query forwarded verbatim; the path exactly as checked | request: `Authorization`, `Cookie`/`Cookie2`, `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, every field named in `Connection`, and `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop`, `Cf-*`; response: the same hop-by-hop set, `Connection`-named fields, `Set-Cookie`/`Set-Cookie2`, `Access-Control-*` | everything else (Distribution headers, `Content-Type`, `Docker-Content-Digest`, `Location`); `401` after a token → `403` | tokens only, in process, keyed by issued scope; no response caching |
| any other canonical path (F18) | any | none | not forwarded: `404` here, before the token service or the registry | n/a | n/a | none |
| a path with an empty, `.` or `..` segment or a trailing slash (F18) | any | none | not forwarded: `400 invalid path` (the mux answers `307` to the cleaned path for the raw forms first) | n/a | n/a | none |

### B.PX-2 Limits

| Limit | Value | Where enforced | Test |
| --- | --- | --- | --- |
| header-read timeout · body-read deadline · idle timeout | 10 s · n/a (no body is read) · 120 s | `main.go` (`newServer`) | `TestServerLimits` (the values; a slow-header test would need the full 10 s) |
| request body cap (declared / streamed) | none needed: no body is read or forwarded | `handler.go:334` (nil body) | `TestServeHTTP_OnlyGetAndHead` |
| request header size | 32 KiB (`431` beyond) | `main.go` (`newServer`) | `TestServerRefusesOversizeHeaders` |
| concurrent connections / in-flight forwards | 64 forwards (`503` + `Retry-After: 1`); connections not capped | `handler.go` (`DefaultMaxInFlight`, the semaphore in `ServeHTTP`) | `TestForward_ConcurrencyIsBounded`, `TestLimits_InFlightBoundFollowsTheLimit`, `TestDefaultLimits` |
| upstream connect · response · total deadline | 5 s · 30 s (headers) · none (blobs stream) | `handler.go` (`limits`, `newHandler`) | `TestDefaultLimits`, `TestLimits_DialDeadlineEndsInBadGateway`, `TestLimits_StalledUpstreamEndsInBadGatewayAndReleasesSlot`, `TestLimits_SlowBodyStreamsPastTheHeaderDeadline` |
| token fetch | 10 s, 64 KiB; at most one retry, after a `401` and a changed secret file | `fetcher.go` (`NewFetcher`, `Fetch`, `attempt`) | `TestFetchFailsClosed`, `TestFetchRotationFailsClosed` |
| token cache | 512 entries; margin 30 s | `cache.go:177` | `TestCacheIsBounded` |
| admission-state lifetime | in-flight slot: held for the forward, released on return, also after a timeout | `handler.go` (`defer` in `ServeHTTP`) | `TestLimits_StalledUpstreamEndsInBadGatewayAndReleasesSlot` |

---

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade — A (proxy 96.9%, token 95.5%, config 86.7%, cmd/server 38.6%; race-clean; 59 test functions, 142 runs; measured 2026-10-18 on the 0.1.7 tree)

| Dimension | Assessment |
| --- | --- |
| Happy path | A — scope prediction, challenge parse (quoted, escaped, lowercase scheme), hop-by-hop, remap, cache hit and margin, fetcher success, `HEAD` |
| Error path | A — fail-closed 502, fetcher non-200/empty/oversize/transport failures with their classes, refused challenge scopes, refused token eviction, redirect (both legs), 405s, 404/400 for refused routes, 508, 503 on the bound, stalled upstream and dial timeouts, class-only failure logs for forwards and token fetches |
| Boundary / edge | A− — route grammar (names to 255 characters, tags, digests, smuggled bytes), traversal and non-canonical paths, cache bound and eviction, single flight, `Connection`-named fields, stalled upstream, dial deadline, slow body, header block over 32 KiB, a recording upstream asserting no credential reaches a foreign `Location` on the credentialed leg; **missing:** a slow-header (`ReadHeaderTimeout`) test, which needs the full 10 s |
| Security-relevant | A — secret loading and rotation (unit, concurrent and end to end), inbound strip (replaced not appended), cookies, edge fields, CORS, scope-exact cache, read-only enforcement, server settings; graceful shutdown (in `main`, needs a signal) is untested |

### C.2 Hermetic vs. live paths

| Path | Hermetic unit test? | Deferred to | Tracking |
| --- | --- | --- | --- |
| Scope prediction, hop-by-hop, remap, cache, flight | yes | — | proxy and token tests |
| Request/response field policy, route allowlist, edge fields, loop, in-flight bound, failure logs | yes (`forwarding_test.go`, `limits_test.go`) | — | F14–F18 |
| Token fetch (Basic auth, cap, non-200, expiry) | yes | — | fetcher tests |
| Config secret loading and URL validation; secret re-read after a refusal | yes | — | config and fetcher tests, `TestSecretRotationWithoutRestart` |
| Server settings, header cap, upstream deadlines, in-flight bound | yes (loopback listeners and local servers; short deadlines) | — | F20 |
| Graceful shutdown; limits sized and measured under load | no | pre-mainnet limits measurement (maintainer) | F20 remainder |
| Image carries the licence notices | CI job `image` (container build; rootless podman locally) | — | F22 |
| Live token service + registry end to end | no hermetic test; the platform-probe catalogue check exercises the real chain | staging cluster | `platform-probe` status check |
| Negative check that a pod outside the allowed set cannot reach `:8181` | no | pre-mainnet, platform | F19 |

---

## Section D — Deployment-readiness gates

### pre-localnet (dev / integration)

- [x] builds; tests + race pass; runs from `.env.example`; `SECURITY.md` present
- [x] fail-closed, strip, remap, redirect behaviour tested — F13 (the body-cap test was removed with the buffer, F8)
- [x] B.PX-1 and B.PX-2 complete; hop-by-hop, redirect (both legs), method, `..` and in-flight-limit tests green — F14, F15; the deadline and header-cap tests landed in 0.1.7 (F20)
- [x] configuration fails startup on invalid values — F1
- [x] algorithm and secret rules: secret from a mounted file, nothing secret in source or logs; fail-closed tests green — F13

### pre-testnet (staging)

- [x] F1, F2, F4 (redirect) landed and tested
- [x] cache keyed by issued scope (F7, 0.1.4)
- [x] method allowlist + pull-only scope requests (F8, 0.1.4)
- [x] B.AUTH-1 key & credential inventory and B.AUTH-2 client & relation inventory complete (this audit)
- [x] proxies strip inbound credentials; the proxy requests no scope beyond pull/catalog (F8, F14)
- [x] non-root runtime; pod security context complete; probes and limits set; deployed by digest from `config/images.yaml` (cosign-verified 2026-10-09 for 0.1.6 and 2026-10-18 for 0.1.7)
- [x] client identity: nothing keyed on an address; secrets never logged (I8)
- [ ] origin lock verified positively and negatively — the proxy's door is bounded by NetworkPolicy and Access but the negative check does not exist yet (F19); maintainer/platform, pre-mainnet

### pre-mainnet (production)

- [x] bounded cache + single-flight (F3, 0.1.4)
- [x] release gate = CI gates; toolchain aligned; image scan before signing (F9, 0.1.4–0.1.5)
- [x] SBOM, signing and provenance in place
- [x] SIGTERM drains in-flight requests; health endpoint reveals nothing (`main.go:78-87`, `/healthz`)
- [x] release build flags stated (`-trimpath`, `CGO_ENABLED=0`, version injection); image per the IMG lens
- [x] F5's platform transport cited in SECURITY.md; rotation procedure documented (F5, F10, F12) — `SECURITY.md` "Transport to the token service and the registry" (decision D18) and "Client-secret rotation and compromise", 0.1.7, commit `de46a96`; the rotation rehearsal is the maintainer line below
- [x] README `cosign verify` pinned to the publish workflow; licence notices shipped in the image; `docs/` committed (F12, F22) — README regexp pinned to `docker-publish.yml@refs/tags/v*`; notices in `/usr/share/doc/registry-auth-proxy/` with the `image` CI job (`scripts/check-image-notices.sh`, `image notices OK` under rootless podman); `docs/` committed with the 0.1.7 commit (commit `de46a96`)
- [ ] key rotation with overlap rehearsed; compromise procedure documented for the `registry-browser` secret (F10) — the compromise procedure is documented (`SECURITY.md`, 0.1.7) and rotation is restart-free (`TestSecretRotationWithoutRestart`); the rehearsal against the live cluster, a cadence and a last-rotation record are maintainer tasks
- [ ] the negative origin check runs on a schedule (F19) — platform, maintainer
- [x] deadline and header-cap tests (F20) — `limits_test.go`, `dial_linux_test.go`, `cmd/server/main_test.go`; 0.1.7, commit `de46a96`
- [ ] limits sized for the plan tier and measured under load (F20 remainder) — maintainer
- [ ] registry credential inventory (scope, holder, rotation date) — maintainer, `OPERATOR_TASKS.md` "Image registry credentials", deferred to launch
- [ ] external review of the forwarding path — awaiting external review

---

## Cross-project themes

- **The token service is the authority; the proxy no longer widens requests.** Since 0.1.4 (F8) a Keto
  mis-grant does not flow through the UI as write or delete: the proxy asks only for pull and catalog
  and forwards only `GET`/`HEAD`. The registry-token-service audit's org-level fallback grant (its F9)
  and the broad Hydra client registration (F21) stay relevant as layers behind it.
- **Scope-exact credential caches.** The AUTH-lens cache rule (F7) applies to any client that caches
  tokens per scope; this proxy now holds it, with a bound and single flight (F3). No sibling service
  caches gateway or registry tokens.
- **Release gates and toolchain drift** are shared with static-server (F2 there) and the other Go
  services: the reusable Go CI workflow, Trivy on the pushed image before signing, and a builder pinned
  to the `go.mod` toolchain are in place here (F9).
- **Supply chain & release integrity** — stdlib only, no lockfile needed; actions pinned by SHA; builder
  pinned by digest and checked against the toolchain; signed image with SBOM and provenance; govulncheck
  clean in CI; Dependabot weekly. The registry credential inventory is a maintainer item
  (`OPERATOR_TASKS.md` "Image registry credentials"), deferred to launch.
- **Wire-format coupling & conformance vectors** — the Distribution token spec is the contract
  (B.AUTH-3). This repository pins its consumer side with fake token-service and registry servers; the
  issuer side is pinned in registry-token-service; there is no shared golden vector between them, and
  the platform-probe catalogue check is the live drift detector.
- **On-chain-truth boundary** and **chain-access layering** — N/A (no chain involvement).
- **Deployment readiness** — Section D, kept current.
- **Pre-v0.2 policy:** F18–F22 changed behaviour (route allowlist, edge fields, notices) without shims in
  0.1.7 (released and deployed 2026-10-18). Consumers: joxit's nginx forwards only `/v2`, which is what the allowlist
  admits; nothing else calls the proxy except `platform-probe` (`/v2/_catalog`).

## Normative requirements (MUST)

1. The proxy MUST cache a token only under the scope it was issued for — holds (I15, F7).
2. The proxy MUST forward only read methods and request only pull and catalog scopes, independent of
   the identity's grants — holds (I4, I7, I16, F8).
3. The token cache MUST be bounded, with eviction independent of re-reads — holds (I12, F3).
4. Fail closed on token-service errors — holds (I2).
5. Strip inbound credentials; inject only toward the configured upstream; never follow redirects
   with credentials — holds (I1, I14).
6. The proxy MUST remove hop-by-hop and `Connection`-named fields and cookies, and MUST NOT pass
   upstream CORS or `Set-Cookie` to the UI — holds (I5, I17, F14).
7. The proxy MUST refuse a looped request, bound the forwards in flight and every upstream wait, and
   cap request headers — holds in code (I18–I20, F15); untested for the deadlines and header cap (F20).
8. The proxy MUST forward only listed routes with a validated path — holds (I10, F18).
9. Failures MUST map to fixed `502`/`503`/`508`/`404`/`400` bodies with no upstream detail in responses
   or default logs — holds for forwards and for the token fetch (I21, F16, F17).
10. The proxy MUST NOT forward forwarding headers or edge-added fields (`X-Forwarded-*`, `Forwarded`,
    `X-Real-Ip`, `Cf-*`) to the registry — holds (I23, F18).
11. A rotated client secret MUST take effect without a restart or fail closed — holds (I24, F10).

**AUTH lens baseline:**

| ID | Holds? | Evidence |
| --- | --- | --- |
| AUTH-M1 | N/A (the proxy does not verify tokens; the registry does) | — |
| AUTH-M2 | yes for custody (mounted file, never env or logs); rotation and compromise steps in `SECURITY.md`, restart-free; no cadence or rehearsal record (maintainer) | F10 |
| AUTH-M3 | N/A (issued by the token service) | — |
| AUTH-M4 | yes (delegated; fail closed) | I2 |
| AUTH-M5 | yes — the proxy requests read scopes only, the token service grants requested ∩ Keto, Keto holds pull and catalog | F8, F21 |
| AUTH-M6 | N/A here (`client_credentials` only, no redirect URIs; registration in Hydra, scope broader than use) | F21 |
| AUTH-M7 | N/A (no browser tokens; joxit never sees one) | — |
| AUTH-M8 | yes | I1, I14 |
| AUTH-M9 | N/A | — |
| AUTH-M10 | yes for logging and error bodies (no credential logged, fixed responses); rate limiting is at the edge, with the 64-forward bound here | F3, F15 |
| AUTH-M11 | N/A | — |

**GO lens baseline:**

| ID | Holds? | Evidence |
| --- | --- | --- |
| GO-M1 | yes (`ReadHeaderTimeout` 10 s, `IdleTimeout` 120 s, `MaxHeaderBytes` 32 KiB with a `431` test, no body is read; `WriteTimeout` intentionally absent for streaming) | F11, F15, F20 |
| GO-M2 | yes (fetch 10 s + 64 KiB; upstream dial 5 s and response-header 30 s, both tested; streamed bodies) | F13, F15, F20 |
| GO-M3 | N/A (no filesystem serving); path hygiene: route allowlist, F18 | — |
| GO-M4 | N/A (no token verification) | — |
| GO-M5 | yes | I8 |
| GO-M6 | N/A (no client address is used; the per-visitor limit is nginx's) | F3 |
| GO-M7 | yes (lint, vet, race tests, pinned govulncheck, Trivy — in CI and on the tag) | F9 |
| GO-M8 | yes (10-second graceful shutdown) | — |

**IMG lens baseline:** IMG-M1 yes (builder digest checked against the toolchain, `scratch`); IMG-M2 yes
(`.dockerignore` excludes secrets, env files and `.git`); IMG-M3 yes; IMG-M4 yes; IMG-M5 yes (pod
context in `k8s/base/registry/auth-proxy`); IMG-M6 yes (overlay digest from `config/images.yaml`; the
base tag `0.1.1` is stale, F12, a platform item); IMG-M7 yes (signature, SPDX SBOM attestation,
provenance); IMG-M8 yes from 0.1.7 (scan before sign, SBOM, licence notices F22, and the README `cosign
verify` pinned to the workflow, F12).

**PROXY lens baseline:**

| ID | Holds? | Evidence |
| --- | --- | --- |
| PX-M1 | yes — methods and a route allowlist enforced, canonical paths only, upstream URL from configuration | F18 |
| PX-M2 | yes — hop-by-hop and `Connection`-named fields removed both ways; `Via` set by the proxy; `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `Cf-*` dropped | F14, F18 |
| PX-M3 | yes — `Set-Cookie`, `Access-Control-*` and `Connection`-named fields dropped | F14 |
| PX-M4 | yes | F4 |
| PX-M5 | yes (header read, idle, header size, in-flight, dial, response-header; the deadlines, bound and header cap are tested; the 10 s header-read timeout is pinned only by value) | F15, F20 |
| PX-M6 | yes for forwards and for the token fetch | F16, F17 |
| PX-M7 | N/A (no admission state) | — |
| PX-M8 | N/A for the upstream (the registry is its own gate); the proxy's door is bounded by NetworkPolicy and Access, with no scheduled negative check | F19 |
| PX-M9 | yes (invalid configuration fails startup; strict defaults) | F1 |

## Implementation suggestions (SHOULD / MAY)

- **S1** *(done in 0.1.4)* `readOnlyScope` intersects challenge scopes with `{pull, catalog}` before any
  token request and returns `403` locally (F8).
- **S2** *(done in 0.1.4)* bounded cache with expiry-first eviction and `Flight` single flight (F3).
- **S3** MAY negatively cache "no access" outcomes per scope for a short TTL, to blunt the remaining
  unique-name amplification (F3).
- **S4** *(done in 0.1.7)* `CLIENT_SECRET_FILE` is re-read when the token service answers `401`; rotation is
  restart-free (F10).
- **S5** *(done in 0.1.7)* the token-fetch failure is logged by class (`token.FailureClass`), not by error
  text (F17).
- **S6** *(done in 0.1.7)* the `/v2` read routes are allow-listed with the registry's grammars, the path is
  never rewritten, empty and `.` segments are refused, and `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`,
  `True-Client-Ip`, `Cdn-Loop` and `Cf-*` are dropped. The remaining request fields stay a denylist on
  purpose (F18).
- **S7** *(done in 0.1.7)* the deadlines are fields of the handler's limits; stalled-upstream, dial,
  slow-body, in-flight-bound, `431` header-cap and credentialed-redirect tests exist (F20, F4).
- **S8** SHOULD narrow `:8181` in `networkpolicy.yaml` to the `registry-ui` pod (plus platform-probe) and
  add a scheduled negative probe (F19).
- **S9** SHOULD drop `registry:push` from the `registry-browser` client registration (F21).
- **S10** *(done in 0.1.7, except the base manifest tag in `k8s/`)* transport and rotation text in
  SECURITY.md, the README `cosign verify` pinned to the publish workflow, licence notices in
  `/usr/share/doc/registry-auth-proxy/`, the README build example corrected, `docs/` committed (F5, F10, F12,
  F22).
- **S11** SHOULD, in the platform repository: list `registry-auth-proxy-secret` in `SECRETS.md`, name it in
  `docs/auth/OPERATIONS.md` "Rotate a client secret" (update it before the Job; restart only as the
  fallback), bump or placeholder the tag `0.1.1` in `k8s/base/registry/auth-proxy/deployment.yaml` (F10,
  F12).

## Open questions (`OQ#`)

1. **OQ1** *(baseline OQ1)* NetworkPolicy enforcement and the transport path for proxy ↔ token service.
   Facts recorded: mutual authentication is not run (decision D18) and WireGuard covers only inter-node
   traffic (F5); a default-deny policy exists but admits whole namespaces to `:8181` (F19). SECURITY.md
   now names the manifest and the whole-namespace admission (0.1.7). Open: should `:8181` be narrowed to
   the `registry-ui` pod (plus `platform-probe`)? Recommendation: yes — a platform change, S8; no
   product decision is involved.
2. **OQ2** *(baseline OQ2)* Cache growth. (Decided 2026-10-08, 0.1.4: a fixed bound of 512 entries with
   expiry-first eviction and single flight; no per-client limit in the proxy — the per-visitor limit is
   nginx's — see F3.) Open remainder: is the unique-name amplification acceptable without a negative
   cache (S3)?
3. **OQ3** *(baseline OQ3)* `%2F` in repository names. (Decided 2026-10-18, 0.1.7: an encoded slash
   decodes to `/`, which is the legal hierarchy separator of a repository name; `Route` validates the
   decoded path against the name grammar and forwards exactly what it checked, so nothing else can ride
   in on an encoding — see F18.)
4. **OQ4** *(baseline OQ4)* Upstream redirect policy — **(Decided 2026-10-03: pass through; `CheckRedirect` →
   `ErrUseLastResponse`, tested — see F4.)**
5. **OQ5** *(baseline OQ5)* `go.mod` 1.26.6 vs the toolchain. (Decided 2026-10-09, 0.1.5: `go.mod`
   names `toolchain go1.26.9`, the builder is pinned to that patch and the Dockerfile fails on a
   mismatch — see F9.)
6. **OQ6** Is joxit deployed with image deletion enabled? The `registry-ui` manifest sets
   `DELETE_IMAGES: "true"`, so the UI offers deletion that the read-only proxy now refuses with `405`
   (F8). Should the toggle be turned off so the UI stops offering it, or is deletion to return through
   a separate, authenticated path?
7. **OQ7** Should the Hydra `registry-browser` client lose its `registry:push` scope now (S9, F21), or
   stay aligned with the other clients until the next client-setup change? Recommendation: drop it at the
   next client-setup change; three layers withhold push today, so there is no urgency. A platform
   manifest (`k8s/base/auth/jobs/hydra-client-setup.yaml`), not edited here.

## Risks

- **Read-only by layers:** the Keto tuples, the token service's intersection and the proxy's own
  filters agree today; the Hydra registration alone is broader than use (F21).
- **Availability:** the proxy is a single replica with a 64-forward bound; a registry or token-service
  outage ends in `502`/`503` by design, and a rotated secret breaks browsing only until the mounted
  file is refreshed (F10; no restart needed since 0.1.7, but the order of the rotation steps matters).
- **Plaintext hop:** proxy ↔ token-service traffic is in-cluster HTTP on one node with no mutual
  authentication; a hostile pod in an admitted namespace is bounded only by NetworkPolicy (F5, F19);
  `SECURITY.md` states this since 0.1.7.
- **Supply-chain mutability:** the image depends on the pinned builder, the Go toolchain and the GitHub
  and Sigstore services; registry push tokens are long-lived until the maintainer inventory is done.
- **Unmeasured limits:** the 64-forward bound, deadlines and header cap are tested for behaviour (F20) but
  not sized or measured under load for the plan tier (maintainer, pre-mainnet).
- **Route allowlist drift:** a UI or registry upgrade that adds a read route (joxit 2.6.0 uses the five
  shapes in F18) would see `404` until `routeRules` is extended; the platform-probe catalogue check and
  the registry-ui itself would show it at once.

---

## Re-verification log

- 2026-09-18 — first-pass baseline (adversarial pass). F1–F6 recorded. F1, F2, F3, F4 (redirect) and
  F5 (platform) marked RESOLVED during that pass; coverage proxy 78.9%, token 20.8%, config 0%.
- 2026-10-03 — second pass at `7436220` (release `v0.1.3` = `65b575a`; Docker Hub 0.1.3
  `sha256:e3f4578c…`).
  - **Lenses:** AUDIT_TEMPLATE.md (2026-10-02) + GO (2026-09-30) + AUTH + IMG (2026-09-30).
  - **Measured:** vet clean; race tests pass; coverage 85.4 / 93.3 / 82.1 / 0.
  - **Re-checked:**
    - F1, F2, F4 (redirect) and F6 hold;
    - F1's header/body contradiction settled;
    - I14's GAP marking corrected;
    - **F3 re-opened** (probe: 500 unique scopes → 502 entries);
    - F5 kept RESOLVED per the platform, not re-verified, with SECURITY.md's claimed documentation
      shown absent.
  - **New:** F7–F13 (F7 and F8 probe-verified with a fake registry + token service; deleted
    afterwards); OQ6. OQ4 decided.
  - **No findings resolved:** by maintainer instruction this pass only recorded findings; remediation
    was applied separately (0.1.4–0.1.6, below).
  - **Not run:** govulncheck (403), golangci-lint (not installed), quay.io, infrastructure manifests.
- 2026-10-09 — re-verified against `v0.1.6` (`7928960`; image `sha256:d98c347c…1581`, equal on quay.io,
  Docker Hub, `config/images.yaml` and the overlay; cosign-verified, 16/16). Lenses: base + GO + IMG +
  AUTH at 2026-10-08 (the template dates reconciled; no disposition depends on the lens changes), and **PROXY added** (front-matter table, forwarding matrix, Section A rows,
  B.PX-1 and B.PX-2, PX baseline). Measured: vet clean; race tests pass; coverage 93.8 / 94.1 / 86.8 / 0;
  37 test functions (79 runs).
  - **Resolved by 0.1.4–0.1.6:** F3 (bound, single flight — MITIGATED with the negative-cache residual
    accepted), F7 (scope-exact cache), F8 (read-only methods and scopes), F9 (release gate parity, image
    scan before signing, Go 1.26.9 and a checked builder), the parser half of F11; F2, F4, F1 re-checked
    and annotated with their tests.
  - **Corrected:** F5 from RESOLVED to MITIGATED — the SPIFFE mutual authentication it cited is not run
    (decision D18) and WireGuard covers only inter-node traffic on a one-node cluster; the cited
    manifest `mutual-auth-ciliumnetworkpolicy.yaml` does not exist.
  - **New, RESOLVED (0.1.6, `7928960`):** F14 (`Connection`-named fields, cookies, CORS and `Set-Cookie`,
    `Via` loop check with `508`), F15 (64 in flight with `503` + `Retry-After`, 5 s dial and 30 s
    response-header deadlines, 32 KiB headers), F16 (upstream failures logged by class without the
    address).
  - **New, open from the lens review:** F17 (token-fetch log carries the endpoint URL, ACCEPTED-RISK),
    F18 (denylist forwarding, no route allowlist, ACCEPTED-RISK), F19 (NetworkPolicy breadth and no
    scheduled negative check, MITIGATED), F20 (deadline and header-cap tests, DEFERRED), F21 (Hydra
    client registered with `registry:push`, MITIGATED), F22 (licence notices, DEFERRED). F10 and F12
    re-checked and left DEFERRED with the specific gaps recorded (the workspace rotation procedure
    exists but omits the pod restart and the separate Secret).
  - **Open questions:** OQ2 and OQ5 carry their decisions (0.1.4 and 0.1.5); OQ1, OQ3 and OQ6 stay
    open with new facts (OQ6: `DELETE_IMAGES: "true"` in the `registry-ui` manifest); OQ7 added.
  - **Totals (22):** 9 RESOLVED (F1, F2, F4, F7, F8, F9, F14, F15, F16), 5 MITIGATED (F3, F5, F11, F19,
    F21), 2 ACCEPTED-RISK (F17, F18), 4 DEFERRED (F10, F12, F20, F22), 2 Positive (F6, F13).
  - **Live checks (2026-10-10):** `registry-ui.meddleware.co.uk/v2/_catalog` answers `302` to the
    Cloudflare Access login without a session; the quay.io and Docker Hub `0.1.6` digests match.
  - **Not run:** golangci-lint and govulncheck locally (CI runs them), a request through the live proxy
    (the UI is Access-gated), `kubectl` against the cluster; the Cloudflare Access policy itself and the
    `Cf-Access-Jwt-Assertion` header on the proxy hop (F18) were not observed.
  - Registry credential inventory: a maintainer item (`OPERATOR_TASKS.md` "Image registry credentials"),
    deferred to launch.
- 2026-10-18 — fix wave, 0.1.7 (commit `de46a96`; released and deployed later the same day, see the next entry). Toolchain
  `GOTOOLCHAIN=go1.26.9`.
  - **Resolved:** F17 (token-fetch failures logged by class and status, `token.FetchError`), F18 (route
    allowlist with the registry's grammars, canonical never-rewritten paths, `X-Forwarded-*`/`Forwarded`/
    `X-Real-Ip`/`True-Client-Ip`/`Cdn-Loop`/`Cf-*` dropped), F20 (limits as handler fields; stalled
    upstream, dial, slow body, in-flight bound, `431` header cap, server settings and wiring tests;
    `cmd/server` 0% to 38.6%), F22 (licence notices and `LICENSE` in the image, `scripts/` and the `image` CI
    job).
  - **Also fixed:** the query-string half of F11 (the token request URL is built with `url.Parse` and a
    merged query; `TestFetchKeepsEndpointQuery`).
  - **Mitigated, with the remainder named:** F10 (procedure documented, rotation restart-free via a
    one-shot re-read on a token-service `401`; cadence, last-rotation record and live rehearsal are
    maintainer tasks; the proxy's Secret still has to be added to `SECRETS.md` and `docs/auth/OPERATIONS.md`),
    F12 (`SECURITY.md` transport and rotation text, README `cosign verify` pinned, `docs/` committed; the
    base manifest tag `0.1.1` is in `k8s/`). F19 and F21 untouched (platform: NetworkPolicy narrowing and
    the Hydra client scope; recorded in F19, F21, OQ1, OQ7).
  - **Correction:** F18's claim that `//` and `.` segments were forwarded as sent was true only of the
    `Handler` used directly; the wired server's `ServeMux` already answered `307` to the cleaned path
    (pinned by `TestWiredRoutePolicy`). The real gaps were the trailing slash, the decoded forms and the
    absence of an allowlist.
  - **Also added:** `TestForward_NoCredentialReachesAForeignRedirectTarget` (F4, the credentialed leg
    named in its note; row I25).
  - **Decided:** OQ3 (encoded slash). OQ1, OQ7 keep recommendations; OQ2, OQ6 unchanged.
  - **Measured:** `go vet` and `gofmt -l` clean; `go test -race -cover ./...` ok — proxy 96.9%, token
    95.5%, config 86.7%, `cmd/server` 38.6%; 59 test functions (142 runs), none skipped; three
    consecutive `-race` runs of the new limit tests green; golangci-lint v2.13.0 `0 issues`; govulncheck
    v1.8.0 `No vulnerabilities found`; rootless podman build and `scripts/check-image-notices.sh`
    `image notices OK`.
  - **Checked against the pinned UI:** joxit/docker-registry-ui 2.6.0 — nginx proxies only `location /v2`
    and the script uses `/v2/`, `/v2/_catalog?n=`, `/v2/<name>/tags/list`, `/v2/<name>/manifests/<ref>`.
  - **Totals (22):** 13 RESOLVED (F1, F2, F4, F7, F8, F9, F14, F15, F16, F17, F18, F20, F22), 7 MITIGATED
    (F3, F5, F10, F11, F12, F19, F21), 0 ACCEPTED-RISK, 0 DEFERRED, 2 Positive (F6, F13).
  - **Not done / not mine:** the registry credential inventory, the rotation rehearsal, the external
    review, the scheduled negative origin check (F19), the Hydra client scope (F21) — maintainer or
    platform.

- 2026-10-18 — released and deployed (`v0.1.7` = `a3678e4`, `0.1.7@sha256:150382016712b23b60c991996b5b69293b6dde5f481447d4c0574197ef2f097e`), verified live. Cosign keyless signature verified against the workflow-anchored identity (`verify-digests.sh` 16/16); rollout (`kubectl apply -k`, registry overlay) succeeded. On-node route checks after the rollout: allowed routes `200`, write methods `405`, non-routes `404`, non-canonical paths `400` (release facts). Still open and unchanged: F19, F21 (platform), the rotation rehearsal, the credential inventory and the external review.

## Pre-save consistency checklist (this pass)

- [x] Section A ↔ findings: every row HOLDS (2026-10-18: I10, I20, I21 now cite F18, F20, F17 as resolved;
  I23–I25 added); no GAP row beside a RESOLVED finding.
- [x] Finding header ↔ body: consistent (original 2026-10-03 text kept as history under each header, the
  remediation paragraph states what was done).
- [x] Template line: base + GO + IMG + AUTH + PROXY at the registry dates (2026-10-08); untriggered lenses named.
- [x] Corpus IDs preserved (F1–F13, OQ1–OQ6); new IDs F14–F22 / OQ7 (no new finding in the 2026-10-18 pass).
- [x] Section D ↔ dispositions (unticked items name their gate: pre-mainnet or maintainer).
- [x] Executive summary ↔ dispositions and ceiling (Medium; realised Low): 13 RESOLVED, 7 MITIGATED, 0 ACCEPTED-RISK, 0 DEFERRED, 2 Positive = 22.
- [x] C.1 counts measured 2026-10-18 (0.1.7 tree).
- [x] Re-verification log entry added.
