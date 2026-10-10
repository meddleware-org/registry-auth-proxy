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
- `docs/` (this audit) is still untracked in the repository (`git status`: `?? docs/`).

**Review date:** 2026-10-03 (second pass; baseline 2026-09-18) · re-verified 2026-10-09
**Reviewer:** Internal review
**Severity ceiling:** Medium.

- The proxy holds one read-only identity (`registry-browser`, pull + catalog) and authenticates
  nothing inbound, by design.
- The real authorization decision lives in registry-token-service + Keto and the registry.
- A defect can deny registry browsing, amplify load on the token service and IdP, or widen what the
  proxy *requests*. It cannot exceed what Keto grants the identity.
- Realised ceiling at this pass: **Low** (every open item is Low or Info and none widens access).

**Status:** re-verified 2026-10-09.

- The baseline was supplied to this review and is **not committed** in the repo; this file is still
  untracked (F12).
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
| Images | `quay.io/meddleware-org/registry-auth-proxy:0.1.6@sha256:d98c347c…1581`; `docker.io/meddleware/registry-auth-proxy:0.1.6` (same digest); best-effort mirror on the self-hosted registry |
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
| Signing / client credentials | `registry-browser` client secret — mounted file `CLIENT_SECRET_FILE` (Secret `registry-auth-proxy-secret`, mode 0440) — no rotation cadence fixed (F10); no signing key |
| Authorization model | Keto namespace `Registry`: `registry-browser` is `pullers` of `meddleware-org` and `listers` of `catalog`; the proxy adds its own request-side limit (read scopes only, F8) |

**PROXY lens front matter:**

| Field | Value |
| --- | --- |
| Upstreams | one origin, `UPSTREAM_URL` (`http://registry.registry.svc.cluster.local:5000`), set in the manifest and validated at startup (F1); the registry authenticates every request itself (Bearer), so there is no origin lock to enforce (F19) |
| Public paths | every path, no inbound credential, `GET` and `HEAD` only (anything else is `405`); `/healthz` is local |
| Body cap / timeouts | no request body is read or forwarded; `ReadHeaderTimeout` 10 s; `IdleTimeout` 120 s; `MaxHeaderBytes` 32 KiB; no `WriteTimeout` (blobs stream); upstream dial 5 s and response-header 30 s, no total deadline; 64 forwards in flight (B.PX-2) |
| Trusted forwarding hops | one: joxit's nginx in the same namespace; the proxy uses no client address and sets no `X-Forwarded-*` of its own (F18) |

**Location:** `registry-auth-proxy/docs/audit/registry-auth-proxy-audit.md`. This directory is still
untracked; committing this file also brings the baseline history into the repo (F12).

> **Access note:** the review ran against the workspace checkout `repos/registry-auth-proxy` at `main`
> = `v0.1.6` (`7928960`) and the read-only manifests under `k8s/`. Nothing was changed, committed or
> pushed.

---

## Executive summary

A small, stdlib-only proxy (about 1,100 lines of Go plus 1,100 lines of tests).

**Every finding of the 2026-10-03 pass was fixed in 0.1.4–0.1.6 and verified here against `v0.1.6`
(`7928960`).** Coverage is now **93.8 / 94.1 / 86.8%** for proxy / token / config (37 test functions,
79 runs with subtests; `cmd/server` 0%). Verified in code and tests:

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
- Unchanged and still holding: inbound `Authorization` stripped, fail-closed `502` on a token-fetch
  error, `401→403` remap after a token is attached, a file-only client secret never logged, upstream
  redirects not followed, `..` traversal rejected, config URL validation, and spec-conformant token
  expiry (default 60 s; issue time = min(`issued_at`, local clock)).

**Findings after this pass: 22 — 9 RESOLVED, 5 MITIGATED, 2 ACCEPTED-RISK, 4 DEFERRED, 2 Positive.**
Nothing is Medium or higher; every open item is Low or Info and none widens access.

- **F5 corrected (Low, MITIGATED).** The baseline called the plaintext hop to the token service
  RESOLVED by "WireGuard + SPIFFE mutual authentication". The platform no longer runs mutual
  authentication (decision D18) and WireGuard protects only inter-node traffic; the cluster is one
  node. The hop is plain in-cluster HTTP bounded by NetworkPolicy and Cloudflare Access in front of
  the UI.
- **Lens items found open (all Low or Info):**
  - F17 (ACCEPTED-RISK): a token-fetch failure still logs the token endpoint URL;
  - F18 (ACCEPTED-RISK): the forwarding policy is a denylist and any `GET`/`HEAD` path is forwarded;
  - F19 (MITIGATED): the proxy's own door is bounded by NetworkPolicy and Access, with no scheduled
    negative check;
  - F20 (DEFERRED): the new deadlines and header cap are configured but not exercised by tests;
  - F21 (MITIGATED): the Hydra client is registered with a `registry:push` scope that only Keto and
    the proxy now withhold.
- **Still deferred to the pre-mainnet gate:** the credential-rotation procedure for the
  `registry-browser` secret (F10); documentation that still lacks the transport protection, the
  workflow-pinned `cosign verify` command and a committed audit (F12); tests for the new deadlines and
  header cap (F20); and licence notices in the image (F22).

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
| Browser UI / same-namespace client (joxit's nginx; anyone who can drive the UI) | reachability to :8181; no credential. The public UI is behind Cloudflare Access | send `GET`/`HEAD` for any path with any headers; drive scope prediction and cache keys | read-only upstream identity; `405` for other methods, no body forwarded (F8); scope-exact bounded cache (F3, F7); 64 in flight (F15); `ReadHeaderTimeout` and 32 KiB headers; 401→403 remap; traversal reject. **Any path is forwarded (F18)** |
| On-path attacker (proxy ↔ token service) | plaintext in-cluster HTTP on one node | observe the Basic-auth secret and issued tokens | NetworkPolicy, one node, WireGuard between nodes only; no mutual authentication (F5) |
| Malicious / compromised upstream registry | operator config, or MITM | craft `WWW-Authenticate` (`service`, `scope`); huge bodies; cookies, CORS grants, `Connection`-named fields, redirects | fetcher 10 s timeout + 64 KiB cap; redirects not followed (F4); streamed responses; quote-aware parse and a read-only scope filter (F8); response filtering (F14); 30 s response-header deadline (F15) |
| Token service / IdP (registry-token-service → Hydra, Keto) | the authority | issue tokens with the granted intersection | fail-closed 502 here; its own audit |
| Operator | env + mounted Secret | misconfigure URLs or identity scope; rotate the secret | URL validation at startup (F1). **Rotation is documented only at workspace level (F10)** |

### Forwarding matrix (PROXY lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Client | method, path, query, every header (body is never read) | §A route policy (`GET`/`HEAD` only; `..` rejected, F18 for the rest), header policy (F14), limits (F15) |
| Upstream (the registry) | status, headers, body, redirects, timing | response filtering (F14), redirects not followed (F4), deadlines (F15), streamed bodies |
| A party on the path to the upstream | the same, on plain in-cluster HTTP | NetworkPolicy and a single node (F5); the registry's own Bearer check |
| State store behind the gate | none: the token cache is in process memory | — |
| Whoever can reach the registry directly | the registry's own token authentication applies to them; there is no bypass of this hop to protect | the registry (F19) |

### Identity & credential matrix (AUTH lens)

| Authority / credential | Holder | What it confers | Misuse / compromise impact | Rotation / revocation plan |
| --- | --- | --- | --- | --- |
| OAuth client secret (`registry-browser`, confidential client, client credentials) | this service (`CLIENT_SECRET_FILE`, read once at startup); the same value sits in `hydra-client-secrets` | tokens for the identity's Keto grants (pull + catalog) | registry read access as `registry-browser` | workspace procedure `docs/auth/OPERATIONS.md` "Rotate a client secret", then restart the pod (the file is not re-read); no cadence, no compromise procedure in this repo (F10) |
| Registry Bearer token (Distribution JWT) | in-memory per-scope cache | the token's `access` claim for its TTL | replay within the TTL | short TTL from the token service; scope-exact key (F7); margin `TOKEN_REFRESH_MARGIN` (30 s); evicted when the registry refuses it |
| Keto relations for `registry-browser` | platform | which repositories and actions | widening them no longer widens the proxy: it requests only read scopes (F8) | registry-token-service audit |
| Cloudflare Access session of the human using the UI | the browser, then joxit's nginx | reaching the UI at all | a leaked Access JWT header is forwarded to the registry (F18) | Cloudflare Access (PLATFORM lens) |

---

## Severity scale

Critical / High / Medium / Low / Info / Positive.

## Scope

- **In scope (`v0.1.6` = `7928960`, `main` HEAD):**
  - `cmd/server/main.go`, `internal/{config,proxy,token}/**` and tests
  - `Dockerfile`, `.dockerignore`, `go.mod`, `.env.example`
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
- **Environment (2026-10-09, local Go 1.27.1 with `GOTOOLCHAIN=local`; CI uses 1.26.9):**

| Command | Result |
| --- | --- |
| `go vet ./...` | clean |
| `go test -race -cover ./...` | ok — `internal/proxy` **93.8%**, `internal/token` **94.1%**, `internal/config` **86.8%**, `cmd/server` 0%; 37 test functions (79 runs with subtests) |
| Registries (2026-10-10) | quay.io and Docker Hub tag `0.1.6` both resolve to `sha256:d98c347c…1581`, equal to `config/images.yaml` and the overlay pin |
| Live (2026-10-10) | `GET` and `POST https://registry-ui.meddleware.co.uk/v2/_catalog` without a session answer `302` to the Cloudflare Access login: the UI that fronts the proxy is not anonymous |
| govulncheck / golangci-lint | run in CI (pinned v1.8.0 and v2.13.0); the `0.1.6` image exists on both registries, and the publish job runs only after the CI-equivalent `verify` job passes; the local binaries were not re-run here |
| 2026-10-03 scratch probes (F3, F7, F8, F11) | superseded: each scenario is now a committed test (see the findings) |

  The working tree was left clean.

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
still accepted (F11).

### F2 — Scope prediction emitted malformed scopes from crafted paths
**Severity:** Low–Medium   **Disposition:** RESOLVED (re-verified 2026-10-09)
**Where:** `internal/proxy/scope.go:58-70` (`NormalizePath` cleans the path, rejects any `..`
segment, and keeps `/v2` requests under `/v2`); `handler.go:166-172` (400 `invalid path`);
`PredictScope` normalises first. Tested by `TestNormalizePath` and `TestPredictScope`.
**Note:** this closes *traversal-based* key minting only. Unique repository names still mint keys,
now bounded by the cache cap (F3). Empty and `.` segments are cleaned for prediction but forwarded as
sent (F18).

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
  into one token request, detached from any one caller's context (`handler.go:239-252`). Tests:
  `TestFlightSharesOneFetch`, `TestFlightDoesNotCacheResultsOrErrors`, `TestFlightKeysAreIndependent`,
  `TestServeHTTP_ConcurrentMissesShareOneTokenRequest`.
- **Residual (accepted).** Distinct repository names still each cost one probe and one token request;
  there is no negative cache (S3). The cost is bounded by the 64-forward cap (F15), the nginx limit of
  20 requests per second per visitor on `registry-ui` (`k8s/base/registry/registry-ui/ingress.yaml`),
  Cloudflare Access in front of the UI, and the token service's own limits. Each cache entry is one
  scope string and one token, so 512 entries is a small fixed memory cost.

### F4 — Upstream redirects no longer auto-followed
**Severity:** Low   **Disposition:** RESOLVED (redirect half, re-verified 2026-10-09 —
`handler.go:129-131` `CheckRedirect` → `http.ErrUseLastResponse`; `TestServeHTTP_DoesNotFollowUpstreamRedirect`).
The `service`/`scope` forwarding half the baseline left open is now resolved as **F8**.
**Note:** the test redirects the unauthenticated probe, so it pins the probe leg; the credentialed
retry uses the same client and the same `CheckRedirect`, but a recording upstream asserting that no
credential reaches a foreign `Location` on that leg would match the PROXY lens test exactly (C.1).

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
SECURITY.md contains no WireGuard, SPIFFE, mTLS or NetworkPolicy text (F12). SECURITY.md also makes
no false claim about it.

### F6 — Response splitting / header injection not exploitable
**Severity:** Positive (re-verified 2026-10-09) — header copy uses `Header().Add`. Go rejects CR/LF in
header values, and `service`/`scope` flow only into `url.Values.Encode`. Fields named in `Connection`
are now filtered in both directions as well (F14).

### F7 — A non-pull challenge poisons the pull-scope cache entry (read denial per repository)

**Severity:** Low (availability of registry browsing; any UI user can trigger it)
**Disposition:** RESOLVED (0.1.4, `e1ed1c8`)
**Where (at 2026-10-03):** `internal/proxy/handler.go:157-186`.

- `resolvedScope` is the challenge scope.
- `h.cache.Set(resolvedScope, …)` **and** `h.cache.Set(predictedScope, tok, …)` when they differ.
- `PredictScope` always predicts `:pull` (`scope.go:16-46`).

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

- `Handler.token` (`handler.go:239-252`) caches only under the scope it fetched for; the second `Set`
  under the predicted alias is gone. `proxyWithToken` evicts a token the registry refuses
  (`:275`), so a wrong-scope token cannot linger.
- `DELETE` can no longer start the sequence at all: it is `405` before any probe (F8).
- Tests: `TestServeHTTP_TokenCachedOnlyUnderIssuedScope` (the registry challenges for
  `repository:a:pull` on a `/v2/b/…` path; the token is not served from `b`'s key),
  `TestServeHTTP_RefusedTokenIsDropped`, `TestServeHTTP_RefusesNonReadChallenge`.

### F8 — Read-only is not enforced by the proxy: all methods forwarded, and any challenge scope requested

**Severity:** Low (defence in depth; Keto remains the authority)   **Disposition:** RESOLVED (0.1.4,
`e1ed1c8`)
**Where (at 2026-10-03):** `internal/proxy/handler.go:103-120` (bodies buffered for any method),
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
  first step (`handler.go:142-146`); `roundTrip` builds the upstream request with no body (`:292`), so
  nothing is read or buffered and the 32 MiB cap is gone. Test: `TestServeHTTP_OnlyGetAndHead`
  (PUT, POST, DELETE, PATCH, OPTIONS → 405; neither the upstream nor the token service is hit),
  `TestServeHTTP_HeadIsForwarded`.
- **Scopes.** `readOnlyScope` (`challenge.go:455-473`) admits only `registry:catalog:*` and
  `repository:<name>:pull`, checking every space-separated entry; anything else, including
  `pull,push`, `delete`, `*`, an unknown type or a malformed entry, is `403` with no token request
  (`handler.go:211-218`). Tests: `TestServeHTTP_RefusesNonReadChallenge` (seven refused scopes, token
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
**Disposition:** DEFERRED (pre-mainnet gate "key rotation rehearsed; compromise procedure
documented", Section D; the rehearsal is a maintainer task)
**Where:** `internal/config/config.go:497-504` (read once); README, SECURITY.md and CLAUDE.md (no
"rotat…" anywhere).

**Issue / Impact:**

- Rotating the `registry-browser` secret in Hydra makes every token fetch fail (fail-closed `502`)
  until the pod restarts with the new Secret.
- There is no documented sequence (dual-secret overlap in Hydra if supported, update the Secret,
  roll the deployment) and no compromise procedure.

**Remediation / evidence:**

- Document rotation and compromise steps in SECURITY.md.
- Optionally re-read `CLIENT_SECRET_FILE` on a `401` from the token service (kubelet updates mounted
  Secrets in place), or watch the file.

**Status (2026-10-09):** code and repo documents are unchanged (read once; no rotation text). What
exists is workspace-level: `docs/auth/OPERATIONS.md` "Rotate a client secret" (put the new value in
`hydra-client-secrets`, re-run the `hydra-client-setup` Job, which replaces the client so the old
secret stops working at once, then update the consumers — "the registry auth proxy" among them), and
the token-service runbook defers to it. The gaps are specific:

- the proxy reads the file once, so its pod must be restarted after the Job runs, and until then every
  token fetch fails closed (`502`) — the procedure does not say so;
- the proxy's copy is a separate Secret, `registry-auth-proxy-secret` (the same value, written by
  `bootstrap/profiles/single-node.sh` and `recover-secrets.sh`), which `SECRETS.md` does not list;
- no cadence, no recorded last-rotation date and no compromise procedure for this credential.

None is exploitable; the impact of a missed step is a self-inflicted browse outage.

### F11 — Challenge parsing and fetch-URL details

**Severity:** Info   **Disposition:** MITIGATED (parser and body-read halves RESOLVED in 0.1.4; the
query-string and health-endpoint halves accepted)
**Where (at 2026-10-03):** `handler.go:281-306`, `fetcher.go:204-209`.

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
- **Endpoint query string — ACCEPTED-RISK.** `fetcher.go:372` still concatenates `?`; the deployed
  `TOKEN_ENDPOINT` has no query and is operator-set in the manifest.
- **Body hold — moot.** No request body is read (F8); `ReadHeaderTimeout` is 10 s, so there is nothing
  for a `ReadTimeout` to bound. The missing `WriteTimeout` stays intentional (blobs stream).
- **`/healthz`** is process liveness only and is documented as such in the README endpoint table; it
  does not check the registry or the token service, so a downstream outage does not restart the pod.

### F12 — Documentation drift

**Severity:** Info   **Disposition:** DEFERRED (pre-mainnet documentation gate, Section D; committing
`docs/` is a maintainer action)

- SECURITY.md invariant 4 ("predicts and requests only `pull` and `catalog`") is false for requests
  (F8). CLAUDE.md "read-only" describes the identity, not the proxy (F8).
- SECURITY.md does not document the transport protection F5 relies on. The baseline claimed it did.
- No secret-rotation procedure anywhere (F10).
- The baseline audit (2026-09-18) is not committed. It also contained the F1 and I14 contradictions
  noted above. Commit this file as `docs/audit/registry-auth-proxy-audit.md`.

**Status (2026-10-09):**

- **Fixed in 0.1.4:** SECURITY.md invariants 4 and 5, CLAUDE.md invariants 3–4 and the README /
  AGENTS.md request flow now describe the code (read-only by construction, scope-exact bounded
  cache); CLAUDE.md also records the 0.1.6 forwarding rules.
- **Still open:**
  - SECURITY.md has no transport text (F5) and no rotation text (F10);
  - the README's `cosign verify` example accepts `meddleware-org/registry-auth-proxy/.*`, any workflow
    in the repository; the Publish job summary prints the pinned regexp (IMG *Verification command*,
    the same finding as registry-token-service F22);
  - the README build example uses `v0.1.0`;
  - `k8s/base/registry/auth-proxy/deployment.yaml` still names tag `0.1.1` (the overlay replaces it
    with the 0.1.6 digest, so the cluster is correct; the base alone would run 0.1.1);
  - `docs/` is untracked (`git status`: `?? docs/`).

### F13 — Positive: credential handling and fail-closed behaviour are implemented and tested

**Severity:** Positive (re-verified 2026-10-09)

- **Secret custody.** The client secret is read only from `CLIENT_SECRET_FILE` (non-empty, trimmed),
  never from env, never logged. Error messages include URLs and scope, never credentials.
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
**Where:** `internal/proxy/handler.go:54-86` (hop-by-hop set, `viaToken`, `requestDropped`,
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
- Not covered by this finding: the request policy is a denylist (F18).

### F15 — Concurrency bound, upstream deadlines and header cap

**Severity:** Low (availability)   **Disposition:** RESOLVED (0.1.6, `7928960`); the values are not
exercised by tests (F20)
**Where:** `internal/proxy/handler.go:70-77, 116-124, 156-164`; `cmd/server/main.go:76-84`;
`internal/proxy/forwarding_test.go`.
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
**Where:** `internal/proxy/handler.go:184-189, 259-264, 363-377` (`errorKind`);
`TestForward_UpstreamFailureLogsNoHostname`.
**Issue (before 0.1.6):** the probe and forward errors were logged with the error text, which carries
the upstream URL and so an internal hostname.
**Remediation / evidence:** the log line carries `cause` = `timeout`, `canceled` or `unreachable`
only, and the client sees the fixed body `upstream unavailable` with `502`. The test closes the
upstream, then asserts the host and port appear in neither the log nor the response body and that
`"cause":"unreachable"` is logged. The token-fetch path is not covered (F17).

### F17 — A token-service failure still logs the token endpoint URL

**Severity:** Info   **Disposition:** ACCEPTED-RISK (operator-only log, no credential; the fix is one
line, S5)
**Where:** `internal/proxy/handler.go:226` (`slog.Error("token fetch error", …, "err", err)`) with
`internal/token/fetcher.go:382` (`fmt.Errorf("token endpoint: %w", err)`, which wraps the `*url.Error`
carrying the full request URL).
**Issue:** when the fetch fails at the transport level, the logged error includes
`http://token-service.registry.svc.cluster.local:8080/token?scope=…&service=…`. That is an internal
hostname in the default-level log, which the PROXY lens *Error mapping* row forbids ("internal
hostnames never appear in … logs"). It is not a secret: the Basic credential travels in a header, never
the URL, and the response body is not logged. The client sees only `auth service error` with `502`.
**Why accepted:** the log is an in-cluster JSON stream read by the operator, the hostname is
the one in the public manifests of this workspace, and the repository states no log-visibility
promise. Logging the class (`errorKind`) as F16 does would close it.

### F18 — Forwarding policy is a denylist: any path is forwarded, and some client fields pass through

**Severity:** Low   **Disposition:** ACCEPTED-RISK (the registry authenticates every request and the
identity is read-only; S6 narrows it)
**Where:** `internal/proxy/handler.go:166-172, 287-316`; `internal/proxy/scope.go:58-70`.
**Issue:** three related gaps against the PROXY lens *Route & method policy* and *Request header
policy* rows:

1. **No route allowlist.** Any `GET`/`HEAD` path is forwarded, not only the `/v2` read routes the
   scope predictor knows (`/v2/`, `_catalog`, `tags/list`, `manifests`, `blobs`). `NormalizePath`
   applies its `/v2` confinement only to paths that start with `/v2`.
2. **Path forwarded as sent.** `NormalizePath` cleans the path for scope prediction and rejects `..`,
   but `roundTrip` forwards `r.URL.Path` unchanged: empty (`//`) and `.` segments are not rejected, and
   an encoded slash is decoded to `/` by net/http before the proxy sees it (OQ3). A cache hit is keyed
   by the cleaned path's scope while the registry receives the uncleaned one. The token attached is
   still the read-only pull token for the same repository name, so this cannot reach another
   repository's data; the worst case is a confusing `404` or a registry-side clean-path redirect
   (which is returned, not followed). Not probed against a live registry.
3. **Denylist for client fields.** Everything except `Authorization`, cookies, the hop-by-hop set and
   `Connection`-named fields is copied: `X-Forwarded-*`, `Forwarded`, `X-Real-IP` and the
   Cloudflare-added `Cf-Access-Jwt-Assertion` pass to the registry as joxit's nginx received them (an
   Access-protected request carries that header; this was not observed in the cluster). The registry
   does not authenticate with these, but a Distribution registry can build absolute `Location` URLs from
   `X-Forwarded-Host`/`-Proto`, and an Access assertion is a bearer for the UI application.
**Why accepted:** the only caller is joxit's nginx, behind Cloudflare Access; the injected token is
read-only; the registry returns `404` for anything outside `/v2`; and none of the three reaches
another principal's data. Allow-listing the routes and rebuilding the forwarding fields would
remove the question (S6).

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

### F20 — The new deadlines and header cap are configured but not exercised by tests

**Severity:** Info   **Disposition:** DEFERRED (pre-mainnet gate "limits measured and tested",
Section D)
**Where:** `internal/proxy/handler.go:73-74, 118-124`; `cmd/server/main.go:76-84` (`cmd/server` has 0%
coverage).
**Issue:** the PROXY lens *Limits* tests require "a stalled upstream ends with the stated status and
releases any admission state" and an oversize request to be refused. `TestForward_ConcurrencyIsBounded`
covers the in-flight bound and release, but nothing stalls an upstream past the response-header
deadline, closes a slow dial, or sends a header block over 32 KiB; the values are constants in
`NewHandler` and `main`, so a mistaken edit would pass the suite. `go test` passes with the values
unexercised; a stalled-upstream test needs a configurable deadline.
**Remediation / evidence:** make the deadlines fields of `Handler` (default the constants), add a
stalled-upstream test asserting `502` and a released slot, and build the `http.Server` in a function
the test can drive to assert `431` beyond 32 KiB.

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
the setup Job) is a one-line platform change outside this repository. A mis-edit of the Keto tuples
alone no longer widens the browser.

### F22 — No licence or notice text for the compiled-in stdlib and the CA bundle ships in the image

**Severity:** Info   **Disposition:** DEFERRED (pre-mainnet documentation gate, Section D; the same
finding as registry-token-service F18)
**Where:** `Dockerfile:33-55` (`scratch` plus `/auth-proxy` and `/etc/ssl/certs/ca-certificates.crt`).
**Issue:** the IMG lens *SBOM & notices* row asks that code redistributed in the image ships its
licence texts. The binary contains the Go standard library (BSD-3-Clause) and the image carries the
Mozilla CA bundle copied from the builder (MPL-2.0); the project's own licence is 0BSD (label and
`LICENSE`), and no notice for either is in the image. The SBOM does list the stdlib version and the
base. Low impact: the obligation is attribution, and `scratch` has nowhere to put it today.
**Remediation / evidence:** copy the Go `LICENSE` and the CA bundle's licence note from the builder
into the runtime stage (for example `/THIRD_PARTY_LICENSES`), as the web images now do.

---

## Section A — Invariant verification matrix

| # | Invariant | Enforced at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | Inbound `Authorization` stripped, replaced (never appended) by the proxy's own token | `handler.go:301, 310` | `TestForward_RequestFieldPolicy`, `TestServeHTTP_HappyPath` | HOLDS |
| I2 | Fail closed on a token-fetch error → 502, never a naked 401 | `handler.go:222-229` | `TestServeHTTP_TokenFailureIsBadGateway` | HOLDS |
| I3 | 401→403 remap after a token is attached | `handler.go:267-277` | `TestServeHTTP_RemapUnauthorized`, `TestServeHTTP_RefusedTokenIsDropped` | HOLDS |
| I4 | Only pull/catalog scopes predicted **and requested** (read-only) | `scope.go:16-46`; `challenge.go:455-473`; `handler.go:211-218` | `TestPredictScope`, `TestReadOnlyScope`, `TestServeHTTP_RefusesNonReadChallenge` | HOLDS (F8) |
| I5 | Hop-by-hop and `Connection`-named fields stripped both directions | `handler.go:54-63, 299-307, 321-347` | `TestIsHopByHop`, `TestForward_RequestFieldPolicy`, `TestForward_ResponseFieldPolicy` | HOLDS (F14) |
| I6 | No body tampering; responses streamed | `handler.go:331-332` | happy path | HOLDS |
| I7 | Only `GET`/`HEAD` forwarded; no request body read or forwarded | `handler.go:142-146, 292` | `TestServeHTTP_OnlyGetAndHead`, `TestServeHTTP_HeadIsForwarded` | HOLDS (F8; the 32 MiB cap was removed with the buffer) |
| I8 | Client secret file-only, never env, never logged | `config.go:481-504`; `fetcher.go` | config tests; grep of every `slog` call | HOLDS |
| I9 | Non-root scratch UID 65534 | `Dockerfile:33, 57`; pod `securityContext` | Dockerfile; manifest | HOLDS |
| I10 | Path normalization / traversal defence | `scope.go` `NormalizePath`; handler 400 | `TestNormalizePath`, `TestPredictScope` | HOLDS for `..` (F2); empty/`.` segments and non-`/v2` paths pass (F18) |
| I11 | Upstream URL validated at config time | `config.go` `validateHTTPURL` | `config_test.go` | HOLDS (F1) |
| I12 | Cache bounded (512); expired entries evicted | `cache.go:177, 236-270` | `TestCacheIsBounded`, `TestCacheEvictionKeepsEmptyScope` | HOLDS (F3) |
| I13 | Refresh margin subtracted before store; spec expiry | `cache.go:236-249`; `fetcher.go:403-416` | `TestCacheMarginExpiry`, `TestCacheSkipsTokenAlreadyInsideMargin`, `TestFetchExpiry` | HOLDS |
| I14 | Upstream redirects not followed | `handler.go:129-131` | `TestServeHTTP_DoesNotFollowUpstreamRedirect` | HOLDS (F4; probe leg tested, credentialed leg shares the client) |
| I15 | Cache key = the scope the token was issued for (AUTH lens) | `handler.go:239-252` | `TestServeHTTP_TokenCachedOnlyUnderIssuedScope` | HOLDS (F7) |
| I16 | Proxy requests only pull/catalog scopes and forwards only read methods (SECURITY.md 4; CLAUDE.md) | I4 + I7 | the tests of I4 and I7 | HOLDS (F8) |
| I17 | Cookies are not sent upstream; `Set-Cookie` and `Access-Control-*` are not passed to the UI | `handler.go:82-86, 301, 324` | `TestForward_RequestFieldPolicy`, `TestForward_ResponseFieldPolicy` | HOLDS (F14) |
| I18 | A request that already passed through the proxy is refused (`508`) before any upstream call | `handler.go:148-154` | `TestForward_LoopIsRefusedBeforeAnyUpstreamCall` | HOLDS (F14) |
| I19 | At most 64 forwards in flight; `503` with `Retry-After` beyond | `handler.go:156-164` | `TestForward_ConcurrencyIsBounded` | HOLDS (F15) |
| I20 | Upstream dial 5 s and response-header 30 s deadlines; request headers ≤ 32 KiB | `handler.go:118-124`; `main.go:79-83` | none | HOLDS in code only — F20 |
| I21 | An upstream failure is logged by class, without the upstream address | `handler.go:186, 261, 363-377` | `TestForward_UpstreamFailureLogsNoHostname` | HOLDS for forwards (F16); the token-fetch log carries the URL (F17) |
| I22 | Concurrent misses for one scope share one token request; a refused token is evicted | `flight.go`; `handler.go:239-252, 275` | `TestFlight*`, `TestServeHTTP_ConcurrentMissesShareOneTokenRequest`, `TestServeHTTP_RefusedTokenIsDropped` | HOLDS (F3, F7) |

### Lens category coverage

| Lens | Category | Status |
| --- | --- | --- |
| GO | HTTP server hygiene | HOLDS (code-only) — `ReadHeaderTimeout` 10 s, `IdleTimeout` 120 s, `MaxHeaderBytes` 32 KiB, no `WriteTimeout` (blobs stream, intentional); methods allow-listed (`405` with `Allow: GET, HEAD`); no body is read; a handler panic is recovered per connection by net/http |
| GO | Outbound calls | HOLDS — token fetcher `Timeout` 10 s and 64 KiB body cap; upstream client dial 5 s and response-header 30 s with streamed bodies; no `InsecureSkipVerify`/`TLSClientConfig` anywhere; redirects: PROXY row |
| GO | Input & path handling | HOLDS for `..` and the `/v2` confinement; the rest is F18 |
| GO | AuthN / AuthZ | N/A inbound (by design); no secret comparison exists; token rules: AUTH rows |
| GO | Secrets | HOLDS — I8 |
| GO | Client identity | N/A — the proxy keys nothing on an address; the per-visitor limit is nginx's (20 r/s, F3) |
| GO | Concurrency | HOLDS — `go test -race` green; the cache and `Flight` are mutex-guarded; no goroutine is started per request |
| GO | Graceful shutdown | HOLDS (code-only) — SIGTERM and SIGINT call `Server.Shutdown` with 10 s (`main.go:94-103`) |
| GO | Health & version | HOLDS — `/healthz` returns `{"status":"ok"}`; no `/version` |
| GO | Error handling | HOLDS — fixed text bodies (`upstream unavailable`, `auth service error`, `scope not permitted`, `busy`, `loop detected`, `invalid path`); F17 for the token-fetch log |
| GO | CI (B.GO-1) | HOLDS — `go vet`, golangci-lint v2.13.0, race tests, govulncheck v1.8.0 (pinned), Trivy filesystem scan; no `go.sum` (stdlib only); `-trimpath`, `CGO_ENABLED=0`, version injected with `-X main.version` |
| IMG | Base images | HOLDS — builder digest-pinned and checked against the `go.mod` toolchain; runtime `scratch` |
| IMG | Build context | HOLDS — `.dockerignore` excludes `.git/`, `.env*`, `client-secret`, `*.key`, `*.pem` |
| IMG | Reproducible build stage | HOLDS — `go.mod` only, no dependency to resolve; only the binary and the CA bundle reach the runtime stage |
| IMG | No secrets in layers | HOLDS — build args are OCI label strings |
| IMG | Runtime user & filesystem | HOLDS — `USER 65534:65534`; pod: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities dropped, `RuntimeDefault` seccomp, `automountServiceAccountToken: false` |
| IMG | Runtime configuration | HOLDS — the image sets only `PORT`; the manifest sets `UPSTREAM_URL`, `TOKEN_ENDPOINT`, `CLIENT_ID`, `CLIENT_SECRET_FILE`, `TOKEN_REFRESH_MARGIN`, `LOG_LEVEL` |
| IMG | Health & resources | HOLDS — readiness and liveness on `/healthz`; requests 20m/32Mi, limits 200m/128Mi |
| IMG | SBOM & notices | SBOM HOLDS (SPDX attestation generated from the pushed image); licence notices GAP — F22 |
| IMG | Scan before sign | HOLDS — Trivy on the pushed digest before `cosign sign` (F9) |
| IMG | Verification command | PARTIAL — the job summary prints a workflow-pinned regexp; the README example accepts any workflow in the repository (F12) |
| IMG | Deployment pinning | HOLDS — digest from `config/images.yaml` stamped into the `registry` overlay and cosign-verified 2026-10-09; the base manifest's stale tag `0.1.1` is overridden (F12) |
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
| PROXY | Route & method policy | PARTIAL — `GET`/`HEAD` only, `..` and `/v2` escape rejected, upstream URL from configuration; no route allowlist, empty/`.` segments forwarded as sent (F18) |
| PROXY | Request header policy | HOLDS with a denylist — `Authorization`, cookies, hop-by-hop and `Connection`-named fields removed, `Host` set, `Via` added (F14); forwarding fields and the Access assertion are copied (F18) |
| PROXY | Response header policy | HOLDS — hop-by-hop, `Connection`-named, `Set-Cookie` and `Access-Control-*` dropped (F14) |
| PROXY | Redirects | HOLDS — `ErrUseLastResponse` on the one client (F4) |
| PROXY | Limits & timing | HOLDS in code (F15), untested (F20) — 10 s header read, 120 s idle, 32 KiB headers, no body, 64 in flight, upstream dial 5 s and response-header 30 s; no total deadline by design; no cap on idle connections |
| PROXY | Error mapping | HOLDS for forwards (F16): fixed `502`/`503`/`508` bodies, class-only logs; F17 for the token log |
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
| `CLIENT_SECRET_FILE` | mounted k8s Secret `registry-auth-proxy-secret` (0440; SOPS at rest) | read once at startup; unexported; never env or logs | Basic auth to the token service | `docs/auth/OPERATIONS.md` plus a pod restart; no cadence or compromise procedure (F10) |

CI and release integrity (base §B.2): actions pinned by full SHA; explicit `permissions:` (`contents:
read`; `id-token` and `attestations` only on `publish-public`); tag-gated release (`v*`); release gate
equals CI; Dependabot weekly and grouped for Docker and GitHub Actions; no `set -x` or secret echo; no
real-funds job; no test-only build mode.

### B.IMG-1 Publish & attestation

Each pushed image (quay.io and Docker Hub, multi-arch, signed at the index digest) carries a keyless
cosign signature, an SPDX SBOM attached as a signed attestation (`cosign attest --type spdxjson`) and a
GitHub build-provenance attestation, plus BuildKit `provenance: mode=max` (`sbom: false` because the
BuildKit scanner pull is unreliable); none of these steps uses `continue-on-error`. The self-hosted
registry push (`publish-private`) is a best-effort, unsigned mirror. The 0.1.6 digest
`sha256:d98c347c…1581` is the same on quay.io, Docker Hub and in `config/images.yaml`, and was
cosign-verified on 2026-10-09.

### B.AUTH-1 Key & credential inventory

| Key / credential | Type / algorithm | Where held | Who can read it | Rotation cadence · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| `registry-browser` client secret | OAuth 2 client secret (client credentials; HTTP Basic to the token service) | k8s Secret `registry-auth-proxy-secret` mounted at `CLIENT_SECRET_FILE`; the same value in `hydra-client-secrets` (`browser-client-secret`); SOPS-encrypted sources in the cluster directory | the pod; cluster admins; the age-key holder | no cadence fixed · set at bootstrap, no rotation date recorded | rotate through the `hydra-client-setup` Job and restart the pod (`docs/auth/OPERATIONS.md`); no dedicated compromise procedure (F10) |
| Cached registry Bearer tokens | Distribution JWT (opaque to the proxy) | process memory | the process | TTL from the token service; margin 30 s; max 512 entries | expire; a refused token is evicted; restart clears |
| quay.io / Docker Hub push tokens | registry robot/access tokens | GitHub repository secrets | maintainers | not recorded — maintainer item, `OPERATOR_TASKS.md` "Image registry credentials" (before mainnet) | revoke at the registry |

### B.AUTH-2 Client & authorization inventory

| OAuth client / relation | Type, grant types, auth method | Redirect URIs | Scopes / relations granted | Owner | Last reviewed |
| --- | --- | --- | --- | --- | --- |
| `registry-browser` | confidential; `client_credentials`; `client_secret_basic` (through registry-token-service) | n/a | Hydra registration: `registry:push registry:pull registry:catalog` (broader than use, F21); Keto: `pullers` on `meddleware-org`, `listers` on `catalog`; the proxy requests only pull and catalog (F8) | platform (`hydra-client-setup`, `keto-relations-setup` Jobs) | 2026-10-09 (this audit; tuples read-only) |
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
| `/v2/_catalog`, `/v2/<name>/tags/list`, `/v2/<name>/manifests/<ref>`, `/v2/<name>/blobs/<digest>`, `/v2/` | `GET`, `HEAD` (others `405`) | none inbound; the proxy's Bearer outbound | every field except those stripped, plus `Via` and the proxy's `Authorization`; `Host` = the upstream's; query forwarded verbatim | request: `Authorization`, `Cookie`/`Cookie2`, `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` and every field named in `Connection`; response: the same hop-by-hop set, `Connection`-named fields, `Set-Cookie`/`Set-Cookie2`, `Access-Control-*` | everything else (Distribution headers, `Content-Type`, `Docker-Content-Digest`, `Location`); `401` after a token → `403` | tokens only, in process, keyed by issued scope; no response caching |
| any other path (F18) | `GET`, `HEAD` | as above | as above | as above | as above | none |

### B.PX-2 Limits

| Limit | Value | Where enforced | Test |
| --- | --- | --- | --- |
| header-read timeout · body-read deadline · idle timeout | 10 s · n/a (no body is read) · 120 s | `main.go:79-80` | none (F20) |
| request body cap (declared / streamed) | none needed: no body is read or forwarded | `handler.go:292` (nil body) | `TestServeHTTP_OnlyGetAndHead` |
| request header size | 32 KiB (`431` beyond) | `main.go:83` | none (F20) |
| concurrent connections / in-flight forwards | 64 forwards (`503` + `Retry-After: 1`); connections not capped | `handler.go:76, 156-164` | `TestForward_ConcurrencyIsBounded` |
| upstream connect · response · total deadline | 5 s · 30 s (headers) · none (blobs stream) | `handler.go:73-74, 118-124` | none (F20) |
| token fetch | 10 s, 64 KiB | `fetcher.go:361, 386` | `TestFetchFailsClosed` |
| token cache | 512 entries; margin 30 s | `cache.go:177` | `TestCacheIsBounded` |
| admission-state lifetime | n/a (no admission state) | — | — |

---

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade — A− (proxy 93.8%, token 94.1%, config 86.8%; race-clean; 37 test functions, 79 runs)

| Dimension | Assessment |
| --- | --- |
| Happy path | A — scope prediction, challenge parse (quoted, escaped, lowercase scheme), hop-by-hop, remap, cache hit and margin, fetcher success, `HEAD` |
| Error path | A− — fail-closed 502, fetcher non-200/empty/oversize, refused challenge scopes, refused token eviction, redirect, 405s, 508, 503 on the bound, class-only failure log |
| Boundary / edge | B+ — traversal and normalisation, cache bound and eviction, single flight, `Connection`-named fields; **missing:** a stalled upstream and the dial deadline, a header block over 32 KiB (F20), empty/`.` segments and non-`/v2` paths (F18), a recording upstream asserting no credential reaches a foreign `Location` on the credentialed leg (F4) |
| Security-relevant | A− — secret loading, inbound strip (replaced not appended), cookies, CORS, scope-exact cache, read-only enforcement; `cmd/server` (0%) holds the server settings and graceful shutdown, which are untested |

### C.2 Hermetic vs. live paths

| Path | Hermetic unit test? | Deferred to | Tracking |
| --- | --- | --- | --- |
| Scope prediction, hop-by-hop, remap, cache, flight | yes | — | proxy and token tests |
| Request/response field policy, loop, in-flight bound, failure log | yes (`forwarding_test.go`) | — | F14–F16 |
| Token fetch (Basic auth, cap, non-200, expiry) | yes | — | fetcher tests |
| Config secret loading and URL validation | yes | — | config tests |
| Server timeouts, header cap, upstream deadlines, shutdown | no | pre-mainnet limits measurement | F20 |
| Live token service + registry end to end | no hermetic test; the platform-probe catalogue check exercises the real chain | staging cluster | `platform-probe` status check |
| Negative check that a pod outside the allowed set cannot reach `:8181` | no | pre-mainnet, platform | F19 |

---

## Section D — Deployment-readiness gates

### pre-localnet (dev / integration)

- [x] builds; tests + race pass; runs from `.env.example`; `SECURITY.md` present
- [x] fail-closed, strip, remap, redirect behaviour tested — F13 (the body-cap test was removed with the buffer, F8)
- [x] B.PX-1 and B.PX-2 complete; hop-by-hop, redirect (probe leg), method, `..` and in-flight-limit tests green — F14, F15; the deadline and header-cap tests are F20 (pre-mainnet)
- [x] configuration fails startup on invalid values — F1
- [x] algorithm and secret rules: secret from a mounted file, nothing secret in source or logs; fail-closed tests green — F13

### pre-testnet (staging)

- [x] F1, F2, F4 (redirect) landed and tested
- [x] cache keyed by issued scope (F7, 0.1.4)
- [x] method allowlist + pull-only scope requests (F8, 0.1.4)
- [x] B.AUTH-1 key & credential inventory and B.AUTH-2 client & relation inventory complete (this audit)
- [x] proxies strip inbound credentials; the proxy requests no scope beyond pull/catalog (F8, F14)
- [x] non-root runtime; pod security context complete; probes and limits set; deployed by digest from `config/images.yaml` (cosign-verified 2026-10-09)
- [x] client identity: nothing keyed on an address; secrets never logged (I8)
- [ ] origin lock verified positively and negatively — the proxy's door is bounded by NetworkPolicy and Access but the negative check does not exist yet (F19); maintainer/platform, pre-mainnet

### pre-mainnet (production)

- [x] bounded cache + single-flight (F3, 0.1.4)
- [x] release gate = CI gates; toolchain aligned; image scan before signing (F9, 0.1.4–0.1.5)
- [x] SBOM, signing and provenance in place
- [x] SIGTERM drains in-flight requests; health endpoint reveals nothing (`main.go:94-103`, `/healthz`)
- [x] release build flags stated (`-trimpath`, `CGO_ENABLED=0`, version injection); image per the IMG lens
- [ ] F5's platform transport cited in SECURITY.md; rotation procedure documented (F5, F10, F12) — documentation gate; the rotation rehearsal is a maintainer task
- [ ] README `cosign verify` pinned to the publish workflow; licence notices shipped in the image; `docs/` committed (F12, F22) — maintainer
- [ ] key rotation with overlap rehearsed; compromise procedure documented for the `registry-browser` secret (F10) — maintainer
- [ ] the negative origin check runs on a schedule (F19) — platform, maintainer
- [ ] limits sized for the plan tier and measured; deadline and header-cap tests (F20)
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
- **Pre-v0.2 policy:** F18–F22 may change behaviour (route allowlist, notices) without shims. The next
  release is 0.1.7.

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
8. The proxy MUST forward only listed routes with a validated path — **partly** (F18).
9. Failures MUST map to fixed `502`/`503`/`508` bodies with no upstream detail in responses or default
   logs — holds for forwards (I21, F16); the token-fetch log carries the endpoint URL (F17).

**AUTH lens baseline:**

| ID | Holds? | Evidence |
| --- | --- | --- |
| AUTH-M1 | N/A (the proxy does not verify tokens; the registry does) | — |
| AUTH-M2 | yes for custody (mounted file, never env or logs); rotation: workspace procedure only, no cadence or compromise steps | F10 |
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
| GO-M1 | yes (`ReadHeaderTimeout` 10 s, `IdleTimeout` 120 s, `MaxHeaderBytes` 32 KiB, no body is read; `WriteTimeout` intentionally absent for streaming) | F11, F15 |
| GO-M2 | yes (fetch 10 s + 64 KiB; upstream dial 5 s and response-header 30 s; streamed bodies) | F13, F15 |
| GO-M3 | N/A (no filesystem serving); path hygiene: F18 | — |
| GO-M4 | N/A (no token verification) | — |
| GO-M5 | yes | I8 |
| GO-M6 | N/A (no client address is used; the per-visitor limit is nginx's) | F3 |
| GO-M7 | yes (lint, vet, race tests, pinned govulncheck, Trivy — in CI and on the tag) | F9 |
| GO-M8 | yes (10-second graceful shutdown) | — |

**IMG lens baseline:** IMG-M1 yes (builder digest checked against the toolchain, `scratch`); IMG-M2 yes
(`.dockerignore` excludes secrets, env files and `.git`); IMG-M3 yes; IMG-M4 yes; IMG-M5 yes (pod
context in `k8s/base/registry/auth-proxy`); IMG-M6 yes (overlay digest from `config/images.yaml`; the
base tag `0.1.1` is stale, F12); IMG-M7 yes (signature, SPDX SBOM attestation, provenance); IMG-M8
partial (scan before sign and SBOM hold; licence notices F22; the README `cosign verify` is not
workflow-pinned, F12).

**PROXY lens baseline:**

| ID | Holds? | Evidence |
| --- | --- | --- |
| PX-M1 | partial — methods and `..` enforced, upstream URL from configuration; no route allowlist | F18 |
| PX-M2 | yes — hop-by-hop and `Connection`-named fields removed both ways; `Via` set by the proxy; other forwarding fields copied from the trusted nginx hop | F14, F18 |
| PX-M3 | yes — `Set-Cookie`, `Access-Control-*` and `Connection`-named fields dropped | F14 |
| PX-M4 | yes | F4 |
| PX-M5 | yes in code (header read, idle, header size, in-flight, dial, response-header); tests missing for the deadlines and header cap | F15, F20 |
| PX-M6 | yes for forwards; the token-fetch log carries the endpoint URL | F16, F17 |
| PX-M7 | N/A (no admission state) | — |
| PX-M8 | N/A for the upstream (the registry is its own gate); the proxy's door is bounded by NetworkPolicy and Access, with no scheduled negative check | F19 |
| PX-M9 | yes (invalid configuration fails startup; strict defaults) | F1 |

## Implementation suggestions (SHOULD / MAY)

- **S1** *(done in 0.1.4)* `readOnlyScope` intersects challenge scopes with `{pull, catalog}` before any
  token request and returns `403` locally (F8).
- **S2** *(done in 0.1.4)* bounded cache with expiry-first eviction and `Flight` single flight (F3).
- **S3** MAY negatively cache "no access" outcomes per scope for a short TTL, to blunt the remaining
  unique-name amplification (F3).
- **S4** MAY re-read `CLIENT_SECRET_FILE` when the token service answers `401`, to make rotation
  restart-free (F10).
- **S5** SHOULD log the failure class (`errorKind`) instead of the error text for token-fetch failures
  (F17).
- **S6** SHOULD allow-list the `/v2` read routes, forward the cleaned path, reject empty and `.`
  segments, and build the forwarded fields from an allowlist (F18).
- **S7** SHOULD make the upstream deadlines fields of `Handler`, add a stalled-upstream test and a
  `431` header-cap test, and a recording-upstream redirect test on the credentialed leg (F20, F4).
- **S8** SHOULD narrow `:8181` in `networkpolicy.yaml` to the `registry-ui` pod (plus platform-probe) and
  add a scheduled negative probe (F19).
- **S9** SHOULD drop `registry:push` from the `registry-browser` client registration (F21).
- **S10** SHOULD, in one patch release: add transport and rotation text to SECURITY.md, pin the README
  `cosign verify` to the publish workflow, ship licence notices (`/THIRD_PARTY_LICENSES`), correct the
  README build example, and commit `docs/` (F5, F10, F12, F22).

## Open questions (`OQ#`)

1. **OQ1** *(baseline OQ1)* NetworkPolicy enforcement and the transport path for proxy ↔ token service.
   Facts recorded: mutual authentication is not run (decision D18) and WireGuard covers only inter-node
   traffic (F5); a default-deny policy exists but admits whole namespaces to `:8181` (F19). Should
   `:8181` be narrowed to the `registry-ui` pod, and should SECURITY.md link the exact manifests?
2. **OQ2** *(baseline OQ2)* Cache growth. (Decided 2026-10-08, 0.1.4: a fixed bound of 512 entries with
   expiry-first eviction and single flight; no per-client limit in the proxy — the per-visitor limit is
   nginx's — see F3.) Open remainder: is the unique-name amplification acceptable without a negative
   cache (S3)?
3. **OQ3** *(baseline OQ3)* `%2F` in repository names: is an encoded slash ever expected? net/http
   decodes it before `NormalizePath`, and `roundTrip` forwards `r.URL.Path` (decoded), so `%2F`
   becomes `/` upstream (F18).
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
   stay aligned with the other clients until the next client-setup change?

## Risks

- **Read-only by layers:** the Keto tuples, the token service's intersection and the proxy's own
  filters agree today; the Hydra registration alone is broader than use (F21).
- **Availability:** the proxy is a single replica with a 64-forward bound; a registry or token-service
  outage ends in `502`/`503` by design, and a rotated secret breaks browsing until the pod restarts
  (F10).
- **Plaintext hop:** proxy ↔ token-service traffic is in-cluster HTTP on one node with no mutual
  authentication; a hostile pod in an admitted namespace is bounded only by NetworkPolicy (F5, F19).
- **Supply-chain mutability:** the image depends on the pinned builder, the Go toolchain and the GitHub
  and Sigstore services; registry push tokens are long-lived until the maintainer inventory is done.
- **Unmeasured limits:** the 64-forward bound, deadlines and header cap are untested and unmeasured
  under load (F20).

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

## Pre-save consistency checklist (this pass)

- [x] Section A ↔ findings: every row HOLDS or carries its finding (I10 → F18, I20 → F20, I21 → F17);
  no GAP row beside a RESOLVED finding.
- [x] Finding header ↔ body: consistent (original 2026-10-03 text kept as history under each header, the
  remediation paragraph states what was done).
- [x] Template line: base + GO + IMG + AUTH + PROXY at the registry dates (2026-10-08); untriggered lenses named.
- [x] Corpus IDs preserved (F1–F13, OQ1–OQ6); new IDs F14–F22 / OQ7.
- [x] Section D ↔ dispositions (unticked items name their gate: pre-mainnet or maintainer).
- [x] Executive summary ↔ dispositions and ceiling (Medium; realised Low).
- [x] C.1 counts measured 2026-10-09.
- [x] Re-verification log entry added.
