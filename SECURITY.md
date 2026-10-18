# Security Policy

## Scope

This policy covers security issues in:

- The Go binary (`cmd/server`, `internal/*`) — credential leakage, authentication or
  authorization bypass, request smuggling, header injection, or similar
- The container image build (`Dockerfile`) — issues arising from the base image or build
  configuration
- The published images at `quay.io/meddleware-org/registry-auth-proxy` and
  `docker.io/meddleware/registry-auth-proxy`

It does not cover:

- The security of the CNCF Distribution registry, Ory Hydra, or Ory Keto themselves
  (report those upstream)
- The [registry-token-service](https://github.com/meddleware-org/registry-token-service),
  which has its own policy
- Vulnerabilities in the Go standard library (report to the
  [Go security team](https://go.dev/security))
- Operator misconfiguration of the registry, Kubernetes, or Docker deployment (e.g.
  granting the `registry-browser` identity more than pull + catalog)

## Security model (invariants)

These invariants are load-bearing. A report demonstrating that any is violated is in
scope and treated as high severity:

1. **The client secret is file-only and never logged.** It is read solely from
   `CLIENT_SECRET_FILE` (mounted from a Kubernetes Secret) at startup and again when the token
   service refuses the credentials (rotation, below), never from an environment
   variable, and never appears in logs or error messages. Issued Bearer tokens are never
   logged either.
2. **Fail closed.** If the token service is unreachable or errors, the proxy returns
   `502` — it never passes through a naked `401` (which would trigger the browser UI's
   login dialog) and never fabricates a success.
3. **Inbound Authorization is stripped.** Client-supplied `Authorization` headers (e.g.
   stale credentials from joxit `localStorage`) are removed before forwarding; the proxy
   attaches only tokens it fetched itself.
4. **Read-only.** Only `GET` and `HEAD` are forwarded (others are `405`), and no request
   body is forwarded. The proxy predicts and requests only `pull` and `catalog` scopes: a
   challenge for any other scope is answered `403` without calling the token service. A
   request that is still `401` after a valid token is attached is remapped to `403` —
   authenticated but not authorized — and the refused token is dropped, never escalated.
5. **Tokens are cached only under the scope they were issued for,** in a cache bounded to
   512 entries, so one path can never be served a token issued for another resource and
   a client enumerating repository names cannot grow memory without bound.
6. **No response body tampering.** Response bodies are streamed verbatim; only the fields listed
   under "Forwarding policy" below are removed in transit.
7. **Only the registry's read routes are forwarded, in canonical form.** The proxy holds a
   credential, so the requests it will make with it are an allowlist: `/v2/` (and `/v2`),
   `/v2/_catalog`, and `/v2/<name>/{tags/list,manifests/<ref>,blobs/<digest>,referrers/<digest>}`
   with `<name>`, `<ref>` and `<digest>` matching the registry's own grammars (lower-case
   repository name of at most 255 characters, tag or OCI digest). Any other canonical path is `404`;
   a path with an empty, `.` or `..` segment or a trailing slash is `400`. Both are answered
   before the token service or the registry is contacted, and the path the registry receives is
   exactly the path that was checked (it is never rewritten), so an encoded slash, NUL or newline
   cannot reach the registry or a cache key. The joxit nginx in front only proxies `/v2`.

## Forwarding policy

- **Request, removed before forwarding:** `Authorization` (replaced by the proxy's own Bearer
  token), `Cookie`/`Cookie2`, the hop-by-hop set (RFC 9110 §7.6.1) and every field named in
  `Connection`, and the fields that describe the client's path rather than the request:
  `X-Forwarded-*`, `Forwarded`, `X-Real-Ip`, `True-Client-Ip`, `Cdn-Loop` and every `Cf-*`
  field (including the Cloudflare Access assertion `Cf-Access-Jwt-Assertion`, which is a bearer
  for the UI application, not for the registry). Everything else (`Accept`, `Range`,
  `If-None-Match`, `User-Agent`, …) is forwarded; the proxy adds `Via: 1.1 registry-auth-proxy` and
  refuses (`508`) a request that already carries it.
- **Response, removed before it reaches the UI:** the hop-by-hop set, fields named in
  `Connection`, `Set-Cookie`/`Set-Cookie2` and `Access-Control-*`.
- **Limits:** at most 64 forwards in flight (`503` + `Retry-After` beyond that); upstream dial
  5 s and response-header 30 s with no total deadline (blob downloads stream); request headers
  at most 32 KiB (`431` beyond); `ReadHeaderTimeout` 10 s. These are pinned by tests.
- **Logs:** a failed upstream or token fetch is logged by class (`timeout`, `canceled`,
  `unreachable`, and for the token service `status`/`malformed` with the status code), never with the
  error text, which carries the internal address. Credentials and tokens are never logged.

## Transport to the token service and the registry

The proxy reaches the token service (`TOKEN_ENDPOINT`, e.g.
`http://token-service.registry.svc.cluster.local:8080/token`) and the registry (`UPSTREAM_URL`) over
**in-cluster HTTP** (ClusterIP services). `config.Load` validates both are well-formed `http(s)` URLs
with a host and fails fast otherwise. The hops are plaintext and **not mutually authenticated**: the
platform runs no SPIFFE/SPIRE mutual authentication (withdrawn, decision D18: Cilium deprecated
the feature, and its successor cannot serve traffic between enrolled and non-enrolled pods). The
Basic-auth client secret and the issued Bearer tokens therefore cross the pod network in clear. The
controls that bound it are:

- **NetworkPolicy.** The `registry` namespace runs default-deny ingress
  (`k8s/base/registry/networkpolicy.yaml`, enforced by Cilium); `allow-registry-ingress` admits the
  `nginx-ingress`, `monitoring` and `registry` namespaces and, on `8181`/`8080`, the `platform-probe`
  pod only. That is whole namespaces, not single pods: any pod in an admitted namespace can reach
  the proxy, which confers the read-only `registry-browser` identity to any caller by design. There is
  no Ingress for the proxy; the human door is `registry-ui`, behind Cloudflare Access.
- **Client-secret authentication at the token service.** Hydra accepts the exchange only with a
  valid client secret, and the token service grants only what Keto allows `registry-browser`
  (pull on the organisation's repositories and the catalog). The proxy additionally requests only
  read scopes (invariant 4).
- **Single-node traffic.** On the current one-node cluster the traffic never leaves the host.
  Between nodes it would be encrypted by Cilium WireGuard transparent encryption (applied to the live
  release; no peers yet), which still would not authenticate the peers.

Application-level mTLS is intentionally **not** implemented here: a hostile pod on the same node is
bounded only by the NetworkPolicy, the registry's own Bearer authentication, and the read-only grants.

## Client-secret rotation and compromise

The credential is the `registry-browser` Hydra client secret. It exists in three places that must hold
the same value: the Hydra client (reconciled by the `hydra-client-setup` Job from
`hydra-client-secrets`, key `browser-client-secret`), and the proxy's own Kubernetes Secret
`registry-auth-proxy-secret` (key `client-secret`, mounted as the file `CLIENT_SECRET_FILE`). The
workspace procedure (`docs/auth/OPERATIONS.md`, "Rotate a client secret") rotates Hydra; the steps
below add the proxy's side.

1. Generate the new value (`openssl rand -base64 32`).
2. Update **both** Secrets with it: `browser-client-secret` in `hydra-client-secrets` and `client-secret`
   in `registry-auth-proxy-secret` (SOPS source `registry/auth-proxy-secret.enc.yaml`), and apply them.
3. Wait for the kubelet to refresh the mounted file (it updates a Secret volume in place, normally
   within about a minute; a `subPath` mount would never update, and this deployment does not use one).
4. Re-run the `hydra-client-setup` Job. It replaces the client, so the **old secret stops working at
   once**.

What the proxy does: tokens already cached keep working until they expire. The first token request after
step 4 is refused by the token service (`401`); the proxy then **re-reads `CLIENT_SECRET_FILE`, and if the
value changed retries once with it**, so no restart is needed (the log shows
`client secret reloaded after the token service refused the credentials`; the value is never logged). If
the file still holds the old value (step 3 not finished) the request fails closed with `502` and the next
miss tries again. The restart is the fallback: `kubectl -n registry rollout restart
deployment/registry-auth-proxy`. Confirm with the `platform-probe` catalogue check or
`GET /v2/_catalog` through `registry-ui`.

**Compromise** of the secret (it is read-only identity material, but it mints pull tokens): do steps 1–4
immediately with the new value, treat step 3 as complete only when the pod can read the new file, then
review the token service and registry access logs for the period. There is no overlap window: Hydra
holds one secret per client, so the old value dies in step 4. No rotation cadence is fixed and no last
rotation date is recorded in this repository; the rehearsal and cadence are maintainer tasks
(`OPERATOR_TASKS.md`).

## Supported versions

Only the latest published image tag receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by emailing **<security@meddleware.co.uk>**. Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept (if available)
- The image tag or commit SHA you tested against

You will receive an acknowledgement within **3 business days** and a resolution plan
within **14 days** for confirmed issues. Critical issues (CVSS ≥ 9.0) are prioritised for
same-day acknowledgement.

## Disclosure

Once a fix is released, a security advisory will be published on the GitHub repository.
Reporters may be credited by name unless they prefer to remain anonymous.
