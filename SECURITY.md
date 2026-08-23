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
   `CLIENT_SECRET_FILE` (mounted from a Kubernetes Secret), never from an environment
   variable, and never appears in logs or error messages. Issued Bearer tokens are never
   logged either.
2. **Fail closed.** If the token service is unreachable or errors, the proxy returns
   `502` — it never passes through a naked `401` (which would trigger the browser UI's
   login dialog) and never fabricates a success.
3. **Inbound Authorization is stripped.** Client-supplied `Authorization` headers (e.g.
   stale credentials from joxit `localStorage`) are removed before forwarding; the proxy
   attaches only tokens it fetched itself.
4. **Read-only identity.** The proxy predicts and requests only `pull` and `catalog`
   scopes. A request that is still `401` after a valid token is attached is remapped to
   `403` — authenticated but not authorized — never escalated.
5. **No request/response body tampering.** Bodies are streamed verbatim; hop-by-hop
   headers (RFC 7230 §6.1) are the only headers removed in transit.

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
