# ── Build stage ───────────────────────────────────────────────────────────────
# Base pinned by digest for reproducible builds; the tag is kept for readability.
# To bump: docker buildx imagetools inspect golang:<go.mod toolchain>-bookworm --format '{{.Manifest.Digest}}'
FROM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS builder

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# Stdlib-only module: there is no go.sum and `go mod download` is a no-op, but
# copying go.mod first keeps the dependency layer cacheable if deps are ever added.
COPY go.mod ./
RUN go mod download

# The binary is built with the toolchain go.mod names, which is the one CI's govulncheck checks: a builder
# image left on another patch fails here instead of shipping an unchecked stdlib.
RUN grep -q "^toolchain $(go env GOVERSION)$" go.mod || { echo "builder $(go env GOVERSION) != go.mod toolchain"; exit 1; }

COPY . .

# Fully static binary: no libc, no CGO — runs in scratch.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/auth-proxy \
    ./cmd/server

# Licence notices of what the image redistributes besides the service: the Go standard library compiled
# into the binary (BSD-3-Clause) and the Mozilla CA bundle copied below (MPL-2.0); the build fails if either
# cannot be produced. The project's own LICENSE (0BSD) is copied beside them.
RUN mkdir -p /out/doc && sh scripts/third-party-licenses.sh /out/doc/THIRD_PARTY_LICENSES && cp LICENSE /out/doc/LICENSE

# ── Runtime stage ─────────────────────────────────────────────────────────────
# scratch: zero OS footprint. The binary is fully self-contained.
FROM scratch

ARG VERSION=dev
ARG VENDOR="Meddleware"
ARG DESCRIPTION="Pre-authenticating reverse proxy for the CNCF Distribution registry (joxit UI backend)."
ARG SOURCE_URL="https://github.com/meddleware-org/registry-auth-proxy"
ARG DOCUMENTATION_URL="https://github.com/meddleware-org/registry-auth-proxy#readme"
ARG IMAGE_URL="https://quay.io/meddleware-org/registry-auth-proxy"

LABEL org.opencontainers.image.title="registry-auth-proxy" \
      org.opencontainers.image.description="${DESCRIPTION}" \
      org.opencontainers.image.url="${IMAGE_URL}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.documentation="${DOCUMENTATION_URL}" \
      org.opencontainers.image.vendor="${VENDOR}" \
      org.opencontainers.image.licenses="0BSD" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=builder /out/auth-proxy /auth-proxy
# CA bundle so the proxy can dial HTTPS token endpoints if ever configured;
# the in-cluster default (plain HTTP ClusterIP) does not require it.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Notices: BSD-3-Clause (Go standard library), MPL-2.0 (CA bundle), and the 0BSD licence of this service.
COPY --from=builder /out/doc/ /usr/share/doc/registry-auth-proxy/

# Non-root nobody: the binary needs no filesystem writes and no privileges.
USER 65534:65534

EXPOSE 8181

ENV PORT=8181

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/auth-proxy", "-healthcheck"]

ENTRYPOINT ["/auth-proxy"]
