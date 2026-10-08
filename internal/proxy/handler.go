// Package proxy implements the pre-authenticating reverse proxy that sits
// between joxit/docker-registry-ui and a CNCF Distribution registry.
//
// joxit cannot pre-store Bearer credentials for a token-authenticated registry;
// left to its own devices it prompts the operator for a username/password on
// first use. This proxy removes that prompt by owning the entire Bearer token
// dance on joxit's behalf:
//
//  1. Predict the OCI scope for the incoming request from its URL path
//     (see scope.go) and, on a cache hit, forward immediately with the cached
//     token — no extra round trip.
//  2. On a cache miss, probe the registry unauthenticated. Anything other than
//     401 is streamed straight back.
//  3. On 401, parse the registry's Bearer challenge, fetch a token from the
//     internal token service using the registry-browser client credentials,
//     cache it, and retry the original request with the token attached.
//
// Two properties keep joxit's login dialog from ever appearing:
//
//   - The proxy strips any inbound Authorization header, so stale credentials
//     in joxit's localStorage are never forwarded upstream.
//   - If a request is still 401 after a valid token was attached (for example a
//     delete attempt the read-only registry-browser identity is not granted),
//     the proxy remaps the status to 403 before responding. joxit treats 403 as
//     "not allowed" and does not prompt; a raw 401 would trigger the dialog.
//
// Hop-by-hop headers (RFC 7230 §6.1) are stripped in both directions so the
// proxied response is well-formed for joxit's nginx.
//
// The proxy is read-only by construction: only GET and HEAD are forwarded (anything else is 405
// before any token is requested), no request body is forwarded, and a token is requested only for
// pull and catalog scopes (see scope.go and challenge.go). A token is cached under exactly the scope
// it was issued for, never under a predicted alias.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/meddleware-org/registry-auth-proxy/internal/token"
)

// hopByHopHeaders are connection-scoped headers that must not be forwarded by an
// intermediary (RFC 7230 §6.1). Copying these upstream→client (notably
// Transfer-Encoding and Connection) can produce a malformed response, so they
// are dropped from both the outbound request and the returned response.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Handler is a pre-authenticating reverse proxy. It sits between joxit's nginx
// and the Distribution registry, transparently handling Bearer token auth so
// joxit never sees a 401 and never needs its own credentials dialog. A Handler
// is safe for concurrent use: its token cache is internally synchronised and it
// holds no per-request state.
type Handler struct {
	upstream *url.URL
	cache    *token.Cache
	fetcher  *token.Fetcher
	flight   token.Flight
	client   *http.Client
}

// NewHandler builds a Handler that proxies to upstreamURL, caching and fetching
// tokens via the supplied cache and fetcher. upstreamURL is assumed already
// validated by config.Load; a parse failure here yields a nil upstream, which
// surfaces as a 502 on the first request rather than a panic at construction.
// The HTTP client deliberately has no global timeout — per-request deadlines
// come from the inbound request context, which allows arbitrarily long blob
// downloads to stream without being cut off.
func NewHandler(upstreamURL string, cache *token.Cache, fetcher *token.Fetcher) *Handler {
	u, _ := url.Parse(upstreamURL) // already validated in config.Load
	return &Handler{
		upstream: u,
		cache:    cache,
		fetcher:  fetcher,
		client: &http.Client{
			// no global timeout; per-request context controls deadline
			// Do not follow upstream redirects: the registry is trusted and does not 3xx on the
			// proxied paths, so an unexpected redirect is returned verbatim (and remapped like any
			// other status) rather than silently followed to an attacker-influenced Location.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// ServeHTTP implements http.Handler. It runs the predict → (cache hit | probe →
// 401 → fetch → cache → retry) flow described in the package comment and streams
// the final response to w.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read-only: the browser UI only ever reads. Refuse everything else before touching the
	// token service, so a push or delete can never cause a token to be requested or cached.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Reject parent-directory traversal / out-of-bounds paths outright (defence-in-depth, F2).
	// joxit is read-only and only ever requests canonical /v2 paths, so a ".." segment is always
	// malformed; rejecting here keeps the predicted scope (and its cache key) honest.
	if _, ok := NormalizePath(r.URL.Path); !ok {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	predictedScope := PredictScope(r.URL.Path)

	// Cache hit: inject token and forward directly.
	if tok, ok := h.cache.Get(predictedScope); ok {
		slog.Debug("cache hit", "scope", predictedScope)
		h.proxyWithToken(w, r, tok, predictedScope)
		return
	}

	// Cache miss: probe upstream without auth.
	probeResp, err := h.roundTrip(r, "")
	if err != nil {
		slog.Error("upstream probe error", "path", r.URL.Path, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}

	if probeResp.StatusCode != http.StatusUnauthorized {
		// Not a 401 — pass through unchanged (200, 404, etc.).
		defer func() { _ = probeResp.Body.Close() }()
		copyResponse(w, probeResp)
		return
	}
	// Must drain and close before the retry.
	_, _ = io.Copy(io.Discard, probeResp.Body)
	_ = probeResp.Body.Close()

	// Parse the Bearer challenge from the 401.
	challenge := probeResp.Header.Get("WWW-Authenticate")
	service, challengeScope := parseBearerChallenge(challenge)

	// Prefer the scope the registry actually asked for; fall back to prediction.
	resolvedScope := challengeScope
	if resolvedScope == "" {
		resolvedScope = predictedScope
	}

	// Only ever ask for read access. A challenge for push/delete (or anything unrecognised) is
	// answered 403 without calling the token service: the browser identity is read-only anyway,
	// and this keeps the proxy from being the thing that requests broader tokens.
	if !readOnlyScope(resolvedScope) {
		slog.Warn("challenge scope refused", "scope", resolvedScope, "path", r.URL.Path)
		http.Error(w, "scope not permitted", http.StatusForbidden)
		return
	}

	slog.Debug("401 intercepted, fetching token", "scope", resolvedScope)

	tok, err := h.token(r.Context(), service, resolvedScope)
	if err != nil {
		// Fail closed: never surface a naked 401 to joxit, which would trigger
		// its login dialog. 502 signals an internal auth failure instead.
		slog.Error("token fetch error", "scope", resolvedScope, "err", err)
		http.Error(w, "auth service error", http.StatusBadGateway)
		return
	}

	// Retry the original request with the Bearer token.
	h.proxyWithToken(w, r, tok, resolvedScope)
}

// token returns a token for scope, from the cache or from the token service. Concurrent misses for
// the same service and scope share one request. The token is cached under the scope it was issued
// for and no other: a token for one scope must never be served for a path predicted to need another.
// The shared fetch runs detached from any one caller's context (the fetcher has its own timeout).
func (h *Handler) token(ctx context.Context, service, scope string) (string, error) {
	tok, _, err := h.flight.Do(service+"\x00"+scope, func() (string, time.Time, error) {
		if cached, ok := h.cache.Get(scope); ok {
			return cached, time.Time{}, nil
		}
		tok, expiry, err := h.fetcher.Fetch(context.WithoutCancel(ctx), service, scope)
		if err != nil {
			return "", time.Time{}, err
		}
		h.cache.Set(scope, tok, expiry)
		return tok, expiry, nil
	})
	return tok, err
}

// proxyWithToken forwards the request with a Bearer token and streams the
// response. Because a token was attached, a lingering 401 means the identity is
// authenticated but not authorized; it is remapped to 403 so joxit does not
// prompt for login (see the package comment).
func (h *Handler) proxyWithToken(w http.ResponseWriter, r *http.Request, tok, scope string) {
	resp, err := h.roundTrip(r, tok)
	if err != nil {
		slog.Error("upstream error", "path", r.URL.Path, "err", err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		// A valid token was attached yet the registry still refused: this is an
		// authorization failure, not an authentication one. Remap 401→403 so the
		// UI reports "forbidden" rather than popping a credentials dialog.
		slog.Info("upstream 401 with token attached; remapping to 403",
			"method", r.Method, "path", r.URL.Path)
		// The registry no longer accepts this token (revoked, or issued for a different resource
		// than its challenge names): drop it so the next request fetches a fresh one.
		h.cache.Delete(scope)
		resp.StatusCode = http.StatusForbidden
	}

	copyResponse(w, resp)
}

// roundTrip builds and executes one upstream HTTP request against the configured
// upstream. It forwards the inbound headers verbatim except that it strips any
// client-supplied Authorization header (the proxy owns that) and all hop-by-hop
// headers, then optionally injects a Bearer token. No request body is forwarded: only GET and HEAD
// reach this point.
func (h *Handler) roundTrip(r *http.Request, bearerToken string) (*http.Response, error) {
	target := *h.upstream
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), nil)
	if err != nil {
		return nil, err
	}

	// Forward headers verbatim except Authorization (we own it) and hop-by-hop
	// headers (must not cross an intermediary).
	for k, vv := range r.Header {
		if strings.EqualFold(k, "authorization") || isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	req.Host = h.upstream.Host

	return h.client.Do(req)
}

// copyResponse writes status, headers, and body from an upstream response to w,
// dropping hop-by-hop headers. The body is streamed (never fully buffered) so
// large blob downloads pass through with constant memory.
func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// isHopByHop reports whether header name is a connection-scoped hop-by-hop
// header that an intermediary must not forward. The comparison is
// case-insensitive.
func isHopByHop(name string) bool {
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}
