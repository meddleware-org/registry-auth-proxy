package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meddleware-org/registry-auth-proxy/internal/token"
)

func TestParseBearerChallenge(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		wantService string
		wantScope   string
	}{
		{
			name:        "full challenge",
			header:      `Bearer realm="https://token.example.com/token",service="reg.example.com",scope="repository:foo:pull"`,
			wantService: "reg.example.com",
			wantScope:   "repository:foo:pull",
		},
		{
			name:        "no scope directive",
			header:      `Bearer realm="https://token.example.com/token",service="reg.example.com"`,
			wantService: "reg.example.com",
			wantScope:   "",
		},
		{
			name:        "unquoted values",
			header:      `Bearer service=reg.example.com,scope=registry:catalog:*`,
			wantService: "reg.example.com",
			wantScope:   "registry:catalog:*",
		},
		{
			name:        "comma inside a quoted scope",
			header:      `Bearer realm="https://t/token",service="reg",scope="repository:foo:pull,push"`,
			wantService: "reg",
			wantScope:   "repository:foo:pull,push",
		},
		{
			name:        "space-separated scope list",
			header:      `Bearer service="reg",scope="repository:a:pull repository:b:pull"`,
			wantService: "reg",
			wantScope:   "repository:a:pull repository:b:pull",
		},
		{
			name:        "escaped quote and lowercase scheme",
			header:      `bearer service="re\"g",scope="registry:catalog:*"`,
			wantService: `re"g`,
			wantScope:   "registry:catalog:*",
		},
		{
			name:        "service text inside another parameter is not a directive",
			header:      `Bearer realm="https://t/token?service=evil,scope=repository:x:push",service="reg"`,
			wantService: "reg",
			wantScope:   "",
		},
		{
			name:        "non-bearer challenge",
			header:      `Basic realm="registry"`,
			wantService: "",
			wantScope:   "",
		},
		{
			name:        "empty",
			header:      "",
			wantService: "",
			wantScope:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, scope := parseBearerChallenge(tt.header)
			if service != tt.wantService || scope != tt.wantScope {
				t.Errorf("parseBearerChallenge(%q) = (%q, %q), want (%q, %q)",
					tt.header, service, scope, tt.wantService, tt.wantScope)
			}
		})
	}
}

func TestIsHopByHop(t *testing.T) {
	for _, h := range []string{"Connection", "connection", "Transfer-Encoding", "Upgrade"} {
		if !isHopByHop(h) {
			t.Errorf("isHopByHop(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"Content-Type", "Authorization", "Docker-Content-Digest"} {
		if isHopByHop(h) {
			t.Errorf("isHopByHop(%q) = true, want false", h)
		}
	}
}

// newTestHandler wires a Handler against a fake token service that always issues
// the given token, and the supplied upstream URL.
func newTestHandler(t *testing.T, upstreamURL, issueToken string) *Handler {
	t.Helper()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      issueToken,
			"expires_in": 300,
			"issued_at":  time.Now().UTC().Format(time.RFC3339),
		})
	}))
	t.Cleanup(tokenSrv.Close)

	cache := token.NewCache(30 * time.Second)
	fetcher := token.NewFetcher(tokenSrv.URL, "registry-browser", "secret")
	return NewHandler(upstreamURL, cache, fetcher)
}

// TestServeHTTP_HappyPath verifies the probe → 401 → fetch → retry flow: an
// unauthenticated probe is challenged, the proxy fetches a token, and the retry
// with the Bearer token succeeds. The client must never see the intermediate 401.
func TestServeHTTP_HappyPath(t *testing.T) {
	const goodToken = "good-token"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+goodToken {
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="https://token.example.com/token",service="reg",scope="repository:foo:pull"`)
			// Hop-by-hop header that must not reach the client.
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "keep-alive") // must be stripped
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tags":[]}`))
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, goodToken)

	req := httptest.NewRequest(http.MethodGet, "/v2/foo/tags/list", nil)
	// A stale client Authorization header must be stripped, not forwarded.
	req.Header.Set("Authorization", "Bearer stale-junk")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Connection"); got != "" {
		t.Errorf("Connection header leaked to client: %q", got)
	}
	if rec.Body.String() != `{"tags":[]}` {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// TestServeHTTP_RemapUnauthorized verifies that a 401 which persists after a
// valid token is attached (an authorization failure) is remapped to 403, so the
// browser UI does not display a login dialog.
func TestServeHTTP_RemapUnauthorized(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Always refuse, even with a token — simulates a lacking permission.
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="https://token.example.com/token",service="reg",scope="repository:foo:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, "any-token")

	req := httptest.NewRequest(http.MethodGet, "/v2/foo/manifests/sha256:abc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (remapped from upstream 401)", rec.Code)
	}
}

// TestServeHTTP_CacheHit verifies that once a token is cached for a predicted
// scope, a subsequent request is forwarded with the Bearer token directly and
// never triggers an unauthenticated probe.
func TestServeHTTP_CacheHit(t *testing.T) {
	const goodToken = "cached-token"
	var probes int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			probes++
			w.Header().Set("WWW-Authenticate",
				`Bearer realm="https://token.example.com/token",service="reg",scope="registry:catalog:*"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, goodToken)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
	}
	// Only the first request should have probed unauthenticated.
	if probes != 1 {
		t.Errorf("unauthenticated probes = %d, want 1 (subsequent requests should hit the cache)", probes)
	}
}

// TestServeHTTP_DoesNotFollowUpstreamRedirect verifies the handler returns an upstream 3xx verbatim
// instead of following its Location (CheckRedirect → http.ErrUseLastResponse). The registry does not
// redirect on proxied paths, so an unexpected redirect must never be chased to another origin.
func TestServeHTTP_DoesNotFollowUpstreamRedirect(t *testing.T) {
	var evilHit bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		evilHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer evil.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", evil.URL)
		w.WriteHeader(http.StatusFound) // 302
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, "any-token")
	req := httptest.NewRequest(http.MethodGet, "/v2/foo/tags/list", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect returned verbatim, not followed)", rec.Code)
	}
	if evilHit {
		t.Fatal("handler followed the upstream redirect — CheckRedirect not enforced")
	}
}

// TestServeHTTP_TokenFailureIsBadGateway verifies the fail-closed path: when the token
// service refuses, the client gets 502 — never the upstream's 401, which would make the
// browser UI prompt for a login — and the upstream is not retried without a token.
func TestServeHTTP_TokenFailureIsBadGateway(t *testing.T) {
	probes := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes++
		w.Header().Set("WWW-Authenticate", `Bearer realm="https://token.example.com/token",service="reg",scope="repository:foo:pull"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer tokenSrv.Close()

	h := NewHandler(upstream.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "registry-browser", "secret"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/foo/tags/list", nil))

	if rec.Code != http.StatusBadGateway || rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("status = %d, WWW-Authenticate = %q; want 502 without a challenge", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	if probes != 1 {
		t.Errorf("upstream called %d times, want only the probe", probes)
	}
}

// TestServeHTTP_OnlyGetAndHead verifies every other method is refused with 405 before the
// upstream or the token service is contacted.
func TestServeHTTP_OnlyGetAndHead(t *testing.T) {
	var upstreamHits, tokenHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamHits.Add(1) }))
	defer upstream.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { tokenHits.Add(1) }))
	defer tokenSrv.Close()
	h := NewHandler(upstream.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "registry-browser", "secret"))

	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/v2/foo/blobs/uploads/x", strings.NewReader("data")))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: status = %d, Allow = %q; want 405 with Allow: GET, HEAD", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if upstreamHits.Load() != 0 || tokenHits.Load() != 0 {
		t.Errorf("upstream hit %d times, token service %d times; want neither", upstreamHits.Load(), tokenHits.Load())
	}
}

// TestServeHTTP_HeadIsForwarded verifies HEAD (used for manifest and blob existence checks) works.
func TestServeHTTP_HeadIsForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead || r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer service="reg",scope="repository:foo:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Docker-Content-Digest", "sha256:abc")
	}))
	defer upstream.Close()
	h := newTestHandler(t, upstream.URL, "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/v2/foo/manifests/latest", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Docker-Content-Digest") != "sha256:abc" {
		t.Errorf("status = %d, digest = %q", rec.Code, rec.Header().Get("Docker-Content-Digest"))
	}
}

// TestServeHTTP_RefusesNonReadChallenge verifies a challenge for push, delete, a wildcard or a
// malformed scope is answered 403 and never reaches the token service.
func TestServeHTTP_RefusesNonReadChallenge(t *testing.T) {
	for _, scope := range []string{
		"repository:foo:push",
		"repository:foo:pull,push",
		"repository:foo:delete",
		"repository:foo:*",
		"repository:foo:pull repository:bar:push",
		"registry:admin:*",
		"repository:foo",
	} {
		t.Run(scope, func(t *testing.T) {
			var tokenHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("WWW-Authenticate", `Bearer service="reg",scope="`+scope+`"`)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer upstream.Close()
			tokenSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { tokenHits.Add(1) }))
			defer tokenSrv.Close()
			h := NewHandler(upstream.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "registry-browser", "secret"))

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/foo/tags/list", nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
			if tokenHits.Load() != 0 {
				t.Error("the token service was asked for a non-read scope")
			}
		})
	}
}

// TestServeHTTP_TokenCachedOnlyUnderIssuedScope is the poisoning regression: the registry challenges
// a request for scope A, the token issued is for A, and a later request that PREDICTS scope B (a
// different resource) must not be served A's token.
func TestServeHTTP_TokenCachedOnlyUnderIssuedScope(t *testing.T) {
	var issued []string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		issued = append(issued, scope)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "token-for:" + scope, "expires_in": 300})
	}))
	defer tokenSrv.Close()

	var seen []string
	var probes int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			probes++
			// Whatever is asked for, the registry challenges for repository:a — a challenge
			// scope that differs from the one predicted from the path.
			w.Header().Set("WWW-Authenticate", `Bearer service="reg",scope="repository:a:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		seen = append(seen, r.URL.Path+" "+auth)
	}))
	defer upstream.Close()

	h := NewHandler(upstream.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "registry-browser", "secret"))
	get := func(path string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", path, rec.Code)
		}
	}
	get("/v2/b/tags/list") // predicted scope repository:b:pull, challenged (and issued) repository:a:pull
	get("/v2/b/tags/list") // must NOT hit the cache under the predicted key repository:b:pull
	get("/v2/a/tags/list") // predicted repository:a:pull — the scope actually issued — may reuse the token

	if len(issued) != 1 || issued[0] != "repository:a:pull" {
		t.Errorf("token requests = %v; want exactly one, for repository:a:pull", issued)
	}
	// Both /v2/b requests probed: the token was not cached under b's predicted key. The /v2/a request
	// predicted the scope the token was issued for and reused it without a probe.
	if probes != 2 {
		t.Errorf("unauthenticated probes = %d, want 2", probes)
	}
	for _, s := range seen {
		if strings.HasPrefix(s, "/v2/b/") && !strings.HasSuffix(s, "token-for:repository:a:pull") {
			t.Errorf("unexpected token on %q", s)
		}
	}
}

// TestServeHTTP_ConcurrentMissesShareOneTokenRequest verifies a burst of cold-cache requests for one
// scope costs one token request.
func TestServeHTTP_ConcurrentMissesShareOneTokenRequest(t *testing.T) {
	var tokenHits atomic.Int32
	release := make(chan struct{})
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenHits.Add(1)
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "tok", "expires_in": 300})
	}))
	defer tokenSrv.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer service="reg",scope="registry:catalog:*"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()
	h := NewHandler(upstream.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "registry-browser", "secret"))

	const n = 6
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
			codes[i] = rec.Code
		}()
	}
	time.Sleep(150 * time.Millisecond) // every request has probed and is waiting on the token
	close(release)
	wg.Wait()

	if tokenHits.Load() != 1 {
		t.Errorf("token service hit %d times, want 1", tokenHits.Load())
	}
	for i, c := range codes {
		if c != http.StatusOK {
			t.Errorf("request %d: status = %d", i, c)
		}
	}
}

// TestServeHTTP_RefusedTokenIsDropped verifies a cached token the registry rejects is evicted, so
// the next request fetches a fresh one instead of failing until the old one expires.
func TestServeHTTP_RefusedTokenIsDropped(t *testing.T) {
	var issuedCount atomic.Int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issuedCount.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": fmt.Sprintf("tok%d", n), "expires_in": 300})
	}))
	defer tokenSrv.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok2" {
			w.Header().Set("WWW-Authenticate", `Bearer service="reg",scope="repository:foo:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer upstream.Close()
	h := NewHandler(upstream.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "registry-browser", "secret"))

	codes := make([]int, 0, 2)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/foo/tags/list", nil))
		codes = append(codes, rec.Code)
	}
	// First request: tok1 is rejected (403). The cache entry is dropped, so the second fetches tok2.
	if codes[0] != http.StatusForbidden || codes[1] != http.StatusOK {
		t.Errorf("statuses = %v, want [403 200]", codes)
	}
}

func TestReadOnlyScope(t *testing.T) {
	for scope, want := range map[string]bool{
		"":                                    true,
		"registry:catalog:*":                  true,
		"repository:foo:pull":                 true,
		"repository:team/app:pull":            true,
		"repository:host:5000/app:pull":       true,
		"repository:a:pull repository:b:pull": true,
		"repository:foo:push":                 false,
		"repository:foo:pull,push":            false,
		"repository:foo:*":                    false,
		"repository::pull":                    false,
		"repository:foo":                      false,
		"registry:catalog:pull":               false,
		"registry:admin:*":                    false,
		"repository:a:pull repository:b:push": false,
		"something":                           false,
	} {
		if got := readOnlyScope(scope); got != want {
			t.Errorf("readOnlyScope(%q) = %v, want %v", scope, got, want)
		}
	}
}
