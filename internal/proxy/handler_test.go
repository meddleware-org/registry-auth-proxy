package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			`Bearer realm="https://token.example.com/token",service="reg",scope="repository:foo:delete"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	h := newTestHandler(t, upstream.URL, "any-token")

	req := httptest.NewRequest(http.MethodDelete, "/v2/foo/manifests/sha256:abc", nil)
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
