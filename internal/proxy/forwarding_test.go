package proxy

// The forwarding rules of the PROXY lens: which request fields reach the registry, which response
// fields reach the UI, loops, concurrency bounds, and what the logs may say about a failed upstream.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meddleware-org/registry-auth-proxy/internal/token"
)

// recordingUpstream answers 200 and records the request fields it received. When challenge is true it first
// demands a Bearer token the way the registry does.
func recordingUpstream(t *testing.T, respond func(http.Header)) (*httptest.Server, func() http.Header) {
	t.Helper()
	var mu sync.Mutex
	var last http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://t/token",service="reg",scope="registry:catalog:*"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		last = r.Header.Clone()
		mu.Unlock()
		if respond != nil {
			respond(w.Header())
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header { mu.Lock(); defer mu.Unlock(); return last }
}

// TestForward_RequestFieldPolicy checks which request fields reach the registry: the allowlisted ones pass, the caller's credentials and hop-by-hop fields never do.
func TestForward_RequestFieldPolicy(t *testing.T) {
	srv, got := recordingUpstream(t, nil)
	h := newTestHandler(t, srv.URL, "proxy-token")

	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
	// A request as a browser behind the edge might send it: its own credentials, a cookie, a Proxy-Authorization and a Connection header naming two more fields.
	req.Header.Set("Authorization", "Bearer client-supplied")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("Connection", "keep-alive, X-Secret-Hop, x-other")
	req.Header.Set("X-Secret-Hop", "leak")
	req.Header.Set("X-Other", "leak")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	// What the registry actually received, recorded by the upstream double.
	up := got()
	if auth := up.Values("Authorization"); len(auth) != 1 || auth[0] != "Bearer proxy-token" {
		t.Errorf("Authorization = %v, want only the proxy's own token (replaced, never appended)", auth)
	}
	// None of the caller's own secrets, nor the fields the Connection header named, may reach the registry.
	for _, name := range []string{"Cookie", "X-Secret-Hop", "X-Other", "Proxy-Authorization"} {
		if v := up.Get(name); v != "" {
			t.Errorf("%s reached the registry: %q", name, v)
		}
	}
	if up.Get("Accept") != "application/json" {
		t.Errorf("an ordinary field (Accept) was not forwarded")
	}
	// The proxy marks what it forwards so a request that loops back to it can be recognised (the next test).
	if via := up.Get("Via"); !strings.Contains(via, "registry-auth-proxy") {
		t.Errorf("Via = %q, want the proxy's loop marker", via)
	}
}

// TestForward_ResponseFieldPolicy checks the response fields the UI must not see (cookies, upstream CORS grants) are dropped.
func TestForward_ResponseFieldPolicy(t *testing.T) {
	srv, _ := recordingUpstream(t, func(h http.Header) {
		// An upstream response that tries to widen who may read it, set a cookie and leak an internal field through Connection.
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Set-Cookie", "a=b")
		h.Set("Connection", "X-Internal")
		h.Set("X-Internal", "topology")
		// Ordinary registry fields that the UI needs and that must pass through untouched.
		h.Set("Docker-Distribution-Api-Version", "registry/2.0")
		h.Set("Content-Type", "application/json")
	})
	h := newTestHandler(t, srv.URL, "t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))

	// The dropped fields must be absent from what the UI receives.
	for _, name := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Set-Cookie", "X-Internal", "Connection"} {
		if v := rec.Header().Get(name); v != "" {
			t.Errorf("%s reached the UI: %q", name, v)
		}
	}
	for _, name := range []string{"Docker-Distribution-Api-Version", "Content-Type"} {
		if rec.Header().Get(name) == "" {
			t.Errorf("%s was dropped; an ordinary registry field must pass", name)
		}
	}
}

// TestForward_LoopIsRefusedBeforeAnyUpstreamCall checks a request that would loop back through the proxy is refused before any upstream call is made.
func TestForward_LoopIsRefusedBeforeAnyUpstreamCall(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	h := newTestHandler(t, srv.URL, "t")
	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
	// A request that already carries the proxy's own Via marker came back through it.
	req.Header.Set("Via", "1.1 registry-auth-proxy")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// 508 Loop Detected, and the upstream was never contacted.
	if rec.Code != http.StatusLoopDetected || hits != 0 {
		t.Fatalf("status %d, upstream hits %d; want 508 and no upstream call", rec.Code, hits)
	}
}

// TestForward_ConcurrencyIsBounded checks no more than the configured number of requests are in flight at once, and that the rest are answered 503 instead of queueing.
func TestForward_ConcurrencyIsBounded(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, DefaultMaxInFlight+8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://t/token",service="reg",scope="registry:catalog:*"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		started <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	h := newTestHandler(t, srv.URL, "t")
	// Prime the token cache so every forward goes straight to the upstream and is held open there.
	// Prime the token cache so every forward holds the upstream open.
	h.cache.Set("registry:catalog:*", "t", time.Now().Add(time.Hour))

	var wg sync.WaitGroup
	for i := 0; i < DefaultMaxInFlight; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
		}()
	}
	for i := 0; i < DefaultMaxInFlight; i++ {
		select {
		// Wait until every held request has reached the upstream, so the bound is full before the next request.
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatal("forwards did not start")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	// Past the bound the proxy answers 503 with Retry-After instead of queueing (queued requests would hold memory).
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("request past the bound: status %d retry-after %q, want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	// Let the held requests finish; the slots must come back.
	close(release)
	wg.Wait()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("after the burst: status %d, want 200 (the bound must release)", rec.Code)
	}
}

// TestForward_UpstreamFailureLogsNoHostname checks a failing upstream is logged by its class only, never its hostname.
func TestForward_UpstreamFailureLogsNoHostname(t *testing.T) {
	buf := captureLog(t)

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstreamURL := srv.URL
	// The upstream is gone, so the forward fails; its address is exactly what must not leak.
	srv.Close() // unreachable
	h := newTestHandler(t, upstreamURL, "t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	// Neither the log nor the body may contain the upstream's host and port.
	host := strings.TrimPrefix(upstreamURL, "http://")
	if strings.Contains(buf.String(), host) || strings.Contains(rec.Body.String(), host) {
		t.Errorf("the upstream address leaked:\nlog: %s\nbody: %s", buf.String(), rec.Body.String())
	}
	if !strings.Contains(buf.String(), `"cause":"unreachable"`) {
		t.Errorf("the log lacks the failure class: %s", buf.String())
	}
}

// captureLog routes the default logger to a buffer for the duration of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestForward_EdgeFieldsAreNotForwarded: forwarding headers and the fields the edge adds (including the
// Cloudflare Access assertion, a bearer for the UI application) do not reach the registry (F18).
func TestForward_EdgeFieldsAreNotForwarded(t *testing.T) {
	srv, got := recordingUpstream(t, nil)
	h := newTestHandler(t, srv.URL, "proxy-token")

	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
	dropped := map[string]string{
		"X-Forwarded-For":                    "203.0.113.9",
		"X-Forwarded-Host":                   "registry-ui.example",
		"X-Forwarded-Proto":                  "https",
		"X-Forwarded-Port":                   "443",
		"Forwarded":                          "for=203.0.113.9;host=registry-ui.example",
		"X-Real-Ip":                          "203.0.113.9",
		"True-Client-Ip":                     "203.0.113.9",
		"Cdn-Loop":                           "cloudflare",
		"Cf-Access-Jwt-Assertion":            "eyJhbGciOi.access.assertion",
		"Cf-Access-Authenticated-User-Email": "user@example.com",
		"Cf-Connecting-Ip":                   "203.0.113.9",
		"Cf-Ray":                             "abc-LHR",
	}
	for k, v := range dropped {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Range", "bytes=0-9")
	req.Header.Set("User-Agent", "joxit")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	up := got()
	for k := range dropped {
		if v := up.Get(k); v != "" {
			t.Errorf("%s reached the registry: %q", k, v)
		}
	}
	for k, want := range map[string]string{"Accept": "application/json", "Range": "bytes=0-9", "User-Agent": "joxit"} {
		if up.Get(k) != want {
			t.Errorf("%s = %q, want %q (an ordinary field must be forwarded)", k, up.Get(k), want)
		}
	}
}

// TestForward_OnlyRegistryReadRoutes: a path that is not a canonical registry read route is answered
// without contacting the registry or the token service (F18).
func TestForward_OnlyRegistryReadRoutes(t *testing.T) {
	var upstreamHits, tokenHits int
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		tokenHits++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "t", "expires_in": 300})
	}))
	defer tokenSrv.Close()
	h := NewHandler(upstream.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "c", "s"))

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/", http.StatusNotFound},
		{"/metrics", http.StatusNotFound},
		{"/v2/token", http.StatusNotFound},
		{"/v2/foo/blobs/uploads/abc", http.StatusNotFound},
		{"/v2/Foo/tags/list", http.StatusNotFound},
		{"/v2//foo/tags/list", http.StatusBadRequest},
		{"/v2/foo/./tags/list", http.StatusBadRequest},
		{"/v2/foo/../bar/tags/list", http.StatusBadRequest},
		{"/v2/_catalog/", http.StatusBadRequest},
		{"/v2/foo%2F..%2Fbar/tags/list", http.StatusBadRequest}, // an encoded traversal decodes to ..
		{"/v2/foo%00/tags/list", http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("GET %q: status %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
	if upstreamHits != 0 || tokenHits != 0 {
		t.Errorf("upstream hits %d, token hits %d; want none for refused paths", upstreamHits, tokenHits)
	}

	// An allowed route still goes through, and the registry receives exactly the path that was checked.
	var seen string
	up2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer up2.Close()
	h2 := NewHandler(up2.URL, token.NewCache(30*time.Second), token.NewFetcher(tokenSrv.URL, "c", "s"))
	rec := httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/org/app/manifests/sha256:abc123?x=1", nil))
	if rec.Code != http.StatusOK || seen != "/v2/org/app/manifests/sha256:abc123" {
		t.Errorf("allowed route: status %d, upstream path %q", rec.Code, seen)
	}
}

// TestForward_TokenFailureLogsClassWithoutEndpoint: a token-fetch failure is logged by class (and the
// status the token service answered with), never with the error text, which names the token endpoint, an
// internal host (F17). The client sees only the fixed 502 body.
func TestForward_TokenFailureLogsClassWithoutEndpoint(t *testing.T) {
	up, _ := recordingUpstream(t, nil)

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unavailable.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer garbage.Close()

	for _, tc := range []struct {
		name      string
		endpoint  string
		wantCause string
		wantExtra string
	}{
		{"endpoint unreachable", closedURL + "/token", `"cause":"unreachable"`, ""},
		{"endpoint answers 503", unavailable.URL + "/token", `"cause":"status"`, `"status":503`},
		{"endpoint answers garbage", garbage.URL + "/token", `"cause":"malformed"`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLog(t)
			h := NewHandler(up.URL, token.NewCache(30*time.Second), token.NewFetcher(tc.endpoint, "registry-browser", "s3cret-value"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
			if rec.Code != http.StatusBadGateway || strings.TrimSpace(rec.Body.String()) != "auth service error" {
				t.Fatalf("status %d body %q, want 502 auth service error", rec.Code, rec.Body.String())
			}
			logged := buf.String()
			if !strings.Contains(logged, "token fetch error") || !strings.Contains(logged, tc.wantCause) || !strings.Contains(logged, tc.wantExtra) {
				t.Errorf("log lacks the failure class: %s", logged)
			}
			host := strings.TrimPrefix(strings.TrimSuffix(tc.endpoint, "/token"), "http://")
			for _, leaked := range []string{host, "/token", "service=", "s3cret-value", "Basic "} {
				if strings.Contains(logged, leaked) || strings.Contains(rec.Body.String(), leaked) {
					t.Errorf("%q leaked:\nlog: %s\nbody: %s", leaked, logged, rec.Body.String())
				}
			}
		})
	}
}

// TestForward_NoCredentialReachesAForeignRedirectTarget: when the registry answers the credentialed request
// with a redirect, the redirect is returned to the caller and never followed, so the Bearer token cannot be
// sent to the Location's host (audit F4, the credentialed leg).
func TestForward_NoCredentialReachesAForeignRedirectTarget(t *testing.T) {
	var foreignHits atomic.Int32
	var foreignAuth atomic.Value
	foreign := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		foreignAuth.Store(r.Header.Get("Authorization"))
	}))
	defer foreign.Close()

	var credentialed atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://t/token",service="reg",scope="registry:catalog:*"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		credentialed.Add(1)
		http.Redirect(w, r, foreign.URL+"/steal", http.StatusFound)
	}))
	defer registry.Close()

	h := newTestHandler(t, registry.URL, "secret-bearer")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if credentialed.Load() != 1 {
		t.Fatalf("the credentialed leg was not exercised (%d requests)", credentialed.Load())
	}
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), foreign.URL) {
		t.Errorf("status %d location %q; the redirect must be returned unchanged", rec.Code, rec.Header().Get("Location"))
	}
	if foreignHits.Load() != 0 {
		t.Errorf("the redirect target received %d requests (Authorization %q)", foreignHits.Load(), foreignAuth.Load())
	}
}
