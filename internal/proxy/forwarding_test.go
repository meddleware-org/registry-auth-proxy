package proxy

// The forwarding rules of the PROXY lens: which request fields reach the registry, which response
// fields reach the UI, loops, concurrency bounds, and what the logs may say about a failed upstream.

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

func TestForward_RequestFieldPolicy(t *testing.T) {
	srv, got := recordingUpstream(t, nil)
	h := newTestHandler(t, srv.URL, "proxy-token")

	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
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

	up := got()
	if auth := up.Values("Authorization"); len(auth) != 1 || auth[0] != "Bearer proxy-token" {
		t.Errorf("Authorization = %v, want only the proxy's own token (replaced, never appended)", auth)
	}
	for _, name := range []string{"Cookie", "X-Secret-Hop", "X-Other", "Proxy-Authorization"} {
		if v := up.Get(name); v != "" {
			t.Errorf("%s reached the registry: %q", name, v)
		}
	}
	if up.Get("Accept") != "application/json" {
		t.Errorf("an ordinary field (Accept) was not forwarded")
	}
	if via := up.Get("Via"); !strings.Contains(via, "registry-auth-proxy") {
		t.Errorf("Via = %q, want the proxy's loop marker", via)
	}
}

func TestForward_ResponseFieldPolicy(t *testing.T) {
	srv, _ := recordingUpstream(t, func(h http.Header) {
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Set-Cookie", "a=b")
		h.Set("Connection", "X-Internal")
		h.Set("X-Internal", "topology")
		h.Set("Docker-Distribution-Api-Version", "registry/2.0")
		h.Set("Content-Type", "application/json")
	})
	h := newTestHandler(t, srv.URL, "t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))

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

func TestForward_LoopIsRefusedBeforeAnyUpstreamCall(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	h := newTestHandler(t, srv.URL, "t")
	req := httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil)
	req.Header.Set("Via", "1.1 registry-auth-proxy")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusLoopDetected || hits != 0 {
		t.Fatalf("status %d, upstream hits %d; want 508 and no upstream call", rec.Code, hits)
	}
}

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
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatal("forwards did not start")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("request past the bound: status %d retry-after %q, want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	close(release)
	wg.Wait()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("after the burst: status %d, want 200 (the bound must release)", rec.Code)
	}
}

func TestForward_UpstreamFailureLogsNoHostname(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstreamURL := srv.URL
	srv.Close() // unreachable
	h := newTestHandler(t, upstreamURL, "t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	host := strings.TrimPrefix(upstreamURL, "http://")
	if strings.Contains(buf.String(), host) || strings.Contains(rec.Body.String(), host) {
		t.Errorf("the upstream address leaked:\nlog: %s\nbody: %s", buf.String(), rec.Body.String())
	}
	if !strings.Contains(buf.String(), `"cause":"unreachable"`) {
		t.Errorf("the log lacks the failure class: %s", buf.String())
	}
}
