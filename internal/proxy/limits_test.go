package proxy

// Tests of the forwarding limits (audit F20): the upstream deadlines and the in-flight bound, exercised
// against local servers that stall. The tests build a Handler with short limits (newHandler); the
// production values are pinned separately by TestDefaultLimits. None waits for a production-sized
// deadline, and the stalling upstreams are released when the test ends.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meddleware-org/registry-auth-proxy/internal/token"
)

const catalogScope = "registry:catalog:*"

func TestDefaultLimits(t *testing.T) {
	lim := defaultLimits()
	if lim.dialTimeout != 5*time.Second || lim.responseHeaderTimeout != 30*time.Second || lim.maxInFlight != 64 {
		t.Errorf("defaultLimits() = %+v, want dial 5s, response-header 30s, 64 in flight", lim)
	}
	if DefaultMaxInFlight != 64 {
		t.Errorf("DefaultMaxInFlight = %d, want 64", DefaultMaxInFlight)
	}

	h := NewHandler("http://registry.invalid:5000", token.NewCache(30*time.Second), token.NewFetcher("http://t.invalid/token", "c", "s"))
	if cap(h.inflight) != 64 {
		t.Errorf("NewHandler in-flight bound = %d, want 64", cap(h.inflight))
	}
	tr, ok := h.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", h.client.Transport)
	}
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("NewHandler response-header deadline = %s, want 30s", tr.ResponseHeaderTimeout)
	}
	if tr.Proxy != nil {
		t.Error("the upstream transport must not use an environment proxy")
	}
	if h.client.Timeout != 0 {
		t.Errorf("client has a total deadline of %s; blob downloads must stream", h.client.Timeout)
	}
}

// stallingUpstream answers 401 to an unauthenticated probe like the registry, and for an authenticated
// request waits (never writing headers) until the test releases it, unless it has been told to answer.
type stallingUpstream struct {
	srv     *httptest.Server
	answer  atomic.Bool // when true, authenticated requests get an immediate 200
	release chan struct{}
	once    sync.Once
	stalled atomic.Int32
}

// free lets every stalled handler return.
func (u *stallingUpstream) free() { u.once.Do(func() { close(u.release) }) }

func newStallingUpstream(t *testing.T, stallProbe bool) *stallingUpstream {
	t.Helper()
	u := &stallingUpstream{release: make(chan struct{})}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := r.Header.Get("Authorization") != ""
		if !authed && !stallProbe {
			w.Header().Set("WWW-Authenticate", `Bearer realm="https://t/token",service="reg",scope="`+catalogScope+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !u.answer.Load() {
			u.stalled.Add(1)
			select {
			case <-u.release:
			case <-r.Context().Done():
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	// Cleanups run last-in-first-out: release the stalled handlers before the server waits for them.
	t.Cleanup(u.srv.Close)
	t.Cleanup(u.free)
	return u
}

func shortLimits() limits {
	return limits{dialTimeout: time.Second, responseHeaderTimeout: 200 * time.Millisecond, maxInFlight: 1}
}

// A registry that accepts the connection but never sends response headers ends in 502, class timeout, at the
// response-header deadline, and the in-flight slot is released (the bound here is 1, so the follow-up
// request can only succeed if the slot came back). Both legs are covered: the credentialed forward on a
// cache hit, and the unauthenticated probe on a miss.
func TestLimits_StalledUpstreamEndsInBadGatewayAndReleasesSlot(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stallProbe bool
		primed     bool
		logLine    string
	}{
		{"credentialed forward", false, true, "upstream error"},
		{"probe", true, false, "upstream probe error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLog(t)
			up := newStallingUpstream(t, tc.stallProbe)
			h := newTestHandlerLimits(t, up.srv.URL, "t", shortLimits())
			if tc.primed {
				h.cache.Set(catalogScope, "t", time.Now().Add(time.Hour))
			}

			start := time.Now()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
			elapsed := time.Since(start)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("stalled upstream: status %d, want 502", rec.Code)
			}
			if elapsed < 150*time.Millisecond || elapsed > 5*time.Second {
				t.Errorf("answered after %s; want about the 200 ms response-header deadline", elapsed)
			}
			if !strings.Contains(buf.String(), `"cause":"timeout"`) || !strings.Contains(buf.String(), tc.logLine) {
				t.Errorf("the log lacks %q with the timeout class: %s", tc.logLine, buf.String())
			}
			if host := strings.TrimPrefix(up.srv.URL, "http://"); strings.Contains(buf.String(), host) || strings.Contains(rec.Body.String(), host) {
				t.Errorf("the upstream address leaked:\nlog: %s\nbody: %s", buf.String(), rec.Body.String())
			}
			if n := len(h.inflight); n != 0 {
				t.Fatalf("%d in-flight slots still held after the timeout", n)
			}

			// The same handler (bound of 1) serves the next request once the registry answers.
			up.answer.Store(true)
			h.cache.Set(catalogScope, "t", time.Now().Add(time.Hour))
			rec = httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("after the timeout: status %d, want 200 (the slot must be released)", rec.Code)
			}
		})
	}
}

// There is no total deadline: a response whose headers arrive in time streams for as long as the registry
// keeps sending, even past the response-header deadline (blob downloads).
func TestLimits_SlowBodyStreamsPastTheHeaderDeadline(t *testing.T) {
	const chunks = 6
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for i := 0; i < chunks; i++ {
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte("chunk;"))
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	h := newTestHandlerLimits(t, srv.URL, "t", limits{dialTimeout: time.Second, responseHeaderTimeout: 200 * time.Millisecond, maxInFlight: 2})
	h.cache.Set(catalogScope, "t", time.Now().Add(time.Hour))

	start := time.Now()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if got := rec.Body.String(); rec.Code != http.StatusOK || got != strings.Repeat("chunk;", chunks) {
		t.Errorf("status %d, body %q; the full slow body must stream", rec.Code, got)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Errorf("the body took %s; the test did not outlast the header deadline", time.Since(start))
	}
}

// The in-flight bound is a property of the handler's limits, not only of the default constant: a bound of 2
// admits two stalled forwards and answers the third at once with 503 and Retry-After.
func TestLimits_InFlightBoundFollowsTheLimit(t *testing.T) {
	up := newStallingUpstream(t, false)
	h := newTestHandlerLimits(t, up.srv.URL, "t", limits{dialTimeout: time.Second, responseHeaderTimeout: 30 * time.Second, maxInFlight: 2})
	h.cache.Set(catalogScope, "t", time.Now().Add(time.Hour))

	done := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
			done <- rec.Code
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for up.stalled.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("the two forwards did not reach the upstream")
		}
		time.Sleep(5 * time.Millisecond)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/_catalog", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("third request: status %d retry-after %q, want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	// Let the registry answer: the two held forwards finish and the bound comes back.
	up.free()
	for i := 0; i < 2; i++ {
		select {
		case code := <-done:
			if code != http.StatusOK {
				t.Errorf("a released forward ended with %d, want 200", code)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a held forward did not finish")
		}
	}
	if n := len(h.inflight); n != 0 {
		t.Errorf("%d in-flight slots still held after the forwards finished", n)
	}
}
