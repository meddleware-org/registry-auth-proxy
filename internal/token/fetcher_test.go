package token

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func serve(t *testing.T, status int, body string, check func(*http.Request)) *Fetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewFetcher(srv.URL+"/token", "proxy", "s3cret")
}

// TestFetchSendsCredentialsAndScope verifies the request: Basic auth with the client
// credentials, the service and scope as query values, nothing else.
func TestFetchSendsCredentialsAndScope(t *testing.T) {
	f := serve(t, 200, `{"token":"t","expires_in":300}`, func(r *http.Request) {
		user, pass, ok := r.BasicAuth()
		q := r.URL.Query()
		if !ok || user != "proxy" || pass != "s3cret" || q.Get("service") != "registry.example" ||
			q.Get("scope") != "repository:org/app:pull" || r.URL.Path != "/token" {
			t.Errorf("request: user=%q service=%q scope=%q path=%q", user, q.Get("service"), q.Get("scope"), r.URL.Path)
		}
	})
	tok, exp, err := f.Fetch(context.Background(), "registry.example", "repository:org/app:pull")
	if err != nil || tok != "t" {
		t.Fatalf("got %q %v", tok, err)
	}
	if d := time.Until(exp); d < 295*time.Second || d > 300*time.Second {
		t.Errorf("expiry in %s, want about 300 s", d)
	}
}

// TestFetchFailsClosed verifies every unusable answer is an error (the handler answers 502).
func TestFetchFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"unauthorized", 401, `{"error":"invalid credentials"}`, "returned 401"},
		{"unavailable", 503, ``, "returned 503"},
		{"malformed", 200, `{"token":`, "parse token response"},
		{"empty token", 200, `{"expires_in":60}`, "empty token"},
		{"oversized", 200, `{"token":"` + strings.Repeat("a", 70<<10) + `"}`, "parse token response"},
	}
	for _, c := range cases {
		_, _, err := serve(t, c.status, c.body, nil).Fetch(context.Background(), "s", "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: error leaks the client secret", c.name)
		}
	}
}

// TestFetchExpiry verifies the spec default for a missing lifetime and that a token
// service clock running ahead cannot extend the cached lifetime.
func TestFetchExpiry(t *testing.T) {
	_, exp, err := serve(t, 200, `{"token":"t"}`, nil).Fetch(context.Background(), "s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 55*time.Second || d > 60*time.Second {
		t.Errorf("missing expires_in: expiry in %s, want about 60 s", d)
	}

	ahead := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	_, exp, err = serve(t, 200, `{"token":"t","expires_in":300,"issued_at":"`+ahead+`"}`, nil).Fetch(context.Background(), "s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d > 300*time.Second {
		t.Errorf("clock ahead: expiry in %s, want at most 300 s", d)
	}

	behind := time.Now().Add(-100 * time.Second).UTC().Format(time.RFC3339)
	_, exp, err = serve(t, 200, `{"token":"t","expires_in":300,"issued_at":"`+behind+`"}`, nil).Fetch(context.Background(), "s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d > 205*time.Second || d < 195*time.Second {
		t.Errorf("issued 100 s ago: expiry in %s, want about 200 s", d)
	}
}

// TestFetchErrorsCarryNoEndpoint: every failure is a *FetchError with a class, and its text names neither
// the token endpoint nor the secret, so a caller that logs the error cannot leak the internal host (F17).
func TestFetchErrorsCarryNoEndpoint(t *testing.T) {
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	stalled := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stalled:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(stalled)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	timedOut, cancelTimeout := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelTimeout()

	cases := []struct {
		name  string
		f     *Fetcher
		ctx   context.Context
		class string
		code  int
	}{
		{"unreachable", NewFetcher(closedURL+"/token", "c", "s3cret"), context.Background(), "unreachable", 0},
		{"canceled", NewFetcher(slow.URL+"/token", "c", "s3cret"), cancelled, "canceled", 0},
		{"timeout", NewFetcher(slow.URL+"/token", "c", "s3cret"), timedOut, "timeout", 0},
		{"status", serve(t, 503, "", nil), context.Background(), "status", 503},
		{"malformed", serve(t, 200, "{", nil), context.Background(), "malformed", 0},
		{"empty token", serve(t, 200, "{}", nil), context.Background(), "malformed", 0},
	}
	for _, c := range cases {
		_, _, err := c.f.Fetch(c.ctx, "svc", "repository:a:pull")
		var fe *FetchError
		if !errors.As(err, &fe) {
			t.Errorf("%s: %T %v is not a *FetchError", c.name, err, err)
			continue
		}
		if got := FailureClass(err); got != c.class {
			t.Errorf("%s: class %q, want %q", c.name, got, c.class)
		}
		if got := FailureStatus(err); got != c.code {
			t.Errorf("%s: status %d, want %d", c.name, got, c.code)
		}
		for _, leaked := range []string{"127.0.0.1", "localhost", "/token", "service=", "s3cret", "http://"} {
			if strings.Contains(err.Error(), leaked) {
				t.Errorf("%s: error text %q contains %q", c.name, err.Error(), leaked)
			}
		}
	}
	if FailureClass(errors.New("x")) != "unknown" || FailureStatus(errors.New("x")) != 0 {
		t.Error("a foreign error must classify as unknown with no status")
	}
	// The transport cause stays reachable for errors.Is.
	_, _, err := cases[1].f.Fetch(cancelled, "svc", "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false for %v", err)
	}
}

// rotatingService is a token service that accepts exactly one client secret, which a test can change.
type rotatingService struct {
	srv      *httptest.Server
	accepted atomic.Value // string
	calls    atomic.Int32
}

func newRotatingService(t *testing.T, accepted string) *rotatingService {
	t.Helper()
	rs := &rotatingService{}
	rs.accepted.Store(accepted)
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.calls.Add(1)
		if _, pass, ok := r.BasicAuth(); !ok || pass != rs.accepted.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"t","expires_in":300}`))
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestFetchRereadsRotatedSecret: after a rotation the token service refuses the old secret (401); the
// fetcher reads the secret file again and retries once with the new value, so no restart is needed (F10).
func TestFetchRereadsRotatedSecret(t *testing.T) {
	logs := captureSlog(t)
	rs := newRotatingService(t, "old-secret")
	var reads atomic.Int32
	file := "old-secret"
	var fileMu sync.Mutex
	f := NewFetcher(rs.srv.URL, "c", "old-secret").WithSecretReload(func() (string, error) {
		reads.Add(1)
		fileMu.Lock()
		defer fileMu.Unlock()
		return file, nil
	})

	if _, _, err := f.Fetch(context.Background(), "s", ""); err != nil {
		t.Fatalf("before the rotation: %v", err)
	}
	if reads.Load() != 0 {
		t.Fatalf("the file was read %d times on a successful fetch; it must be read only after a refusal", reads.Load())
	}

	// Rotation: the service accepts the new secret; the mounted file is updated.
	rs.accepted.Store("new-secret")
	fileMu.Lock()
	file = "new-secret"
	fileMu.Unlock()
	rs.calls.Store(0)
	if _, _, err := f.Fetch(context.Background(), "s", ""); err != nil {
		t.Fatalf("after the rotation: %v", err)
	}
	if reads.Load() != 1 || rs.calls.Load() != 2 {
		t.Errorf("file reads %d, token requests %d; want 1 read and 2 requests (refused, then retried)", reads.Load(), rs.calls.Load())
	}

	// The new secret is now the one in use: the next fetch needs neither a read nor a retry.
	rs.calls.Store(0)
	if _, _, err := f.Fetch(context.Background(), "s", ""); err != nil || reads.Load() != 1 || rs.calls.Load() != 1 {
		t.Errorf("next fetch: err %v, reads %d, requests %d; want success on the first request", err, reads.Load(), rs.calls.Load())
	}
	if out := logs.String(); strings.Contains(out, "old-secret") || strings.Contains(out, "new-secret") {
		t.Errorf("a secret value reached the log: %s", out)
	}
}

// TestFetchRotationFailsClosed: a reload that cannot help leaves the original failure, and is attempted
// at most once per fetch.
func TestFetchRotationFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		reload func() (string, error)
		reads  int32
	}{
		{"file unchanged", func() (string, error) { return "wrong", nil }, 1},
		{"file unreadable", func() (string, error) { return "", errors.New("open /etc/secret: permission denied") }, 1},
		{"no reload configured", nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logs := captureSlog(t)
			rs := newRotatingService(t, "right")
			var reads atomic.Int32
			f := NewFetcher(rs.srv.URL, "c", "wrong")
			if c.reload != nil {
				f.WithSecretReload(func() (string, error) { reads.Add(1); return c.reload() })
			}
			_, _, err := f.Fetch(context.Background(), "s", "")
			if FailureStatus(err) != 401 {
				t.Fatalf("got %v, want the 401 failure", err)
			}
			if reads.Load() != c.reads {
				t.Errorf("file reads %d, want %d", reads.Load(), c.reads)
			}
			if wantCalls := int32(1); rs.calls.Load() != wantCalls {
				t.Errorf("token requests %d, want %d (a reload that changes nothing is not retried)", rs.calls.Load(), wantCalls)
			}
			if out := logs.String(); strings.Contains(out, "wrong") || strings.Contains(out, "right") || strings.Contains(out, "/etc/secret") {
				t.Errorf("secret or file detail reached the log: %s", out)
			}
		})
	}
}

// TestFetchOtherFailuresDoNotReload: only a 401 triggers a re-read; a 5xx or a transport failure does not.
func TestFetchOtherFailuresDoNotReload(t *testing.T) {
	var reads atomic.Int32
	f := serve(t, 503, "", nil).WithSecretReload(func() (string, error) { reads.Add(1); return "x", nil })
	if _, _, err := f.Fetch(context.Background(), "s", ""); FailureStatus(err) != 503 {
		t.Fatalf("got %v", err)
	}
	if reads.Load() != 0 {
		t.Errorf("a 503 caused %d secret reads", reads.Load())
	}
}

// TestFetchConcurrentRotation: concurrent fetches across a rotation all end up succeeding, race-free.
func TestFetchConcurrentRotation(t *testing.T) {
	rs := newRotatingService(t, "new")
	f := NewFetcher(rs.srv.URL, "c", "old").WithSecretReload(func() (string, error) { return "new", nil })
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := f.Fetch(context.Background(), "s", ""); err != nil {
				t.Errorf("fetch across a rotation: %v", err)
			}
		}()
	}
	wg.Wait()
}
