package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meddleware-org/registry-auth-proxy/internal/config"
)

// serveOn starts srv on a loopback listener and returns its base URL.
func serveOn(t *testing.T, srv *http.Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

// TestServerLimits pins the server settings (audit F20): the request-header cap and the timeouts.
func TestServerLimits(t *testing.T) {
	srv := newServer(":8181", http.NotFoundHandler())
	if srv.MaxHeaderBytes != 32<<10 || srv.ReadHeaderTimeout != 10*time.Second || srv.IdleTimeout != 120*time.Second {
		t.Errorf("limits: max header %d, read-header %s, idle %s; want 32 KiB, 10s, 120s",
			srv.MaxHeaderBytes, srv.ReadHeaderTimeout, srv.IdleTimeout)
	}
	if srv.WriteTimeout != 0 || srv.ReadTimeout != 0 {
		t.Errorf("write timeout %s, read timeout %s; blob downloads must stream, so neither is set", srv.WriteTimeout, srv.ReadTimeout)
	}
}

// TestServerRefusesOversizeHeaders: a header block over 32 KiB is answered 431 and never reaches the
// handler; a block under the cap is served.
func TestServerRefusesOversizeHeaders(t *testing.T) {
	var reached int
	base := serveOn(t, newServer("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	})))

	get := func(valueLen int) int {
		req, _ := http.NewRequest(http.MethodGet, base+"/v2/_catalog", nil)
		req.Header.Set("X-Padding", strings.Repeat("a", valueLen))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("header of %d bytes: %v", valueLen, err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if got := get(16 << 10); got != http.StatusOK {
		t.Errorf("16 KiB header: status %d, want 200", got)
	}
	before := reached
	if got := get(40 << 10); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("40 KiB header: status %d, want 431", got)
	}
	if reached != before {
		t.Error("an oversize request reached the handler")
	}
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	handleHealth(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != `{"status":"ok"}` {
		t.Errorf("healthz: %d %q", rec.Code, rec.Body.String())
	}

	srv := httptest.NewServer(http.HandlerFunc(handleHealth))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	t.Setenv("PORT", u.Port())
	if code := healthCheck(); code != 0 {
		t.Errorf("healthCheck against a healthy server = %d, want 0", code)
	}
	srv.Close()
	if code := healthCheck(); code != 1 {
		t.Errorf("healthCheck with nothing listening = %d, want 1", code)
	}
}

// TestSecretRotationWithoutRestart runs the wired proxy end to end against a fake registry and a fake token
// service: after the token service starts accepting a new client secret and the mounted file changes, the
// next token request recovers by itself (audit F10), and the secret appears nowhere in the responses.
func TestSecretRotationWithoutRestart(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer issued" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="x",service="reg",scope="registry:catalog:*"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"repositories":[]}`))
	}))
	defer registry.Close()

	var accepted atomic.Value
	accepted.Store("old-secret")
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pass, ok := r.BasicAuth(); !ok || pass != accepted.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"token":"issued","expires_in":1}`)) // 1 s: shorter than the refresh margin below
	}))
	defer tokenSrv.Close()

	secretFile := filepath.Join(t.TempDir(), "client-secret")
	write := func(v string) {
		if err := os.WriteFile(secretFile, []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("old-secret")
	t.Setenv("UPSTREAM_URL", registry.URL)
	t.Setenv("TOKEN_ENDPOINT", tokenSrv.URL+"/token")
	t.Setenv("CLIENT_SECRET_FILE", secretFile)
	t.Setenv("TOKEN_REFRESH_MARGIN", "1h") // every token is already inside the margin: none is cached
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := serveOn(t, newServer("", newMux(cfg)))

	get := func() (int, string) {
		resp, err := http.Get(proxyURL + "/v2/_catalog")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := get(); code != http.StatusOK {
		t.Fatalf("before the rotation: status %d, want 200", code)
	}

	// Rotation: the token service now accepts only the new secret. Until the mounted file changes the
	// proxy fails closed.
	accepted.Store("new-secret")
	if code, body := get(); code != http.StatusBadGateway || strings.Contains(body, "secret") {
		t.Fatalf("rotated service, old file: status %d body %q, want a closed 502", code, body)
	}
	write("new-secret")
	if code, body := get(); code != http.StatusOK || strings.Contains(body, "secret") {
		t.Errorf("after the file changed: status %d body %q, want 200 without a restart", code, body)
	}
}

// TestWiredRoutePolicy runs the wired server against a counting registry: only canonical registry read
// routes reach it (audit F18). net/http's ServeMux answers 307 to the cleaned path for a raw path with an
// empty, "." or ".." segment before the proxy handler runs; the handler refuses the rest (a trailing slash,
// an encoded traversal, a path outside the registry API) itself.
func TestWiredRoutePolicy(t *testing.T) {
	var hits atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer registry.Close()
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1000)
		_, _ = w.Write([]byte(`{"token":"t","expires_in":300}`))
	}))
	defer tokenSrv.Close()

	secretFile := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secretFile, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UPSTREAM_URL", registry.URL)
	t.Setenv("TOKEN_ENDPOINT", tokenSrv.URL+"/token")
	t.Setenv("CLIENT_SECRET_FILE", secretFile)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	base := serveOn(t, newServer("", newMux(cfg)))
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	for path, want := range map[string]int{
		"//v2/_catalog":                http.StatusTemporaryRedirect,
		"/v2//foo/tags/list":           http.StatusTemporaryRedirect,
		"/v2/foo/./tags/list":          http.StatusTemporaryRedirect,
		"/v2/foo/../bar/tags/list":     http.StatusTemporaryRedirect,
		"/v2/_catalog/":                http.StatusBadRequest,
		"/v2/foo%2F..%2Fbar/tags/list": http.StatusBadRequest,
		"/v2/foo/blobs/uploads/abc":    http.StatusNotFound,
		"/metrics":                     http.StatusNotFound,
		"/":                            http.StatusNotFound,
		"/v2/Foo/tags/list":            http.StatusNotFound,
	} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET %s: status %d, want %d", path, resp.StatusCode, want)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("refused paths reached the registry or the token service (hit count %d)", n)
	}

	resp, err := client.Get(base + "/v2/foo/tags/list")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() == 0 {
		t.Errorf("an allowed route: status %d, hits %d; want 200 through the registry", resp.StatusCode, hits.Load())
	}
}
