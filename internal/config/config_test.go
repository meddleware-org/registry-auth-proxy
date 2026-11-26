// Tests for configuration loading: required variables, URL validation (and that a rejected URL is never repeated), the secret file, and the refresh margin.

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateHTTPURL checks which values are accepted as an outbound URL: http and https with a host, and nothing else.
func TestValidateHTTPURL(t *testing.T) {
	// Addresses the in-cluster deployment really uses, plus a public https one.
	valid := []string{
		"http://registry.registry.svc.cluster.local:5000",
		"https://example.com/token",
		"http://localhost:8080/token",
	}
	for _, u := range valid {
		if err := validateHTTPURL("X", u); err != nil {
			t.Errorf("validateHTTPURL(%q) unexpected error: %v", u, err)
		}
	}

	// Every shape of mistake: empty, no scheme, wrong scheme, opaque, no host, missing scheme.
	invalid := []string{
		"",                 // empty
		"not-a-url",        // no scheme/host
		"ftp://host/x",     // wrong scheme
		"registry:5000",    // opaque, no host
		"http://",          // scheme but no host
		"://registry:5000", // missing scheme
	}
	for _, u := range invalid {
		if err := validateHTTPURL("X", u); err == nil {
			t.Errorf("validateHTTPURL(%q) expected error, got nil", u)
		}
	}
}

// TestLoadRejectsMalformedUpstreamURL checks Load fails fast on a bad UPSTREAM_URL and accepts a valid in-cluster http one.
func TestLoadRejectsMalformedUpstreamURL(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secret, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A helper that sets the three required variables, varying only UPSTREAM_URL.
	setEnv := func(t *testing.T, upstream string) {
		t.Setenv("UPSTREAM_URL", upstream)
		t.Setenv("TOKEN_ENDPOINT", "http://token-service.registry.svc.cluster.local:8080/token")
		t.Setenv("CLIENT_SECRET_FILE", secret)
	}

	t.Run("valid in-cluster http config loads", func(t *testing.T) {
		setEnv(t, "http://registry.registry.svc.cluster.local:5000")
		if _, err := Load(); err != nil {
			t.Fatalf("expected valid config to load, got %v", err)
		}
	})

	t.Run("malformed UPSTREAM_URL fails fast", func(t *testing.T) {
		setEnv(t, "ftp://nope")
		if _, err := Load(); err == nil {
			t.Fatal("expected Load to reject a non-http(s) UPSTREAM_URL")
		}
	})
}

// TestReadSecret checks the secret file is trimmed, must be non-empty and readable, and that the error names the path and never the content.
func TestReadSecret(t *testing.T) {
	// One directory for the secret files of the sub-cases.
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	if got, err := ReadSecret(write("ok", "  s3cr3t\n")); err != nil || got != "s3cr3t" {
		t.Errorf("ReadSecret = %q, %v; want the trimmed value", got, err)
	}
	for name, p := range map[string]string{
		"empty file":   write("empty", " \n\t"),
		"missing file": filepath.Join(dir, "absent"),
		"directory":    dir,
	} {
		_, err := ReadSecret(p)
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// An error names the path, never the content.
	p := write("leaky", "")
	if _, err := ReadSecret(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("error %v should name the file", err)
	}
}

// TestLoadRecordsSecretFile checks Load keeps the secret file path, which the fetcher re-reads after a rotation.
func TestLoadRecordsSecretFile(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secret, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UPSTREAM_URL", "http://registry.registry.svc.cluster.local:5000")
	t.Setenv("TOKEN_ENDPOINT", "http://token-service.registry.svc.cluster.local:8080/token")
	t.Setenv("CLIENT_SECRET_FILE", secret)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecretFile != secret || cfg.ClientSecret != "s3cr3t" {
		t.Errorf("SecretFile %q ClientSecret set=%v", cfg.SecretFile, cfg.ClientSecret != "")
	}
}

// TestURLErrorsNeverEchoTheValue checks a rejected URL is named by its variable only: values carrying a user name,
// password, path token and query key (including ones that parse with a secret-looking scheme) must reach no part of
// the error, which is logged.
func TestURLErrorsNeverEchoTheValue(t *testing.T) {
	for _, raw := range []string{
		"ftp://user:s3cret@host.example/tok3n?key=k3y",
		"s3cret:pw@host.example",
		"https://user:s3cret@",
		"https://us:s3cret@[::1",
	} {
		err := validateHTTPURL("UPSTREAM_URL", raw)
		if err == nil {
			t.Fatalf("validateHTTPURL(%q): want an error", raw)
		}
		for _, part := range []string{"user", "s3cret", "host.example", "tok3n", "k3y", "pw@", "ftp"} {
			if strings.Contains(err.Error(), part) {
				t.Errorf("error %q repeats %q", err, part)
			}
		}
		if !strings.Contains(err.Error(), "UPSTREAM_URL") {
			t.Errorf("error %q does not name the variable", err)
		}
	}
}

// TestLoadRejectsNegativeRefreshMargin checks a negative TOKEN_REFRESH_MARGIN is refused instead of making every token look fresh for longer than it lives.
func TestLoadRejectsNegativeRefreshMargin(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secret, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UPSTREAM_URL", "http://registry.registry.svc.cluster.local:5000")
	t.Setenv("TOKEN_ENDPOINT", "http://token-service.registry.svc.cluster.local:8080/token")
	t.Setenv("CLIENT_SECRET_FILE", secret)
	t.Setenv("TOKEN_REFRESH_MARGIN", "-5s")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "TOKEN_REFRESH_MARGIN") {
		t.Errorf("Load with a negative margin: got %v, want an error naming TOKEN_REFRESH_MARGIN", err)
	}
}
