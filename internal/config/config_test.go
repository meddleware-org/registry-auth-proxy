package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateHTTPURL(t *testing.T) {
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

func TestLoadRejectsMalformedUpstreamURL(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secret, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
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

func TestReadSecret(t *testing.T) {
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
