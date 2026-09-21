package config

import (
	"os"
	"path/filepath"
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
