// Package config loads and validates the proxy's runtime configuration from
// environment variables. The one credential — the registry-browser client
// secret — is read from the file named by CLIENT_SECRET_FILE and is never
// accepted as an environment variable, so it can be mounted from a Kubernetes
// Secret without appearing in the process environment.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds validated runtime configuration. The client secret is loaded
// from CLIENT_SECRET_FILE and never exposed as an environment variable.
type Config struct {
	Port          string
	UpstreamURL   string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	RefreshMargin time.Duration
	LogLevel      string
}

// Load reads configuration from the environment and returns a validated Config.
//
// Required variables (an error listing all that are absent is returned if any
// are unset): UPSTREAM_URL, TOKEN_ENDPOINT, CLIENT_SECRET_FILE. Optional
// variables fall back to defaults: PORT=8181, CLIENT_ID=registry-browser,
// LOG_LEVEL=info, TOKEN_REFRESH_MARGIN=30s. The client secret is read from the
// CLIENT_SECRET_FILE path and must be non-empty; TOKEN_REFRESH_MARGIN must parse
// as a time.Duration; UPSTREAM_URL has any trailing slash trimmed.
func Load() (*Config, error) {
	var missing []string

	require := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			missing = append(missing, name)
		}
		return v
	}

	envOr := func(name, def string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return def
	}

	cfg := &Config{
		Port:          envOr("PORT", "8181"),
		UpstreamURL:   require("UPSTREAM_URL"),
		TokenEndpoint: require("TOKEN_ENDPOINT"),
		ClientID:      envOr("CLIENT_ID", "registry-browser"),
		LogLevel:      envOr("LOG_LEVEL", "info"),
	}

	secretFile := require("CLIENT_SECRET_FILE")

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	raw, err := os.ReadFile(secretFile)
	if err != nil {
		return nil, fmt.Errorf("read CLIENT_SECRET_FILE %q: %w", secretFile, err)
	}
	cfg.ClientSecret = strings.TrimSpace(string(raw))
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("CLIENT_SECRET_FILE %q is empty", secretFile)
	}

	marginStr := envOr("TOKEN_REFRESH_MARGIN", "30s")
	margin, err := time.ParseDuration(marginStr)
	if err != nil {
		return nil, fmt.Errorf("parse TOKEN_REFRESH_MARGIN %q: %w", marginStr, err)
	}
	cfg.RefreshMargin = margin

	// Trim trailing slash from upstream URL to keep path joining consistent.
	cfg.UpstreamURL = strings.TrimRight(cfg.UpstreamURL, "/")

	return cfg, nil
}
