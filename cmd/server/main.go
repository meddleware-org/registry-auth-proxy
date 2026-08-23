// Command server runs the registry-auth-proxy: a pre-authenticating reverse
// proxy for the CNCF Distribution registry. It sits between
// joxit/docker-registry-ui and the Distribution registry, transparently handling
// Bearer token auth so the UI never prompts for credentials.
//
// For each request the proxy predicts the required scope, serves a cached token
// on a hit, or otherwise probes the registry, exchanges the resulting 401
// challenge for a token at the internal token service, caches it, and retries.
// See package internal/proxy for the full flow and the 401→403 hardening.
//
// The process also supports a "-healthcheck" argument used by the container
// HEALTHCHECK: it dials the local /healthz endpoint and exits 0 (healthy) or 1.
//
// Environment variables:
//
//	PORT                 — HTTP listen port (default: 8181)
//	UPSTREAM_URL         — Distribution registry base URL (required)
//	TOKEN_ENDPOINT       — Registry token service GET /token URL (required)
//	CLIENT_ID            — Hydra client_id for Basic auth to token service (default: registry-browser)
//	CLIENT_SECRET_FILE   — Path to file containing the Hydra client secret (required)
//	TOKEN_REFRESH_MARGIN — Evict cached tokens this early before expiry (default: 30s)
//	LOG_LEVEL            — info | debug | warn | error (default: info)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/meddleware-org/registry-auth-proxy/internal/config"
	"github.com/meddleware-org/registry-auth-proxy/internal/proxy"
	"github.com/meddleware-org/registry-auth-proxy/internal/token"
)

// version is the build version, overridden at link time via
// -ldflags "-X main.version=...". It defaults to "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthCheck())
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	cache := token.NewCache(cfg.RefreshMargin)
	fetcher := token.NewFetcher(cfg.TokenEndpoint, cfg.ClientID, cfg.ClientSecret)
	handler := proxy.NewHandler(cfg.UpstreamURL, cache, fetcher)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealth)
	mux.Handle("/", handler)

	srv := &http.Server{
		Addr:              net.JoinHostPort("", cfg.Port),
		Handler:           logRequest(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", srv.Addr, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
	slog.Info("shutdown complete")
}

// healthCheck dials the local /healthz endpoint. Used by the container HEALTHCHECK.
func healthCheck() int {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8181"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/healthz", port))
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// responseWriter wraps http.ResponseWriter to capture the status code so the
// logRequest middleware can record it. The zero value records 200 until
// WriteHeader is called.
type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rw, r)
		slog.Debug("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.code,
			"elapsed_ms", time.Since(start).Milliseconds(),
		)
	})
}
