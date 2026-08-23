package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// tokenResponse is the JSON body returned by the registry token service, per the
// Distribution token auth spec. IssuedAt is RFC 3339; ExpiresIn is seconds.
type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	IssuedAt  string `json:"issued_at"`
}

// Fetcher fetches Bearer tokens from the internal token service using
// client_credentials (Basic auth). The client secret must not be logged.
type Fetcher struct {
	endpoint     string
	clientID     string
	clientSecret string
	client       *http.Client
}

// NewFetcher returns a Fetcher that authenticates to endpoint (the token
// service GET /token URL) as clientID using clientSecret via HTTP Basic auth.
// The secret is held only in memory and must never be logged.
func NewFetcher(endpoint, clientID, clientSecret string) *Fetcher {
	return &Fetcher{
		endpoint:     endpoint,
		clientID:     clientID,
		clientSecret: clientSecret,
		client:       &http.Client{Timeout: 10 * time.Second},
	}
}

// Fetch retrieves a token for the given service and scope. It returns the raw
// token string and its absolute expiry time so the caller can cache both.
func (f *Fetcher) Fetch(ctx context.Context, service, scope string) (tok string, expiry time.Time, err error) {
	params := url.Values{"service": {service}}
	if scope != "" {
		params.Set("scope", scope)
	}
	reqURL := f.endpoint + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth(f.clientID, f.clientSecret)

	resp, err := f.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", time.Time{}, fmt.Errorf("parse token response: %w", err)
	}
	if tr.Token == "" {
		return "", time.Time{}, fmt.Errorf("token endpoint returned empty token")
	}

	// Compute absolute expiry from the issue time + lifetime.
	// Fallback to now + expires_in if the issued_at field is missing or unparseable.
	issuedAt := time.Now()
	if tr.IssuedAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, tr.IssuedAt); parseErr == nil {
			issuedAt = t
		}
	}
	expiry = issuedAt.Add(time.Duration(tr.ExpiresIn) * time.Second)

	return tr.Token, expiry, nil
}
