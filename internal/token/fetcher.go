package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// defaultExpiresIn is the token lifetime the Distribution spec assumes when expires_in is absent.
const defaultExpiresIn = 60

// tokenResponse is the JSON body returned by the registry token service, per the
// Distribution token auth spec. IssuedAt is RFC 3339; ExpiresIn is seconds.
type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	IssuedAt  string `json:"issued_at"`
}

// Failure classes reported by FailureClass. They are the only description of a failed fetch that is safe to
// log: the error text of a transport failure names the token endpoint, an internal host.
const (
	classTimeout     = "timeout"     // the token service did not answer in time
	classCanceled    = "canceled"    // the caller gave up
	classUnreachable = "unreachable" // dial, TLS or connection failure
	classStatus      = "status"      // the token service answered with a non-200 status
	classMalformed   = "malformed"   // unreadable, oversized, unparsable or empty answer
	classRequest     = "request"     // the request could not be built
)

// FetchError is the error of a failed token fetch. Error never carries the token endpoint URL or address,
// and never the client secret.
type FetchError struct {
	class  string
	status int
	msg    string
	err    error
}

func (e *FetchError) Error() string { return e.msg }
func (e *FetchError) Unwrap() error { return e.err }

// FailureClass names the class of a failed fetch ("timeout", "canceled", "unreachable", "status",
// "malformed" or "request"), or "unknown" for an error that is not a FetchError.
func FailureClass(err error) string {
	var fe *FetchError
	if errors.As(err, &fe) {
		return fe.class
	}
	return "unknown"
}

// FailureStatus returns the HTTP status the token service answered with, or 0 when it did not answer with
// a non-200 status.
func FailureStatus(err error) int {
	var fe *FetchError
	if errors.As(err, &fe) {
		return fe.status
	}
	return 0
}

// transportError classifies a failure of the HTTP round trip without keeping its text, which carries the
// request URL.
func transportError(err error) *FetchError {
	class := classUnreachable
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		class = classCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		class = classTimeout
	}
	return &FetchError{class: class, msg: "token endpoint " + class, err: err}
}

// Fetcher fetches Bearer tokens from the internal token service using
// client_credentials (Basic auth). The client secret must not be logged.
type Fetcher struct {
	endpoint string
	clientID string
	client   *http.Client

	mu     sync.RWMutex
	secret string
	// reload, when set, re-reads the client secret from its file (see WithSecretReload).
	reload func() (string, error)
}

// NewFetcher returns a Fetcher that authenticates to endpoint (the token
// service GET /token URL) as clientID using clientSecret via HTTP Basic auth.
// The secret is held only in memory and must never be logged.
func NewFetcher(endpoint, clientID, clientSecret string) *Fetcher {
	return &Fetcher{
		endpoint: endpoint,
		clientID: clientID,
		secret:   clientSecret,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// WithSecretReload makes the Fetcher survive a rotation of the client secret without a restart: when the
// token service refuses the credentials (401), reload is called to read the secret file again (the kubelet
// updates a mounted Secret in place), and if the value changed the fetch is retried once with it. A
// secret that did not change, or a file that cannot be read, leaves the original failure (fail closed).
// The secret never leaves the file and this process's memory, and is never logged.
func (f *Fetcher) WithSecretReload(reload func() (string, error)) *Fetcher {
	f.reload = reload
	return f
}

func (f *Fetcher) currentSecret() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.secret
}

// refreshSecret returns the secret to retry with after the token service refused used, and whether
// it differs from used.
func (f *Fetcher) refreshSecret(used string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.secret != used { // another request already picked up the new value
		return f.secret, true
	}
	next, err := f.reload()
	if err != nil {
		slog.Warn("client secret file could not be re-read", "cause", "unreadable")
		return "", false
	}
	if next == used {
		return "", false
	}
	f.secret = next
	slog.Info("client secret reloaded after the token service refused the credentials")
	return next, true
}

// Fetch retrieves a token for the given service and scope. It returns the raw
// token string and its absolute expiry time so the caller can cache both. Every error is a *FetchError.
func (f *Fetcher) Fetch(ctx context.Context, service, scope string) (tok string, expiry time.Time, err error) {
	used := f.currentSecret()
	tok, expiry, err = f.attempt(ctx, service, scope, used)
	if err != nil && f.reload != nil && FailureStatus(err) == http.StatusUnauthorized {
		if next, ok := f.refreshSecret(used); ok {
			return f.attempt(ctx, service, scope, next)
		}
	}
	return tok, expiry, err
}

func (f *Fetcher) attempt(ctx context.Context, service, scope, secret string) (tok string, expiry time.Time, err error) {
	// The request URL is the configured endpoint with service and scope set on its query, so an endpoint
	// that already carries query parameters stays well-formed (they are kept; ours win on a clash).
	u, err := url.Parse(f.endpoint)
	if err != nil {
		return "", time.Time{}, &FetchError{class: classRequest, msg: "build token request", err: err}
	}
	params := u.Query()
	params.Set("service", service)
	if scope != "" {
		params.Set("scope", scope)
	} else {
		params.Del("scope")
	}
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", time.Time{}, &FetchError{class: classRequest, msg: "build token request", err: err}
	}
	req.SetBasicAuth(f.clientID, secret)

	resp, err := f.client.Do(req)
	if err != nil {
		return "", time.Time{}, transportError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", time.Time{}, transportError(err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, &FetchError{class: classStatus, status: resp.StatusCode,
			msg: fmt.Sprintf("token endpoint returned %d", resp.StatusCode)}
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", time.Time{}, &FetchError{class: classMalformed, msg: "parse token response: " + err.Error(), err: err}
	}
	if tr.Token == "" {
		return "", time.Time{}, &FetchError{class: classMalformed, msg: "token endpoint returned empty token"}
	}

	// Absolute expiry = issue time + lifetime. The issue time is the earlier of issued_at and the
	// local clock, so a token service whose clock runs ahead cannot make a token look valid longer
	// than it is. A missing or non-positive expires_in means 60 s (Distribution token spec).
	issuedAt := time.Now()
	if tr.IssuedAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, tr.IssuedAt); parseErr == nil && t.Before(issuedAt) {
			issuedAt = t
		}
	}
	lifetime := tr.ExpiresIn
	if lifetime <= 0 {
		lifetime = defaultExpiresIn
	}
	expiry = issuedAt.Add(time.Duration(lifetime) * time.Second)

	return tr.Token, expiry, nil
}
