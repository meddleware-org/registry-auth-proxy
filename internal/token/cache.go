// Package token provides the Bearer-token machinery the proxy uses to
// authenticate to the Distribution registry on the browser UI's behalf: a
// per-scope token cache (cache.go) and a fetcher that exchanges the
// registry-browser client credentials for a scoped token at the internal token
// service (fetcher.go).
package token

import (
	"sync"
	"time"
)

// cacheEntry is a single cached token together with its effective expiry, which
// already has the refresh margin subtracted (see Cache.Set).
type cacheEntry struct {
	token     string
	expiresAt time.Time
}

// Cache is a thread-safe per-scope token cache. Tokens are evicted
// TOKEN_REFRESH_MARGIN seconds before their stated expiry so that callers
// always receive a token with meaningful remaining lifetime.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	margin  time.Duration
}

// NewCache returns an empty Cache. margin is how long before a token's real
// expiry the cache should stop serving it, so callers always receive a token
// with meaningful remaining lifetime.
func NewCache(margin time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
		margin:  margin,
	}
}

// Get returns the cached token for the given scope, or ("", false) if absent
// or within the refresh margin of expiry. Safe for concurrent use.
func (c *Cache) Get(scope string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[scope]
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.token, true
}

// Set stores a token for scope. rawExpiry is the full token lifetime as
// returned by the token service; the margin is subtracted before storing
// so the entry expires before the token itself does.
func (c *Cache) Set(scope, tok string, rawExpiry time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[scope] = cacheEntry{
		token:     tok,
		expiresAt: rawExpiry.Add(-c.margin),
	}
}
