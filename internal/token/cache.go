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

// maxCacheEntries bounds the cache. Scopes derive from request paths, so without a bound a
// client enumerating repository names grows the map for the life of the process.
const maxCacheEntries = 512

// Cache is a thread-safe per-scope token cache. Tokens are evicted
// TOKEN_REFRESH_MARGIN seconds before their stated expiry so that callers
// always receive a token with meaningful remaining lifetime. The cache holds at most
// maxCacheEntries tokens: Set drops expired entries first, then the one closest to expiry.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	margin  time.Duration
	max     int
}

// NewCache returns an empty Cache. margin is how long before a token's real
// expiry the cache should stop serving it, so callers always receive a token
// with meaningful remaining lifetime.
func NewCache(margin time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
		margin:  margin,
		max:     maxCacheEntries,
	}
}

// Get returns the cached token for the given scope, or ("", false) if absent
// or within the refresh margin of expiry. Expired entries are deleted on miss
// to prevent unbounded map growth. Safe for concurrent use.
func (c *Cache) Get(scope string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[scope]
	if !ok || time.Now().After(e.expiresAt) {
		if ok {
			delete(c.entries, scope)
		}
		return "", false
	}
	return e.token, true
}

// Delete removes the token cached for scope, if any (for example after the registry refused it).
func (c *Cache) Delete(scope string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, scope)
}

// Len returns the number of cached entries, including any not yet swept.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Set stores a token for scope. rawExpiry is the full token lifetime as
// returned by the token service; the margin is subtracted before storing
// so the entry expires before the token itself does. A token that is already within the
// margin of expiry is not stored. When the cache is full, expired entries are swept and, if
// that is not enough, the entry closest to expiry is dropped.
func (c *Cache) Set(scope, tok string, rawExpiry time.Time) {
	expiresAt := rawExpiry.Add(-c.margin)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !expiresAt.After(now) {
		delete(c.entries, scope)
		return
	}
	if _, replacing := c.entries[scope]; !replacing && len(c.entries) >= c.max {
		c.evictLocked(now)
	}
	c.entries[scope] = cacheEntry{token: tok, expiresAt: expiresAt}
}

// evictLocked frees one slot: it drops every expired entry and, if none was expired, the entry
// that expires first. The caller holds c.mu.
func (c *Cache) evictLocked(now time.Time) {
	var oldest string
	var oldestAt time.Time
	found, swept := false, false
	for k, e := range c.entries {
		if !e.expiresAt.After(now) {
			delete(c.entries, k)
			swept = true
			continue
		}
		if !found || e.expiresAt.Before(oldestAt) {
			oldest, oldestAt, found = k, e.expiresAt, true
		}
	}
	if !swept && found {
		delete(c.entries, oldest)
	}
}
