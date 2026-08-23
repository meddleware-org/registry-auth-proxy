package token

import (
	"testing"
	"time"
)

func TestCacheSetGet(t *testing.T) {
	c := NewCache(30 * time.Second)

	if _, ok := c.Get("repository:foo:pull"); ok {
		t.Fatal("expected miss on empty cache")
	}

	// Token that expires well beyond the margin — should be a hit.
	c.Set("repository:foo:pull", "tok-abc", time.Now().Add(5*time.Minute))
	got, ok := c.Get("repository:foo:pull")
	if !ok || got != "tok-abc" {
		t.Fatalf("Get = (%q, %v), want (%q, true)", got, ok, "tok-abc")
	}

	// A different scope is still a miss.
	if _, ok := c.Get("registry:catalog:*"); ok {
		t.Fatal("expected miss for unknown scope")
	}
}

func TestCacheMarginExpiry(t *testing.T) {
	// Margin larger than the token lifetime means the entry is already expired.
	c := NewCache(1 * time.Minute)
	c.Set("s", "tok", time.Now().Add(10*time.Second))
	if _, ok := c.Get("s"); ok {
		t.Fatal("expected miss: token is within the refresh margin of expiry")
	}
}

func TestCacheEmptyScopeKey(t *testing.T) {
	// The empty scope (the /v2/ ping) is a valid cache key.
	c := NewCache(0)
	c.Set("", "ping-tok", time.Now().Add(time.Minute))
	got, ok := c.Get("")
	if !ok || got != "ping-tok" {
		t.Fatalf("Get(\"\") = (%q, %v), want (%q, true)", got, ok, "ping-tok")
	}
}
