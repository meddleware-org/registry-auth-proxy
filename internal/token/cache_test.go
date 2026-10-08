package token

import (
	"fmt"
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

func TestCacheExpiredEntryDeleted(t *testing.T) {
	// An entry that expires after it was stored is deleted on the Get miss, not kept forever.
	c := NewCache(0)
	c.Set("s", "tok", time.Now().Add(20*time.Millisecond))
	if c.Len() != 1 {
		t.Fatalf("expected 1 entry after Set, got %d", c.Len())
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := c.Get("s"); ok {
		t.Fatal("expected miss on expired entry")
	}
	if c.Len() != 0 {
		t.Fatalf("expected 0 entries after Get miss on expired entry, got %d", c.Len())
	}
}

func TestCacheSkipsTokenAlreadyInsideMargin(t *testing.T) {
	c := NewCache(time.Minute)
	c.Set("s", "tok", time.Now().Add(10*time.Second))
	if c.Len() != 0 {
		t.Fatalf("a token inside the refresh margin was stored (%d entries)", c.Len())
	}
}

func TestCacheIsBounded(t *testing.T) {
	c := NewCache(0)
	c.max = 4
	now := time.Now()
	// Distinct scopes with increasing lifetimes: the one closest to expiry goes first.
	for i := 0; i < 10; i++ {
		c.Set(fmt.Sprintf("repository:r%d:pull", i), "tok", now.Add(time.Duration(i+1)*time.Minute))
		if c.Len() > 4 {
			t.Fatalf("cache grew to %d entries, cap is 4", c.Len())
		}
	}
	if _, ok := c.Get("repository:r0:pull"); ok {
		t.Error("the entry closest to expiry should have been evicted")
	}
	if _, ok := c.Get("repository:r9:pull"); !ok {
		t.Error("the newest entry should be cached")
	}
}

func TestCacheEvictionKeepsEmptyScope(t *testing.T) {
	// The empty scope is a real key; eviction must treat it like any other.
	c := NewCache(0)
	c.max = 2
	now := time.Now()
	c.Set("", "ping", now.Add(time.Minute))
	c.Set("a", "ta", now.Add(2*time.Minute))
	c.Set("b", "tb", now.Add(3*time.Minute))
	if c.Len() != 2 {
		t.Fatalf("cache holds %d entries, want 2", c.Len())
	}
	if _, ok := c.Get(""); ok {
		t.Error("the empty-scope entry expires first and should have been evicted")
	}
}

func TestCacheDelete(t *testing.T) {
	c := NewCache(0)
	c.Set("s", "tok", time.Now().Add(time.Minute))
	c.Delete("s")
	if _, ok := c.Get("s"); ok {
		t.Fatal("entry survived Delete")
	}
}
