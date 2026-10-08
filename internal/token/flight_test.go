package token

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFlightSharesOneFetch(t *testing.T) {
	var f Flight
	var runs atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{})
	fn := func() (string, time.Time, error) {
		if runs.Add(1) == 1 {
			close(started)
		}
		<-release
		return "tok", time.Unix(100, 0), nil
	}

	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _, _ = f.Do("scope", fn)
		}()
	}
	<-started
	time.Sleep(50 * time.Millisecond) // let the other callers join the in-flight call
	close(release)
	wg.Wait()

	if n := runs.Load(); n != 1 {
		t.Errorf("fetch ran %d times, want 1", n)
	}
	for i, r := range results {
		if r != "tok" {
			t.Errorf("caller %d got %q", i, r)
		}
	}
}

func TestFlightDoesNotCacheResultsOrErrors(t *testing.T) {
	var f Flight
	var runs int
	fail := errors.New("boom")
	if _, _, err := f.Do("s", func() (string, time.Time, error) { runs++; return "", time.Time{}, fail }); !errors.Is(err, fail) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := f.Do("s", func() (string, time.Time, error) { runs++; return "ok", time.Time{}, nil }); err != nil {
		t.Fatalf("second call err = %v", err)
	}
	if runs != 2 {
		t.Errorf("sequential calls ran fn %d times, want 2", runs)
	}
}

func TestFlightKeysAreIndependent(t *testing.T) {
	var f Flight
	a, _, _ := f.Do("a", func() (string, time.Time, error) { return "ta", time.Time{}, nil })
	b, _, _ := f.Do("b", func() (string, time.Time, error) { return "tb", time.Time{}, nil })
	if a != "ta" || b != "tb" {
		t.Errorf("got %q, %q", a, b)
	}
}
