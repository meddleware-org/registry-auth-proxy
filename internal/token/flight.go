package token

import (
	"sync"
	"time"
)

// call is one in-flight fetch that concurrent callers for the same key share.
type call struct {
	wg  sync.WaitGroup
	tok string
	exp time.Time
	err error
}

// Flight collapses concurrent fetches for the same key into one: while a fetch for a scope is in
// flight, other callers for that scope wait for its result instead of each asking the token
// service. A burst of cold-cache requests (the UI loads many repositories at once) is therefore
// one token request per scope. The zero value is ready to use.
type Flight struct {
	mu    sync.Mutex
	calls map[string]*call
}

// Do runs fn once per key at a time and returns its result to every concurrent caller of that
// key. fn must not depend on any single caller's request context, since its result is shared.
func (f *Flight) Do(key string, fn func() (string, time.Time, error)) (string, time.Time, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = make(map[string]*call)
	}
	if c, ok := f.calls[key]; ok {
		f.mu.Unlock()
		c.wg.Wait()
		return c.tok, c.exp, c.err
	}
	c := &call{}
	c.wg.Add(1)
	f.calls[key] = c
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		delete(f.calls, key)
		f.mu.Unlock()
		c.wg.Done()
	}()
	c.tok, c.exp, c.err = fn()
	return c.tok, c.exp, c.err
}
