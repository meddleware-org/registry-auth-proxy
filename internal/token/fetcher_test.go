package token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serve(t *testing.T, status int, body string, check func(*http.Request)) *Fetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewFetcher(srv.URL+"/token", "proxy", "s3cret")
}

// TestFetchSendsCredentialsAndScope verifies the request: Basic auth with the client
// credentials, the service and scope as query values, nothing else.
func TestFetchSendsCredentialsAndScope(t *testing.T) {
	f := serve(t, 200, `{"token":"t","expires_in":300}`, func(r *http.Request) {
		user, pass, ok := r.BasicAuth()
		q := r.URL.Query()
		if !ok || user != "proxy" || pass != "s3cret" || q.Get("service") != "registry.example" ||
			q.Get("scope") != "repository:org/app:pull" || r.URL.Path != "/token" {
			t.Errorf("request: user=%q service=%q scope=%q path=%q", user, q.Get("service"), q.Get("scope"), r.URL.Path)
		}
	})
	tok, exp, err := f.Fetch(context.Background(), "registry.example", "repository:org/app:pull")
	if err != nil || tok != "t" {
		t.Fatalf("got %q %v", tok, err)
	}
	if d := time.Until(exp); d < 295*time.Second || d > 300*time.Second {
		t.Errorf("expiry in %s, want about 300 s", d)
	}
}

// TestFetchFailsClosed verifies every unusable answer is an error (the handler answers 502).
func TestFetchFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"unauthorized", 401, `{"error":"invalid credentials"}`, "returned 401"},
		{"unavailable", 503, ``, "returned 503"},
		{"malformed", 200, `{"token":`, "parse token response"},
		{"empty token", 200, `{"expires_in":60}`, "empty token"},
		{"oversized", 200, `{"token":"` + strings.Repeat("a", 70<<10) + `"}`, "parse token response"},
	}
	for _, c := range cases {
		_, _, err := serve(t, c.status, c.body, nil).Fetch(context.Background(), "s", "")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "s3cret") {
			t.Errorf("%s: error leaks the client secret", c.name)
		}
	}
}

// TestFetchExpiry verifies the spec default for a missing lifetime and that a token
// service clock running ahead cannot extend the cached lifetime.
func TestFetchExpiry(t *testing.T) {
	_, exp, err := serve(t, 200, `{"token":"t"}`, nil).Fetch(context.Background(), "s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 55*time.Second || d > 60*time.Second {
		t.Errorf("missing expires_in: expiry in %s, want about 60 s", d)
	}

	ahead := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	_, exp, err = serve(t, 200, `{"token":"t","expires_in":300,"issued_at":"`+ahead+`"}`, nil).Fetch(context.Background(), "s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d > 300*time.Second {
		t.Errorf("clock ahead: expiry in %s, want at most 300 s", d)
	}

	behind := time.Now().Add(-100 * time.Second).UTC().Format(time.RFC3339)
	_, exp, err = serve(t, 200, `{"token":"t","expires_in":300,"issued_at":"`+behind+`"}`, nil).Fetch(context.Background(), "s", "")
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d > 205*time.Second || d < 195*time.Second {
		t.Errorf("issued 100 s ago: expiry in %s, want about 200 s", d)
	}
}
