package proxy

import "testing"

func TestPredictScope(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"ping", "/v2/", ""},
		{"ping no trailing slash", "/v2", ""},
		{"catalog", "/v2/_catalog", "registry:catalog:*"},
		{"catalog trailing slash", "/v2/_catalog/", "registry:catalog:*"},
		{"tags list", "/v2/foo/tags/list", "repository:foo:pull"},
		{"tags list namespaced", "/v2/meddleware-org/static-server/tags/list", "repository:meddleware-org/static-server:pull"},
		{"manifest by tag", "/v2/foo/manifests/latest", "repository:foo:pull"},
		{"manifest namespaced", "/v2/a/b/c/manifests/v1.2.3", "repository:a/b/c:pull"},
		{"blob by digest", "/v2/foo/blobs/sha256:abc123", "repository:foo:pull"},
		{"blob namespaced", "/v2/org/img/blobs/sha256:deadbeef", "repository:org/img:pull"},
		// A blob-upload write path matches the blob rule (greedy name capture) and
		// predicts a pull scope. This is harmless: joxit is read-only and never
		// uploads, and a pull token on a write path just yields an upstream 401
		// that the handler remaps to 403.
		{"blob upload (harmless mispredict)", "/v2/foo/blobs/uploads/", "repository:foo:pull"},
		{"unknown v2 subpath", "/v2/foo/wat", ""},
		{"non-v2", "/healthz", ""},
		{"root", "/", ""},
		// F2: traversal must not desync the predicted scope. A crafted ".." path predicts no
		// scope (fail-safe) rather than a confused "repository:foo/manifests/../../bar:pull".
		{"traversal predicts no scope", "/v2/foo/manifests/../../bar/manifests/latest", ""},
		// A clean path with collapsible segments still predicts the canonical scope.
		{"double slash normalised", "/v2//foo/tags/list", "repository:foo:pull"},
		{"dot segment normalised", "/v2/foo/./tags/list", "repository:foo:pull"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PredictScope(tt.path); got != tt.want {
				t.Errorf("PredictScope(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantClean string
		wantOK    bool
	}{
		{"clean tags path", "/v2/foo/tags/list", "/v2/foo/tags/list", true},
		{"ping", "/v2/", "/v2", true},
		{"double slash collapses", "/v2//foo/tags/list", "/v2/foo/tags/list", true},
		{"dot segment collapses", "/v2/foo/./tags/list", "/v2/foo/tags/list", true},
		{"parent traversal rejected", "/v2/foo/manifests/../../bar/manifests/latest", "/v2/bar/manifests/latest", false},
		{"leading traversal rejected", "/v2/../secret", "/secret", false},
		{"non-v2 clean path ok", "/healthz", "/healthz", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clean, ok := NormalizePath(tt.path)
			if clean != tt.wantClean || ok != tt.wantOK {
				t.Errorf("NormalizePath(%q) = (%q, %v), want (%q, %v)",
					tt.path, clean, ok, tt.wantClean, tt.wantOK)
			}
		})
	}
}
