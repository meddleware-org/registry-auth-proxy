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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PredictScope(tt.path); got != tt.want {
				t.Errorf("PredictScope(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
