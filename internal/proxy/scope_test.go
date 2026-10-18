package proxy

import (
	"strings"
	"testing"
)

func TestPredictScope(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"ping", "/v2/", ""},
		{"ping no trailing slash", "/v2", ""},
		{"catalog", "/v2/_catalog", "registry:catalog:*"},
		{"tags list", "/v2/foo/tags/list", "repository:foo:pull"},
		{"tags list namespaced", "/v2/meddleware-org/static-server/tags/list", "repository:meddleware-org/static-server:pull"},
		{"manifest by tag", "/v2/foo/manifests/latest", "repository:foo:pull"},
		{"manifest by digest", "/v2/foo/manifests/sha256:abc123", "repository:foo:pull"},
		{"manifest namespaced", "/v2/a/b/c/manifests/v1.2.3", "repository:a/b/c:pull"},
		{"blob by digest", "/v2/foo/blobs/sha256:abc123", "repository:foo:pull"},
		{"blob namespaced", "/v2/org/img/blobs/sha256:deadbeef", "repository:org/img:pull"},
		{"referrers", "/v2/foo/referrers/sha256:abc123", "repository:foo:pull"},
		{"name with separators", "/v2/my.org/my_img--x/tags/list", "repository:my.org/my_img--x:pull"},
		{"name containing a route word", "/v2/a/blobs/b/manifests/latest", "repository:a/blobs/b:pull"},
		// Paths that are not allowed routes predict no scope; the handler refuses them before use.
		{"blob upload", "/v2/foo/blobs/uploads/", ""},
		{"unknown v2 subpath", "/v2/foo/wat", ""},
		{"non-v2", "/healthz", ""},
		{"root", "/", ""},
		{"traversal", "/v2/foo/manifests/../../bar/manifests/latest", ""},
		{"double slash", "/v2//foo/tags/list", ""},
		{"dot segment", "/v2/foo/./tags/list", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PredictScope(tt.path); got != tt.want {
				t.Errorf("PredictScope(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestRoute pins the forwarding allowlist (audit F18): which paths are forwarded, which are refused as
// non-canonical (400) and which are refused as not a registry read route (404).
func TestRoute(t *testing.T) {
	long := strings.Repeat("a", maxNameLength)
	tests := []struct {
		name string
		path string
		want RouteStatus
	}{
		{"ping", "/v2/", RouteOK},
		{"ping no slash", "/v2", RouteOK},
		{"catalog", "/v2/_catalog", RouteOK},
		{"tags", "/v2/foo/tags/list", RouteOK},
		{"manifest by tag", "/v2/foo/manifests/latest", RouteOK},
		{"manifest tag with dots and dashes", "/v2/foo/manifests/v1.2.3-rc.1_x", RouteOK},
		{"manifest by digest", "/v2/foo/manifests/sha256:0123456789abcdef", RouteOK},
		{"blob", "/v2/foo/blobs/sha256:0123456789abcdef", RouteOK},
		{"referrers", "/v2/foo/referrers/sha256:0123456789abcdef", RouteOK},
		{"longest name", "/v2/" + long + "/tags/list", RouteOK},

		{"name too long", "/v2/" + long + "a/tags/list", RouteNotFound},
		{"parent traversal", "/v2/foo/manifests/../../bar/manifests/latest", RouteInvalid},
		{"leading traversal", "/v2/../secret", RouteInvalid},
		{"double slash", "/v2//foo/tags/list", RouteInvalid},
		{"double slash at root", "//v2/_catalog", RouteInvalid},
		{"dot segment", "/v2/foo/./tags/list", RouteInvalid},
		{"trailing slash", "/v2/_catalog/", RouteInvalid},
		{"trailing slash on tags", "/v2/foo/tags/list/", RouteInvalid},
		{"relative path", "v2/_catalog", RouteInvalid},

		{"root", "/", RouteNotFound},
		{"healthz-like", "/healthz", RouteNotFound},
		{"outside v2", "/metrics", RouteNotFound},
		{"v2 prefix lookalike", "/v2foo/_catalog", RouteNotFound},
		{"v2 internals", "/v2/token", RouteNotFound},
		{"blob upload", "/v2/foo/blobs/uploads/", RouteInvalid},
		{"blob upload session", "/v2/foo/blobs/uploads/abc", RouteNotFound},
		{"upper-case name", "/v2/Foo/tags/list", RouteNotFound},
		{"name with space", "/v2/foo bar/tags/list", RouteNotFound},
		{"name with colon (scope injection)", "/v2/foo:pull repository:bar/tags/list", RouteNotFound},
		{"name with control byte", "/v2/foo\x00/tags/list", RouteNotFound},
		{"name with newline", "/v2/foo\n/tags/list", RouteNotFound},
		{"decoded slash stays a name separator", "/v2/a/b/tags/list", RouteOK},
		{"leading underscore component", "/v2/_x/tags/list", RouteNotFound},
		{"manifest reference with a space", "/v2/foo/manifests/a b", RouteNotFound},
		{"blob by tag", "/v2/foo/blobs/latest", RouteNotFound},
		{"unknown sub-route", "/v2/foo/wat", RouteNotFound},
		{"catalog with extra segment", "/v2/_catalog/x", RouteNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, got := Route(tt.path); got != tt.want {
				t.Errorf("Route(%q) status = %d, want %d", tt.path, got, tt.want)
			}
		})
	}
}
