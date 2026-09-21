package proxy

import (
	"path"
	"regexp"
	"strings"
)

// scopeRules maps registry API URL paths to the OCI token scope they require.
// Rules are evaluated in order and the first match wins. The captured
// repository name may contain slashes (namespaced repositories), so the name
// group is greedy up to the fixed trailing path segment. Every rule here yields
// a pull scope because the proxy fronts a read-only browser UI; write and delete
// scopes are intentionally never predicted (an unauthorised action falls through
// to the registry's own 401, which the handler remaps to 403).
var scopeRules = []struct {
	re    *regexp.Regexp
	scope func(matches []string) string
}{
	// /v2/_catalog
	{
		re:    regexp.MustCompile(`^/v2/_catalog$`),
		scope: func(_ []string) string { return "registry:catalog:*" },
	},
	// /v2/<name>/tags/list  (name may contain slashes for namespaced repos)
	{
		re: regexp.MustCompile(`^/v2/(.+)/tags/list$`),
		scope: func(m []string) string {
			return "repository:" + m[1] + ":pull"
		},
	},
	// /v2/<name>/manifests/<ref>
	{
		re: regexp.MustCompile(`^/v2/(.+)/manifests/[^/]+$`),
		scope: func(m []string) string {
			return "repository:" + m[1] + ":pull"
		},
	},
	// /v2/<name>/blobs/<digest>
	{
		re: regexp.MustCompile(`^/v2/(.+)/blobs/[^/]+$`),
		scope: func(m []string) string {
			return "repository:" + m[1] + ":pull"
		},
	},
}

// NormalizePath cleans a request path and reports whether it is a safe, in-bounds registry
// path. ok is false when the raw path contains a parent-directory traversal ("..") segment or,
// after cleaning, a /v2 request escapes the /v2 API root — a read-only registry browser never
// needs either, and both would otherwise let a crafted path desync the predicted scope (and its
// cache key) from the path actually forwarded upstream. net/http has already percent-decoded
// r.URL.Path, so an encoded `%2E%2E` traversal is visible here as "..".
//
// Defence-in-depth only: the token service remains the real authority and the browser identity is
// read-only, so a mispredicted scope could never escalate — this just removes the cache-confusion
// surface (audit F2).
func NormalizePath(p string) (clean string, ok bool) {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return path.Clean(p), false
		}
	}
	clean = path.Clean(p)
	// A /v2… request must still live under /v2 after cleaning.
	if strings.HasPrefix(p, "/v2") && clean != "/v2" && !strings.HasPrefix(clean, "/v2/") {
		return clean, false
	}
	return clean, true
}

// PredictScope returns the expected OCI scope string for a given URL path.
// Returns an empty string for /v2/ (ping) and any unrecognised paths.
// The empty string is a valid cache key: a no-scope token satisfies /v2/ pings.
// The path is normalised first so `.`/`..`/`//` segments cannot desync the cache key; a path that
// fails normalisation (traversal) predicts no scope (fail-safe — the handler rejects it outright).
func PredictScope(p string) string {
	clean, ok := NormalizePath(p)
	if !ok {
		return ""
	}
	clean = strings.TrimRight(clean, "/")
	if clean == "/v2" {
		return "" // no scope needed for the ping endpoint
	}
	for _, rule := range scopeRules {
		if m := rule.re.FindStringSubmatch(clean); m != nil {
			return rule.scope(m)
		}
	}
	return ""
}
