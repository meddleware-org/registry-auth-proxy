package proxy

import (
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

// PredictScope returns the expected OCI scope string for a given URL path.
// Returns an empty string for /v2/ (ping) and any unrecognised paths.
// The empty string is a valid cache key: a no-scope token satisfies /v2/ pings.
func PredictScope(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "/v2" {
		return "" // no scope needed for the ping endpoint
	}
	for _, rule := range scopeRules {
		if m := rule.re.FindStringSubmatch(path); m != nil {
			return rule.scope(m)
		}
	}
	return ""
}
