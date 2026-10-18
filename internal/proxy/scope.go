package proxy

import (
	"regexp"
	"strings"
)

// The read routes of the Distribution registry HTTP API (OCI Distribution spec, "pull" and "catalog"
// categories) that the registry UI uses, with the grammars the registry itself enforces. Nothing else is
// forwarded: the proxy holds a credential, so the set of requests it will make with it is an allowlist,
// not "everything that is not forbidden" (audit F18).
const (
	// nameGrammar is the repository name grammar: lower-case path components of alphanumerics joined by
	// single separators ("." "_" "__" or dashes), at most 255 characters in all (checked in Route).
	nameGrammar = `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*`
	// tagGrammar is a manifest tag; digestGrammar is an OCI digest (algorithm ":" encoded).
	tagGrammar    = `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`
	digestGrammar = `[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+`
)

// maxNameLength is the longest repository name the registry accepts.
const maxNameLength = 255

// routeRules maps the allowed paths to the OCI token scope they require. Every rule yields a pull (or
// catalog) scope because the proxy fronts a read-only browser UI; write and delete scopes are never
// predicted. The first capture group, when present, is the repository name.
var routeRules = []struct {
	re    *regexp.Regexp
	scope func(name string) string
}{
	{regexp.MustCompile(`^/v2/_catalog$`), func(string) string { return "registry:catalog:*" }},
	{regexp.MustCompile(`^/v2/(` + nameGrammar + `)/tags/list$`), pullScope},
	{regexp.MustCompile(`^/v2/(` + nameGrammar + `)/manifests/(?:` + tagGrammar + `|` + digestGrammar + `)$`), pullScope},
	{regexp.MustCompile(`^/v2/(` + nameGrammar + `)/blobs/` + digestGrammar + `$`), pullScope},
	{regexp.MustCompile(`^/v2/(` + nameGrammar + `)/referrers/` + digestGrammar + `$`), pullScope},
}

func pullScope(name string) string { return "repository:" + name + ":pull" }

// RouteStatus is the outcome of checking a request path against the route allowlist.
type RouteStatus int

const (
	// RouteOK: the path is a canonical read route of the registry API.
	RouteOK RouteStatus = iota
	// RouteInvalid: the path is not canonical (an empty, "." or ".." segment, or a trailing slash): it is
	// refused with 400 rather than cleaned, so the path the registry receives is exactly the one checked.
	RouteInvalid
	// RouteNotFound: a canonical path that is not a read route of the registry API (answered 404 here,
	// as the registry would, without spending a token request).
	RouteNotFound
)

// Route checks a request path (as net/http decoded it) against the route allowlist. For RouteOK it also
// returns the OCI scope the route needs: "registry:catalog:*", "repository:<name>:pull", or "" for the
// version check (/v2/ and /v2), which needs no scope. The empty string is a valid cache key.
//
// The path is never rewritten. Every accepted path is built only from characters of the name, tag and
// digest grammars plus "/" and ":", so an encoded slash, NUL, newline or other smuggled byte decodes to
// something outside the grammar and is refused, and the path forwarded upstream equals the path checked.
// Prediction is only a cache-key optimisation and defence in depth: the token service remains the real
// authority and the browser identity is read-only.
func Route(p string) (scope string, status RouteStatus) {
	if p == "/" {
		return "", RouteNotFound
	}
	if p == "/v2/" || p == "/v2" {
		return "", RouteOK
	}
	if !strings.HasPrefix(p, "/") {
		return "", RouteInvalid
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", RouteInvalid
		}
	}
	for _, rule := range routeRules {
		m := rule.re.FindStringSubmatch(p)
		if m == nil {
			continue
		}
		name := ""
		if len(m) > 1 {
			name = m[1]
			if len(name) > maxNameLength {
				return "", RouteNotFound
			}
		}
		return rule.scope(name), RouteOK
	}
	return "", RouteNotFound
}

// PredictScope returns the OCI scope string a path needs, or "" for the version check and for any path
// that is not an allowed route (the handler refuses those before the prediction is used).
func PredictScope(p string) string {
	scope, status := Route(p)
	if status != RouteOK {
		return ""
	}
	return scope
}
