package proxy

import "strings"

// parseBearerChallenge extracts the service and scope directives from a
// WWW-Authenticate response header value. It returns empty strings for a
// non-Bearer challenge or for directives that are absent. Values may be tokens or quoted strings
// (RFC 9110 §11.2): a quoted value may contain commas and escaped quotes, so the header is
// scanned rather than split on commas. Example input:
//
//	Bearer realm="https://token.example.com/token",service="reg.example.com",scope="repository:foo:pull"
func parseBearerChallenge(header string) (service, scope string) {
	const scheme = "bearer"
	header = strings.TrimSpace(header)
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) || header[len(scheme)] != ' ' {
		return "", ""
	}
	rest := header[len(scheme)+1:]
	for {
		rest = strings.TrimLeft(rest, " \t,")
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			return service, scope
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		var value string
		value, rest = readParamValue(strings.TrimLeft(rest[eq+1:], " \t"))
		switch key {
		case "service":
			service = value
		case "scope":
			scope = value
		}
	}
}

// readParamValue reads one auth-param value from the start of s — a quoted string (with
// backslash escapes) or a bare token ending at a comma — and returns it with the remainder.
func readParamValue(s string) (value, rest string) {
	if !strings.HasPrefix(s, `"`) {
		end := strings.IndexByte(s, ',')
		if end < 0 {
			return strings.TrimSpace(s), ""
		}
		return strings.TrimSpace(s[:end]), s[end:]
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '"':
			return b.String(), s[i+1:]
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), "" // unterminated: take what is there; readOnlyScope still vets it
}

// readOnlyScope reports whether every scope in a challenge's space-separated scope list asks only
// for read access: the catalog, or `pull` on a repository. An empty scope (the /v2/ ping) is
// read-only. Anything else — push, delete, `*`, an unknown resource type, a malformed entry — is
// refused, so the proxy never requests a token broader than the browser UI needs.
func readOnlyScope(scope string) bool {
	for _, one := range strings.Fields(scope) {
		if one == "registry:catalog:*" {
			continue
		}
		name, ok := strings.CutPrefix(one, "repository:")
		if !ok {
			return false
		}
		cut := strings.LastIndexByte(name, ':')
		if cut <= 0 || name[cut+1:] != "pull" {
			return false
		}
		if strings.ContainsAny(name[:cut], " \t\r\n") {
			return false
		}
	}
	return true
}
