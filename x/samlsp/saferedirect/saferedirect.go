// Package saferedirect checks return paths before an application
// redirects the browser to them.
//
// A return path often comes from the request, such as the data of a
// pending login (see x/samlsp/pending) or the RelayState of an unsolicited
// Response, which the IdP or an attacker chose. Redirecting to it as is
// would make the application an open redirector.
package saferedirect

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsSafe reports whether p is a path on this site that is safe
// to redirect the browser to. Use it before redirecting to a return path
// that came from the request:
//
//	next := login.Data
//	if !saferedirect.IsSafe(next) {
//		next = "/"
//	}
//	http.Redirect(w, r, next, http.StatusFound)
//
// p is safe if it is an absolute path, beginning with "/", optionally
// with a query and a fragment, that browsers cannot read as naming
// another host. It is not safe if:
//
//   - it does not begin with "/", such as "https://evil.example" or
//     "javascript:...", or "evil.example", which is relative;
//   - its path has "//" anywhere, which at the start names a host
//     ("//evil.example") and elsewhere may become the start once dot
//     segments are removed ("/..//evil.example");
//   - it has a backslash anywhere, which browsers read as "/" ("/\evil.example");
//   - it has a control or format character or white space anywhere, which
//     browsers drop or trim ("/\t/evil.example" is read as "//evil.example"),
//     or is not valid UTF-8;
//   - url.Parse refuses it, or finds a scheme or a host in it.
//
// It does not limit the length of p: a return path kept in a cookie should
// be checked for length too.
func IsSafe(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return false
	}
	if !utf8.ValidString(p) || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, r := range p {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			return false
		}
	}
	path := p
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if strings.Contains(path, "//") {
		return false
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil && u.Opaque == "" &&
		strings.HasPrefix(u.Path, "/")
}
