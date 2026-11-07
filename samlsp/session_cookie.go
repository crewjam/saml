package samlsp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

const defaultSessionCookieName = "token"

// maxSessionCookieSize is the largest cookie, counting its name and value,
// that browsers reliably store. Chrome and Firefox silently drop a cookie whose
// name and value together exceed 4096 bytes.
const maxSessionCookieSize = 4096

// ErrSessionCookieTooLarge is returned (wrapped) by
// CookieSessionProvider.CreateSession when the encoded session does not fit in
// a cookie. Browsers silently drop such a cookie, so the user would come back
// without a session and be sent to the IdP again, in a loop. This usually means
// the IdP sends more attributes than fit in a cookie; filter them with a custom
// SessionCodec, or store sessions server side with a custom SessionProvider.
var ErrSessionCookieTooLarge = errors.New("saml: session cookie too large")

var _ SessionProvider = CookieSessionProvider{}

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite

	// MaxAge is the lifetime of the session cookie. When Codec is a
	// JWTSessionCodec, set its MaxAge to the same value: the token expires on
	// its own after that, whatever the cookie's lifetime. See the
	// Example (SessionMaxAge).
	MaxAge time.Duration
	Path   string
	Codec  SessionCodec

	// Revocations, if set, records sessions ended by back-channel single
	// logout (see TerminateSessions), and GetSession refuses those sessions
	// as if there were none. The sessions must implement RevocableSession,
	// and Codec must say so by implementing RevocableSessionCodec, as
	// JWTSessionCodec does; the signature of the session token keeps a
	// client from changing what identifies its session. If nil, or if Codec
	// does not implement RevocableSessionCodec, sessions cannot be ended
	// without the browser, and TerminateSessions returns
	// ErrSessionTerminationUnsupported. DefaultSessionProvider sets it.
	Revocations SessionRevocationStore

	// Clock, if non-nil, is the time source for limiting the cookie to the
	// IdP session (SessionNotOnOrAfter) and for the revocation records of
	// TerminateSessions. It should be the Clock of Codec. If nil, the real
	// clock is used (through the deprecated saml.TimeNow).
	Clock *dsig.Clock

	// legacyDomain, if set, is the Domain of a session cookie set by an
	// earlier version of DefaultSessionProvider. CreateSession and
	// DeleteSession expire that cookie too, so that a browser does not keep
	// (and send) both the old domain cookie and the new one.
	legacyDomain string
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	session, err := c.Codec.New(assertion)
	if err != nil {
		return err
	}

	// The cookie lasts no longer than the IdP session (SessionNotOnOrAfter).
	maxAge := c.MaxAge
	if end, ok := sessionEnd(assertion); ok {
		remaining := end.Sub(clockNow(c.Clock))
		if remaining < time.Second {
			return fmt.Errorf("%w: the IdP session ends at %s (SessionNotOnOrAfter)", ErrSessionEnded, end)
		}
		if remaining < maxAge {
			maxAge = remaining
		}
	}

	value, err := c.Codec.Encode(session)
	if err != nil {
		return err
	}
	if size := len(c.Name) + len(value); size > maxSessionCookieSize {
		return fmt.Errorf("%w: cookie %q is %d bytes, browsers accept at most %d",
			ErrSessionCookieTooLarge, c.Name, size, maxSessionCookieSize)
	}

	path := c.Path
	if path == "" {
		path = "/"
	}

	// Expire the legacy cookie before setting the new one: a browser that
	// treats both as the same cookie then keeps the new one.
	c.expireLegacyCookie(w, r, path)

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set when served over https
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    value,
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.TLS != nil,
		SameSite: c.SameSite,
		Path:     path,
	})
	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c CookieSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	if _, err := r.Cookie(c.Name); err == http.ErrNoCookie {
		return nil
	} else if err != nil {
		return err
	}

	// The deletion cookie must use the same path as the one set by CreateSession,
	// otherwise the browser treats it as a different cookie and keeps the session.
	path := c.Path
	if path == "" {
		path = "/"
	}

	http.SetCookie(w, c.expiredCookie(r, c.Domain, path))
	c.expireLegacyCookie(w, r, path)
	return nil
}

// expiredCookie returns a cookie that expires the session cookie scoped to
// domain and path. It has the same attributes as the cookie CreateSession
// sets: a cookie read from the request carries none, so it cannot be reused.
func (c CookieSessionProvider) expiredCookie(r *http.Request, domain, path string) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set when served over https
		Name:     c.Name,
		Domain:   domain,
		Value:    "",
		Expires:  time.Unix(1, 0), // past time as close to epoch as possible, but not zero time.Time{}
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.TLS != nil,
		SameSite: c.SameSite,
		Path:     path,
	}
}

// expireLegacyCookie expires the session cookie scoped to c.legacyDomain, if
// any.
func (c CookieSessionProvider) expireLegacyCookie(w http.ResponseWriter, r *http.Request, path string) {
	if c.legacyDomain == "" || c.legacyDomain == c.Domain {
		return
	}
	http.SetCookie(w, c.expiredCookie(r, c.legacyDomain, path))
}

// GetSession returns the current Session associated with the request, or an
// error matching ErrNoSession (as determined by errors.Is) if there is no valid
// session. When the cookie is present but cannot be decoded, the returned error
// also wraps the error from Codec.Decode, so callers can see why the session
// was rejected. A session revoked in Revocations is refused with an error
// matching both ErrNoSession and ErrSessionRevoked; if Revocations cannot be
// read, the error does not match ErrNoSession, so the request fails rather
// than start a new login.
func (c CookieSessionProvider) GetSession(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(c.Name)
	if err == http.ErrNoCookie {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}

	session, err := c.Codec.Decode(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoSession, err)
	}
	if err := c.checkRevoked(r.Context(), session); err != nil {
		return nil, err
	}
	return session, nil
}
