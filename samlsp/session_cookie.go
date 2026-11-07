package samlsp

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

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

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set when served over https
		Name:     c.Name,
		Domain:   c.Domain,
		Value:    value,
		MaxAge:   int(c.MaxAge.Seconds()),
		HttpOnly: c.HTTPOnly,
		Secure:   c.Secure || r.URL.Scheme == "https",
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

	cookie, err := r.Cookie(c.Name)

	if err == http.ErrNoCookie {
		return nil
	}
	if err != nil {
		return err
	}

	// The deletion cookie must use the same path as the one set by CreateSession,
	// otherwise the browser treats it as a different cookie and keeps the session.
	path := c.Path
	if path == "" {
		path = "/"
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	cookie.Path = path
	cookie.Domain = c.Domain
	http.SetCookie(w, cookie)
	return nil
}

// GetSession returns the current Session associated with the request, or an
// error matching ErrNoSession (as determined by errors.Is) if there is no valid
// session. When the cookie is present but cannot be decoded, the returned error
// also wraps the error from Codec.Decode, so callers can see why the session
// was rejected.
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
	return session, nil
}
