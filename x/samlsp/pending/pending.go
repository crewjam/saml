// Package pending remembers each login in progress, between the
// AuthnRequest a service provider sends and the Response that comes back
// to its assertion consumer service (ACS), in a cookie in the user's
// browser.
//
// ParseResponse in github.com/crewjam/saml/x/samlsp accepts a Response
// only if it answers an AuthnRequest that the application names with
// samlsp.WithRequestID. The application must keep the request's ID until
// the Response arrives, and keep it in this browser, so that a Response
// obtained in one browser is not accepted in another. A Tracker keeps it in
// a cookie named after the request's RelayState, so logins in several tabs
// do not disturb each other:
//
//	tracker, err := pending.New(config, cookieKey)
//
//	func login(w http.ResponseWriter, r *http.Request) {
//		msg, err := config.AuthnRequest(r.Context(), rand.Text())
//		if err != nil { ... }
//		if err := tracker.Remember(w, msg, r.URL.Query().Get("next")); err != nil { ... }
//		msg.Write(w)
//	}
//
//	func acs(w http.ResponseWriter, r *http.Request) {
//		login, err := tracker.Take(w, r)
//		if err != nil { ... } // no login in progress in this browser
//		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID))
//		if err != nil { ... }
//		startSession(w, assertion)
//		http.Redirect(w, r, safeLocalPath(login.Data), http.StatusFound)
//	}
//
// The cookie is authenticated with an HMAC key, so the browser cannot
// change the request ID, the RelayState it belongs to, its expiry or the
// application's data. It is not encrypted: do not put secrets in the data.
// Every server that serves the ACS must use the same key.
//
// The cookie's path is that of the ACS URL, so the browser sends it there
// only. Since the IdP sends its Response with a cross-site POST, which
// browsers do not send SameSite=Lax cookies with, the cookie is
// SameSite=None and Secure when the ACS URL uses https. With an http ACS
// URL, meant for local development, the cookie has no SameSite attribute
// and is not Secure, and whether browsers send it with a cross-site POST
// depends on the browser.
//
// This package is built only on the public API of x/samlsp, which itself
// leaves sessions and cookies to the application. Applications that keep
// pending logins elsewhere, such as in a server-side session, need not use
// it.
package pending

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/x/samlsp"
)

// DefaultMaxAge is how long a login may stay in progress, unless WithMaxAge
// says otherwise. It leaves the user time to authenticate at the IdP,
// including with a second factor.
const DefaultMaxAge = 10 * time.Minute

// DefaultCookiePrefix begins the name of each pending login's cookie,
// unless WithCookiePrefix says otherwise.
const DefaultCookiePrefix = "saml_pending_"

// MinKeyLength is the shortest HMAC key that New accepts, in bytes.
const MinKeyLength = 32

// maxCookieSize is the largest cookie value Remember writes. Browsers keep
// cookies of at least 4096 bytes, name and attributes included.
const maxCookieSize = 3800

// ErrNotFound is returned by Take when the request carries no cookie for
// its RelayState, or when the cookie has expired: no login is in progress
// in this browser for the Response. This is the case of an IdP-initiated
// login, of a Response sent twice, and of a user who took longer than
// MaxAge.
var ErrNotFound = errors.New("pending: no login in progress for this RelayState")

// ErrInvalid is returned by Take when the cookie for the RelayState was
// not made by Remember with this Tracker's key: it was changed, made
// with another key, or made for another RelayState.
var ErrInvalid = errors.New("pending: the login cookie is not valid")

// Login is a login in progress that Take found.
type Login struct {
	// ID is the ID of the AuthnRequest. Pass it to ParseResponse with
	// samlsp.WithRequestID.
	ID string

	// RelayState is the RelayState of the AuthnRequest.
	RelayState string

	// Data is the data passed to Remember, such as where to send the
	// user after login. The browser cannot change it, but it is only as
	// trustworthy as what Remember was given. Check a return path before
	// redirecting to it: it must start with "/", but not with "//" or
	// "/\", which browsers read as another host.
	Data string

	// Expires is when the login would have stopped being accepted.
	Expires time.Time
}

// Tracker keeps logins in progress in cookies. Create one with New. It is
// safe for concurrent use.
type Tracker struct {
	key    []byte
	prefix string
	path   string
	domain string
	secure bool
	maxAge time.Duration
	clock  *dsig.Clock
}

// Option configures New.
type Option func(*Tracker)

// WithMaxAge sets how long a login may stay in progress. The default is
// DefaultMaxAge.
func WithMaxAge(d time.Duration) Option { return func(t *Tracker) { t.maxAge = d } }

// WithCookiePrefix sets what the name of each cookie begins with. The
// default is DefaultCookiePrefix.
func WithCookiePrefix(prefix string) Option { return func(t *Tracker) { t.prefix = prefix } }

// WithDomain sets the Domain attribute of the cookies, so that hosts below
// it receive them too. By default they are host-only.
func WithDomain(domain string) Option { return func(t *Tracker) { t.domain = domain } }

// WithPath sets the Path attribute of the cookies. The default is the path
// of the ACS URL. Set it when the ACS handler is reached at another path,
// such as behind a reverse proxy that rewrites paths.
func WithPath(path string) Option { return func(t *Tracker) { t.path = path } }

// WithClock sets the time source for the expiry of logins. It is mainly
// useful in tests.
func WithClock(clock *dsig.Clock) Option { return func(t *Tracker) { t.clock = clock } }

// deriveKeyLabel separates keys derived by DeriveKey from other uses of
// HMAC-SHA256 with the same secret.
const deriveKeyLabel = "github.com/crewjam/saml/x/samlsp/pending key\x00"

// DeriveKey returns a key for New derived from secret, a secret the
// application already has: for example, the key that signs its sessions,
// or the SP's private key, encoded with x509.MarshalPKCS8PrivateKey. label
// names the use, such as "example.com saml pending login", so that the
// key differs from any other derived from the same secret, and the secret
// itself is never used as the key of a cookie.
//
// The key is as strong as secret, which must be random, kept secret and
// the same on every server; changing it fails the logins in progress. It
// returns an error if secret is shorter than MinKeyLength or label is
// empty.
func DeriveKey(secret []byte, label string) ([]byte, error) {
	if len(secret) < MinKeyLength {
		return nil, fmt.Errorf("pending: the secret must be at least %d bytes, not %d", MinKeyLength, len(secret))
	}
	if label == "" {
		return nil, errors.New("pending: the label is empty")
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(deriveKeyLabel))
	h.Write([]byte(label))
	return h.Sum(nil), nil
}

// New returns a Tracker for the logins of config, whose cookies are
// authenticated with key. key must be at least MinKeyLength random bytes,
// kept secret and shared by every server that serves the ACS. Changing it
// fails the logins in progress.
func New(config *samlsp.Config, key []byte, opts ...Option) (*Tracker, error) {
	if config == nil {
		return nil, errors.New("pending: the config is nil")
	}
	if len(key) < MinKeyLength {
		return nil, fmt.Errorf("pending: the key must be at least %d bytes, not %d", MinKeyLength, len(key))
	}
	acs, err := url.Parse(config.ACSURL())
	if err != nil {
		return nil, fmt.Errorf("pending: invalid ACS URL: %w", err)
	}
	t := &Tracker{
		key:    append([]byte(nil), key...),
		prefix: DefaultCookiePrefix,
		path:   acs.Path,
		secure: acs.Scheme == "https",
		maxAge: DefaultMaxAge,
	}
	if t.path == "" {
		t.path = "/"
	}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	if t.maxAge <= 0 {
		return nil, errors.New("pending: the max age must be positive")
	}
	if t.prefix == "" || strings.ContainsAny(t.prefix, "()<>@,;:\\\"/[]?={} \t") {
		return nil, fmt.Errorf("pending: invalid cookie prefix %q", t.prefix)
	}
	return t, nil
}

// payload is what a cookie holds.
type payload struct {
	ID         string `json:"i"`
	RelayState string `json:"r"`
	Expires    int64  `json:"e"`
	Data       string `json:"d,omitempty"`
}

// Remember sets the cookie that remembers msg, an AuthnRequest made by
// Config.AuthnRequest, until Take finds it, with data for the application,
// such as where to send the user after login. Call it before msg.Write.
//
// It returns an error if msg has no ID, or if data is too large for a
// cookie.
func (t *Tracker) Remember(w http.ResponseWriter, msg *samlsp.Message, data string) error {
	if msg == nil || msg.ID == "" {
		return errors.New("pending: the message has no ID")
	}
	p := payload{
		ID:         msg.ID,
		RelayState: msg.RelayState,
		Expires:    t.clock.Now().Add(t.maxAge).Unix(),
		Data:       data,
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	name := t.cookieName(msg.RelayState)
	value := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(t.mac(name, body))
	if len(name)+len(value) > maxCookieSize {
		return fmt.Errorf("pending: the login cookie would be %d bytes, more than %d", len(name)+len(value), maxCookieSize)
	}
	http.SetCookie(w, t.cookie(name, value, int(t.maxAge/time.Second)))
	return nil
}

// Take returns the login in progress that the Response in r answers, found
// by the Response's RelayState, and clears its cookie, so that it is found
// once. Call it in the ACS handler, before Config.ParseResponse.
//
// It returns ErrNotFound if there is no login in progress for the
// RelayState in this browser, and ErrInvalid if its cookie is not valid. An
// ACS that also accepts IdP-initiated logins with samlsp.AllowUnsolicited
// passes samlsp.WithRequestID only when Take succeeds.
func (t *Tracker) Take(w http.ResponseWriter, r *http.Request) (*Login, error) {
	relayState := r.FormValue("RelayState")
	name := t.cookieName(relayState)
	c, err := r.Cookie(name)
	if err != nil {
		return nil, ErrNotFound
	}
	http.SetCookie(w, t.cookie(name, "", -1))

	encBody, encMAC, ok := strings.Cut(c.Value, ".")
	if !ok {
		return nil, ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(encBody)
	if err != nil {
		return nil, ErrInvalid
	}
	mac, err := base64.RawURLEncoding.DecodeString(encMAC)
	if err != nil || !hmac.Equal(mac, t.mac(name, body)) {
		return nil, ErrInvalid
	}
	var p payload
	if err := json.Unmarshal(body, &p); err != nil || p.RelayState != relayState || p.ID == "" {
		return nil, ErrInvalid
	}
	expires := time.Unix(p.Expires, 0)
	if !t.clock.Now().Before(expires) {
		return nil, ErrNotFound
	}
	return &Login{ID: p.ID, RelayState: p.RelayState, Data: p.Data, Expires: expires}, nil
}

// cookieName returns the name of the cookie for relayState. The RelayState
// is hashed, since it may hold characters that a cookie name cannot.
func (t *Tracker) cookieName(relayState string) string {
	sum := sha256.Sum256([]byte(relayState))
	return t.prefix + base64.RawURLEncoding.EncodeToString(sum[:16])
}

// mac authenticates body as the content of the cookie named name.
func (t *Tracker) mac(name string, body []byte) []byte {
	h := hmac.New(sha256.New, t.key)
	h.Write([]byte("crewjam/saml/x/samlsp/pending v1\x00"))
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil)
}

func (t *Tracker) cookie(name, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{ //nolint:gosec // G124: Secure and SameSite=None are set below when the ACS is https; plain http keeps the browser default
		Name:     name,
		Value:    value,
		Path:     t.path,
		Domain:   t.domain,
		MaxAge:   maxAge,
		HttpOnly: true,
	}
	if t.secure {
		// The IdP's Response arrives with a cross-site POST.
		c.Secure, c.SameSite = true, http.SameSiteNoneMode
	}
	return c
}
