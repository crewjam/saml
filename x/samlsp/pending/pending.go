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
// one of a fixed set of cookies, its slots:
//
//	tracker, err := pending.New(config, cookieKey)
//
//	func login(w http.ResponseWriter, r *http.Request) {
//		next, _ := samlsp.SafeRedirectPath(r.URL.Query().Get("next"))
//		if len(next) > 100 {
//			next = "/"
//		}
//		msg, err := config.AuthnRequest(r.Context(), rand.Text())
//		if err != nil { ... }
//		if err := tracker.Remember(w, msg, next); err != nil { ... }
//		msg.Write(w)
//	}
//
//	func acs(w http.ResponseWriter, r *http.Request) {
//		login, err := tracker.Find(w, r)
//		if err != nil { ... } // no login in progress in this browser
//		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID))
//		if err != nil { ... }
//		tracker.Forget(w, login)
//		startSession(w, assertion)
//		next, _ := samlsp.SafeRedirectPath(login.Data)
//		http.Redirect(w, r, next, http.StatusFound)
//	}
//
// The cookie is authenticated with an HMAC key, so the browser cannot
// change the request ID, the RelayState it belongs to, its expiry, the
// application's data or the slot it is in. It is not encrypted: do not put
// secrets in the data. Every server that serves the ACS must use the same
// key.
//
// The cookie's path is that of the ACS URL, so the browser sends it there
// only. Since the IdP sends its Response with a cross-site POST, which
// browsers do not send SameSite=Lax cookies with, the cookie is
// SameSite=None and Secure when the ACS URL uses https. With an http ACS
// URL, meant for local development, the cookie has no SameSite attribute
// and is not Secure, and whether browsers send it with a cross-site POST
// depends on the browser.
//
// # Slots
//
// There are DefaultSlots slot cookies, or as many as WithSlots says, named
// the cookie prefix followed by the slot's number. Remember picks the slot
// from a hash of the RelayState and sets that cookie only: it does not
// read or rewrite the others, which the browser sends to the ACS only.
// Find finds the login whose RelayState is that of the Response among the
// slots, and Forget clears its slot once the Response is verified.
// Find also clears the slots of expired and invalid logins.
//
// However many logins a browser starts and abandons, it sends the ACS at
// most one cookie per slot: with a 26-character RelayState, such as
// rand.Text, and a 20-byte return path as data, a slot cookie takes about
// 210 bytes of the Cookie header, so all 16 default slots take about
// 3.3 KB, well within the 8 KB of headers that proxies often allow.
// Larger data makes each slot larger, so Remember refuses a cookie larger
// than its share of DefaultMaxCookiesSize (WithMaxCookiesSize): 384 bytes
// with 16 slots, which leaves room for about 150 bytes of data. Without
// that bound, a site that can send the user's browser to the login URL,
// with data such as a long return path taken from the URL, could fill
// every slot with a large cookie, and the proxy would refuse the requests
// to the ACS, and so every login, until they expire. Keep larger data on
// the server, and only its key in the cookie.
//
// Logins started in several tabs of one browser do not disturb each other
// unless their RelayStates fall in the same slot. The later login then
// replaces the earlier one, which fails with ErrNotFound when its Response
// arrives, and the user must start it again. With 16 slots, this happens
// to one of two logins in progress at the same time with probability 1/16
// (6%), and to some login among three or four with probability 18% or
// 33%; logins that were abandoned or finished take no part. A single
// cookie holding every login in progress would fare worse: Remember would
// have to read it, add to it and write it back, but the browser does not
// send it there, and of two logins started at once the last Set-Cookie
// would drop the other every time. More slots make collisions rarer and
// the header larger.
//
// # Security
//
// The cookie binds the Response to the browser that started the login, but
// only as strongly as cookies are bound to the site. A host that can set
// cookies for the domain of the ACS, such as a sibling subdomain under the
// same registrable domain, can plant in the browser a cookie that Remember
// set in the attacker's own browser (cookie tossing), and so log the user
// in to the attacker's account (login CSRF). Where other hosts of the
// domain are not trusted, begin the cookie prefix with __Host-
// (WithCookiePrefix): browsers accept such a cookie only from the host
// itself, over https, with Path "/" (WithPath) and no Domain.
//
// The RelayState should be unpredictable, such as rand.Text. Forget
// clears a login's slot only once ParseResponse has accepted its Response,
// so a junk Response that a site makes the browser post with the user's
// RelayState does not cancel the login in progress; but the RelayState
// travels in the URL of the AuthnRequest, which the IdP sees, and may log,
// and one that says where to return, or counts logins, gives away more
// than it need.
//
// An SP that trusts several IdPs should record in the data passed to
// Remember which IdP it sent the AuthnRequest to, and check after
// ParseResponse that the assertion's Issuer is that IdP: the pending
// login says which request a Response answers, not which IdP must answer
// it.
//
// This package is built only on the public API of x/samlsp, which itself
// leaves sessions and cookies to the application. Applications that keep
// pending logins elsewhere, such as in a server-side session, need not use
// it.
package pending

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/x/samlsp"
)

// DefaultMaxAge is how long a login may stay in progress, unless WithMaxAge
// says otherwise. It leaves the user time to authenticate at the IdP,
// including with a second factor.
const DefaultMaxAge = 10 * time.Minute

// DefaultCookiePrefix begins the name of each slot cookie, unless
// WithCookiePrefix says otherwise.
const DefaultCookiePrefix = "saml_pending_"

// MinKeyLength is the shortest HMAC key that New accepts, in bytes.
const MinKeyLength = 32

// DefaultSlots is how many slot cookies keep logins in progress, unless
// WithSlots says otherwise.
const DefaultSlots = 16

// MaxSlots is the most slot cookies WithSlots accepts.
const MaxSlots = 64

// browserCookieLimit is the largest cookie Remember writes. Browsers keep
// cookies of at least 4096 bytes, name and attributes included.
const browserCookieLimit = 3800

// DefaultMaxCookiesSize is how many bytes of the Cookie header all the
// slot cookies together may take, unless WithMaxCookiesSize says
// otherwise: each takes at most this divided by the number of slots.
const DefaultMaxCookiesSize = 6 << 10

// ErrNotFound is returned by Find when the request carries no
// cookie for its RelayState, or when the cookie has expired: no login is
// in progress in this browser for the Response. This is the case of an IdP-initiated
// login, of a Response sent twice, of a user who took longer than MaxAge,
// and of a login replaced by a later one in the same slot.
var ErrNotFound = errors.New("pending: no login in progress for this RelayState")

// ErrInvalid is returned by Find when no slot holds a login for
// the RelayState and the cookie of the RelayState's slot was not made by
// Remember with this Tracker's key: it was changed, made with another
// key, or made for another slot.
var ErrInvalid = errors.New("pending: the login cookie is not valid")

// Login is a login in progress that Find found.
type Login struct {
	// ID is the ID of the AuthnRequest. Pass it to ParseResponse with
	// samlsp.WithRequestID.
	ID string

	// RelayState is the RelayState of the AuthnRequest.
	RelayState string

	// Data is the data passed to Remember, such as where to send the
	// user after login. The browser cannot change it, but it is only as
	// trustworthy as what Remember was given. Check a return path with
	// samlsp.SafeRedirectPath before redirecting to it: browsers read
	// many paths that merely start with "/" as naming another host, such
	// as "//evil.example", "/\evil.example" and "/<tab>/evil.example".
	Data string

	// Expires is when the login would have stopped being accepted.
	Expires time.Time

	// slot is the name of the slot cookie the login was found in, which
	// Forget clears.
	slot string
}

// Tracker keeps logins in progress in cookies. Create one with New. It is
// safe for concurrent use.
type Tracker struct {
	key    []byte
	prefix string
	path   string
	domain string
	secure bool
	slots  int
	maxAge time.Duration
	clock  *dsig.Clock

	maxCookiesSize int
}

// Option configures New.
type Option func(*Tracker)

// WithMaxAge sets how long a login may stay in progress. The default is
// DefaultMaxAge.
func WithMaxAge(d time.Duration) Option { return func(t *Tracker) { t.maxAge = d } }

// WithSlots sets how many slot cookies keep logins in progress, from 1 to
// MaxSlots. The default is DefaultSlots. Changing it moves RelayStates to
// other slots, but Find still finds the logins in progress.
func WithSlots(n int) Option { return func(t *Tracker) { t.slots = n } }

// WithMaxCookiesSize sets how many bytes of the Cookie header all the slot
// cookies together may take: Remember refuses a cookie larger than this
// divided by the number of slots. The default is DefaultMaxCookiesSize.
// Keep it well below the header size the servers and proxies in front of
// the ACS allow.
func WithMaxCookiesSize(n int) Option { return func(t *Tracker) { t.maxCookiesSize = n } }

// WithCookiePrefix sets what the name of each slot cookie begins with,
// before the slot's number. The default is DefaultCookiePrefix.
//
// Browsers reject a cookie whose name begins with __Secure- unless it is
// Secure, and one whose name begins with __Host- unless it is also
// host-only, with Path "/" (RFC 6265bis §4.1.3), whatever the case of the
// prefix. New returns an error for such a prefix unless the ACS URL uses
// https and, for __Host-, WithPath sets "/" and WithDomain is not used:
// otherwise browsers would reject every slot cookie, and every login fail.
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
		path:   acs.EscapedPath(),
		secure: acs.Scheme == "https",
		slots:  DefaultSlots,
		maxAge: DefaultMaxAge,

		maxCookiesSize: DefaultMaxCookiesSize,
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
	if t.slots < 1 || t.slots > MaxSlots {
		return nil, fmt.Errorf("pending: the number of slots must be from 1 to %d, not %d", MaxSlots, t.slots)
	}
	if t.maxCookieSize() < minCookieSize {
		return nil, fmt.Errorf("pending: %d bytes for %d slot cookies leaves too little for each (see WithMaxCookiesSize)", t.maxCookiesSize, t.slots)
	}
	if t.prefix == "" || strings.ContainsAny(t.prefix, "()<>@,;:\\\"/[]?={} \t") {
		return nil, fmt.Errorf("pending: invalid cookie prefix %q", t.prefix)
	}
	// Browsers match the prefixes case-insensitively (RFC 6265bis §4.1.3).
	switch prefix := strings.ToLower(t.prefix); {
	case strings.HasPrefix(prefix, "__host-") && (!t.secure || t.path != "/" || t.domain != ""):
		return nil, fmt.Errorf("pending: browsers reject cookies whose names begin with %q unless the ACS URL uses https, its Path is \"/\" (WithPath) and it has no Domain", t.prefix)
	case strings.HasPrefix(prefix, "__secure-") && !t.secure:
		return nil, fmt.Errorf("pending: browsers reject cookies whose names begin with %q unless the ACS URL uses https", t.prefix)
	}
	return t, nil
}

// minCookieSize is the least room for a slot cookie that New accepts:
// enough for a 26-character RelayState and a short return path.
const minCookieSize = 256

// maxCookieSize returns how many bytes of the Cookie header one slot
// cookie may take.
func (t *Tracker) maxCookieSize() int {
	return min(browserCookieLimit, t.maxCookiesSize/t.slots)
}

// payload is what a cookie holds.
type payload struct {
	ID         string `json:"i"`
	RelayState string `json:"r"`
	Expires    int64  `json:"e"`
	Data       string `json:"d,omitempty"`
}

// Remember sets the slot cookie that remembers msg, an AuthnRequest made
// by Config.AuthnRequest, until Find finds it, with data for the
// application, such as where to send the user after login. Call it before
// msg.Write. It replaces the login in progress in the same slot, if any,
// and leaves the other slots alone.
//
// It returns an error if msg has no ID, or if the cookie would take more
// than its share of the Cookie header (see WithMaxCookiesSize): keep data
// short, such as a local return path, and check its length when it comes
// from the request.
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
	name := t.cookieName(t.slot(msg.RelayState))
	value := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(t.mac(name, body))
	// The cookie takes "name=value; " of the Cookie header.
	if size := len(name) + 1 + len(value) + 2; size > t.maxCookieSize() {
		return fmt.Errorf("pending: the login cookie would take %d bytes of the Cookie header, more than %d (see WithMaxCookiesSize)", size, t.maxCookieSize())
	}
	http.SetCookie(w, t.cookie(name, value, int(t.maxAge/time.Second)))
	return nil
}

// Find returns the login in progress that the Response in r answers,
// found by the Response's RelayState among the slots, without clearing its
// slot. Call it in the ACS handler, before Config.ParseResponse, and call
// Forget once ParseResponse has accepted the Response: a Response that
// fails, such as a junk one that a site made the browser post with the
// user's RelayState, then leaves the login in progress for the real one.
// Find clears, with w, the slots of expired and invalid logins, which no
// Response can use, but no slot of a login in progress.
//
// It returns ErrNotFound if there is no login in progress for the
// RelayState in this browser, and ErrInvalid if there is none and the
// cookie of the RelayState's slot is not valid. An ACS that also accepts
// IdP-initiated logins with samlsp.AllowUnsolicited passes
// samlsp.WithRequestID only when Find succeeds.
func (t *Tracker) Find(w http.ResponseWriter, r *http.Request) (*Login, error) {
	relayState := r.FormValue("RelayState")
	own := t.cookieName(t.slot(relayState))
	now := t.clock.Now().Unix()
	var (
		login            *Login
		expired, invalid bool
		stale            []string // the slots of expired and invalid logins
	)
	for _, c := range r.Cookies() {
		if !t.isSlot(c.Name) {
			continue
		}
		p, ok := t.open(c.Name, c.Value)
		switch {
		case !ok:
			invalid = invalid || c.Name == own
			stale = append(stale, c.Name)
		case now >= p.Expires:
			expired = expired || subtle.ConstantTimeCompare([]byte(p.RelayState), []byte(relayState)) == 1
			stale = append(stale, c.Name)
		case login == nil && subtle.ConstantTimeCompare([]byte(p.RelayState), []byte(relayState)) == 1:
			login = &Login{ID: p.ID, RelayState: p.RelayState, Data: p.Data, Expires: time.Unix(p.Expires, 0), slot: c.Name}
		}
	}
	// A browser may send two cookies of one name, such as one tossed by
	// another host of the domain: clearing either clears the login's.
	cleared := map[string]bool{}
	for _, name := range stale {
		if !cleared[name] && (login == nil || name != login.slot) {
			cleared[name] = true
			http.SetCookie(w, t.cookie(name, "", -1))
		}
	}
	switch {
	case login != nil:
		return login, nil
	case invalid && !expired:
		return nil, ErrInvalid
	default:
		return nil, ErrNotFound
	}
}

// Forget clears the slot of login, a login that Find returned, so that it
// is found no more. Call it once Config.ParseResponse has accepted the
// Response that login answers. It does nothing if login is nil.
//
// A browser that ignores the clearing can present the cookie again until
// it expires, so a login may be found more than once; ParseResponse still
// accepts each assertion only once (see samlsp.WithReplayState).
func (t *Tracker) Forget(w http.ResponseWriter, login *Login) {
	if login == nil {
		return
	}
	name := login.slot
	if name == "" {
		name = t.cookieName(t.slot(login.RelayState))
	}
	http.SetCookie(w, t.cookie(name, "", -1))
}

// open returns the payload of the cookie named name whose value is value,
// and false if the cookie was not made by Remember with t's key.
func (t *Tracker) open(name, value string) (payload, bool) {
	var p payload
	encBody, encMAC, ok := strings.Cut(value, ".")
	if !ok {
		return p, false
	}
	body, err := base64.RawURLEncoding.DecodeString(encBody)
	if err != nil {
		return p, false
	}
	mac, err := base64.RawURLEncoding.DecodeString(encMAC)
	if err != nil || !hmac.Equal(mac, t.mac(name, body)) {
		return p, false
	}
	if err := json.Unmarshal(body, &p); err != nil || p.ID == "" {
		return p, false
	}
	return p, true
}

// slot returns the slot of relayState.
func (t *Tracker) slot(relayState string) int {
	sum := sha256.Sum256([]byte(relayState))
	return int(binary.BigEndian.Uint64(sum[:]) % uint64(t.slots)) //nolint:gosec // G115: less than MaxSlots
}

// cookieName returns the name of the cookie of slot.
func (t *Tracker) cookieName(slot int) string {
	return t.prefix + strconv.Itoa(slot)
}

// isSlot reports whether name is that of a slot cookie, of this Tracker or
// of one with other WithSlots, up to MaxSlots.
func (t *Tracker) isSlot(name string) bool {
	n, ok := strings.CutPrefix(name, t.prefix)
	if !ok {
		return false
	}
	i, err := strconv.Atoi(n)
	return err == nil && i >= 0 && i < MaxSlots && t.cookieName(i) == name
}

// macSize is the length of a cookie's MAC: HMAC-SHA256 truncated to 128
// bits, which keeps slot cookies small and forgeries out of reach.
const macSize = 16

// mac authenticates body as the content of the cookie named name.
func (t *Tracker) mac(name string, body []byte) []byte {
	h := hmac.New(sha256.New, t.key)
	h.Write([]byte("crewjam/saml/x/samlsp/pending v2\x00"))
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil)[:macSize]
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
