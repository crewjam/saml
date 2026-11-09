// Package pendinglogout remembers each single logout that a service
// provider starts, between the LogoutRequest it sends to the identity
// provider and the LogoutResponse that comes back to its single logout
// service, in a cookie in the user's browser.
//
// slo.Service.ParseResponse in github.com/crewjam/saml/x/samlsp/slo
// accepts a LogoutResponse only if it answers a LogoutRequest whose ID the
// application passes to it (its InResponseTo, saml-core §3.2.2). The
// application must keep that ID until the response arrives; a Tracker
// keeps it, with the request's RelayState, in one of a fixed set of
// cookies, its slots, as package github.com/crewjam/saml/x/samlsp/pending
// does for logins:
//
//	tracker, err := pendinglogout.New(logout, cookieKey)
//
//	func startLogout(w http.ResponseWriter, r *http.Request) {
//		s := currentSession(r)
//		endSession(w, r) // first, so the user is logged out even if the IdP never answers
//		msg, err := logout.Request(r.Context(), s.NameID, rand.Text(), slo.WithSessionIndex(s.SessionIndexes...))
//		if err != nil { ... }
//		if err := tracker.Remember(w, msg, ""); err != nil { ... }
//		msg.Write(w)
//	}
//
//	func sloHandler(w http.ResponseWriter, r *http.Request) {
//		if slo.IsResponse(r) {
//			l, err := tracker.Find(w, r)
//			if err != nil { ... } // no logout in progress in this browser
//			_, err = logout.ParseResponse(r.Context(), r, l.RequestIDs()...)
//			if pendinglogout.Answered(err) {
//				tracker.Forget(w, l)
//			}
//			...
//		}
//	}
//
// The cookie is authenticated with an HMAC key, so the browser cannot
// change the request ID, the RelayState it belongs to, its expiry, the
// application's data or the slot it is in. It is not encrypted: do not put
// secrets in the data. Every server that serves the SLO URL must use the
// same key. The key may be the one a pending.Tracker uses: the MACs of the
// two packages are kept apart.
//
// The cookie's path is that of the SLO URL (slo.Service.Path), so the
// browser sends it there only. The IdP may send its LogoutResponse with a
// cross-site POST (HTTP-POST binding), which browsers do not send
// SameSite=Lax cookies with, so the cookie is SameSite=None and Secure
// when the SLO URL uses https. With an http SLO URL, meant for local
// development, the cookie has no SameSite attribute and is not Secure.
//
// # Slots
//
// There are DefaultSlots slot cookies, or as many as WithSlots says, named
// the cookie prefix followed by the slot's number. Remember picks the slot
// from a hash of the RelayState and sets that cookie only. Find finds the
// logout whose RelayState is that of the LogoutResponse among the slots,
// and Forget clears its slot once the response is verified. Find also
// clears the slots of expired and invalid logouts.
//
// A browser rarely has more than one logout in progress, so there are
// fewer slots than for logins. Two logouts started at once in one browser
// do not disturb each other unless their RelayStates fall in the same
// slot; the later then replaces the earlier, whose LogoutResponse is
// refused with ErrNotFound. The user is still logged out of the SP, whose
// session the application ended before sending the LogoutRequest. Remember
// refuses a cookie larger than its share of DefaultMaxCookiesSize
// (WithMaxCookiesSize), so that a site that can make the browser start
// logouts cannot fill the Cookie header of requests to the SLO URL.
//
// # Security
//
// A LogoutResponse says only that the IdP ended its session: the
// application ends its own session when the logout starts, so a
// LogoutResponse accepted in the wrong browser does not log anyone in or
// out. Tracking the request in the browser that sent it still keeps a
// response from being reported to another user, and lets
// slo.Service.ParseResponse check InResponseTo as saml-profiles §4.4.4.2
// requires.
//
// Where other hosts of the SLO URL's domain are not trusted, begin the
// cookie prefix with __Host- (WithCookiePrefix): browsers accept such a
// cookie only from the host itself, over https, with Path "/" (WithPath)
// and no Domain.
//
// The RelayState should be unpredictable, such as rand.Text. Forget clears
// a logout's slot only once ParseResponse has verified its response, so
// that a junk response posted with the user's RelayState does not cancel
// the logout in progress.
//
// An SP that trusts several IdPs should record in the data passed to
// Remember which IdP it sent the LogoutRequest to, and verify the response
// with that IdP's metadata.
//
// This package is built only on the public APIs of x/samlsp and
// x/samlsp/slo. Applications that keep logouts in progress elsewhere, such
// as in a server-side store keyed by RelayState, need not use it.
package pendinglogout

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

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
)

// DefaultMaxAge is how long a logout may stay in progress, unless
// WithMaxAge says otherwise.
const DefaultMaxAge = 10 * time.Minute

// DefaultCookiePrefix begins the name of each slot cookie, unless
// WithCookiePrefix says otherwise.
const DefaultCookiePrefix = "saml_logout_"

// MinKeyLength is the shortest HMAC key that New accepts, in bytes.
const MinKeyLength = 32

// DefaultSlots is how many slot cookies keep logouts in progress, unless
// WithSlots says otherwise.
const DefaultSlots = 4

// MaxSlots is the most slot cookies WithSlots accepts.
const MaxSlots = 64

// browserCookieLimit is the largest cookie Remember writes. Browsers keep
// cookies of at least 4096 bytes, name and attributes included.
const browserCookieLimit = 3800

// DefaultMaxCookiesSize is how many bytes of the Cookie header all the
// slot cookies together may take, unless WithMaxCookiesSize says
// otherwise: each takes at most this divided by the number of slots.
const DefaultMaxCookiesSize = 2 << 10

// minCookieSize is the least room for a slot cookie that New accepts:
// enough for a request ID, a 26-character RelayState and short data.
const minCookieSize = 256

// ErrNotFound is returned by Find when the request carries no cookie for
// its RelayState, or when the cookie has expired: no logout is in progress
// in this browser for the LogoutResponse. This is the case of a response
// sent twice, of an IdP that took longer than the max age, and of a logout
// replaced by a later one in the same slot.
var ErrNotFound = errors.New("pendinglogout: no logout in progress for this RelayState")

// ErrInvalid is returned by Find when no slot holds a logout for the
// RelayState and the cookie of the RelayState's slot was not made by
// Remember with this Tracker's key: it was changed, made with another key,
// or made for another slot.
var ErrInvalid = errors.New("pendinglogout: the logout cookie is not valid")

// Logout is a logout in progress that Find found.
type Logout struct {
	// ID is the ID of the LogoutRequest. Pass it to
	// slo.Service.ParseResponse, as RequestIDs does.
	ID string

	// RelayState is the RelayState of the LogoutRequest.
	RelayState string

	// Data is the data passed to Remember. The browser cannot change it,
	// but it is only as trustworthy as what Remember was given.
	Data string

	// Expires is when the logout would have stopped being found.
	Expires time.Time

	// slot is the name of the slot cookie the logout was found in, which
	// Forget clears.
	slot string
}

// RequestIDs returns the request IDs to pass to slo.Service.ParseResponse:
// the ID of the LogoutRequest, or none if l is nil, so that
//
//	logout.ParseResponse(ctx, r, l.RequestIDs()...)
//
// refuses the response with slo.ErrNoRequestID when there is no logout in
// progress.
func (l *Logout) RequestIDs() []string {
	if l == nil {
		return nil
	}
	return []string{l.ID}
}

// Answered reports whether err, returned by slo.Service.ParseResponse,
// means that the response was verified and answers the logout: it is nil,
// or says that the IdP logged the user out only in part
// (slo.ErrPartialLogout) or not at all (saml.ErrBadStatus). The logout is
// then over, whatever its outcome, and Forget should clear it. Any other
// error means that the response was refused, and leaves the logout in
// progress for the real one.
func Answered(err error) bool {
	var status saml.ErrBadStatus
	return err == nil || errors.Is(err, slo.ErrPartialLogout) || errors.As(err, &status)
}

// Tracker keeps logouts in progress in cookies. Create one with New. It is
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

// WithMaxAge sets how long a logout may stay in progress. The default is
// DefaultMaxAge.
func WithMaxAge(d time.Duration) Option { return func(t *Tracker) { t.maxAge = d } }

// WithSlots sets how many slot cookies keep logouts in progress, from 1 to
// MaxSlots. The default is DefaultSlots.
func WithSlots(n int) Option { return func(t *Tracker) { t.slots = n } }

// WithMaxCookiesSize sets how many bytes of the Cookie header all the slot
// cookies together may take: Remember refuses a cookie larger than this
// divided by the number of slots. The default is DefaultMaxCookiesSize.
func WithMaxCookiesSize(n int) Option { return func(t *Tracker) { t.maxCookiesSize = n } }

// WithCookiePrefix sets what the name of each slot cookie begins with,
// before the slot's number. The default is DefaultCookiePrefix.
//
// Browsers reject a cookie whose name begins with __Secure- unless it is
// Secure, and one whose name begins with __Host- unless it is also
// host-only, with Path "/" (RFC 6265bis §4.1.3), whatever the case of the
// prefix. New returns an error for such a prefix unless the SLO URL uses
// https and, for __Host-, WithPath sets "/" and WithDomain is not used.
func WithCookiePrefix(prefix string) Option { return func(t *Tracker) { t.prefix = prefix } }

// WithDomain sets the Domain attribute of the cookies, so that hosts below
// it receive them too. By default they are host-only.
func WithDomain(domain string) Option { return func(t *Tracker) { t.domain = domain } }

// WithPath sets the Path attribute of the cookies. The default is the path
// of the SLO URL. Set it when the SLO handler is reached at another path,
// such as behind a reverse proxy that rewrites paths.
func WithPath(path string) Option { return func(t *Tracker) { t.path = path } }

// WithClock sets the time source for the expiry of logouts. It is mainly
// useful in tests.
func WithClock(clock *dsig.Clock) Option { return func(t *Tracker) { t.clock = clock } }

// New returns a Tracker for the logouts that logout starts, whose cookies
// are authenticated with key. key must be at least MinKeyLength random
// bytes, kept secret and shared by every server that serves the SLO URL;
// pending.DeriveKey can derive it from another secret. Changing it fails
// the logouts in progress.
func New(logout *slo.Service, key []byte, opts ...Option) (*Tracker, error) {
	if logout == nil {
		return nil, errors.New("pendinglogout: the slo.Service is nil")
	}
	if len(key) < MinKeyLength {
		return nil, fmt.Errorf("pendinglogout: the key must be at least %d bytes, not %d", MinKeyLength, len(key))
	}
	u, err := url.Parse(logout.URL())
	if err != nil {
		return nil, fmt.Errorf("pendinglogout: invalid SLO URL: %w", err)
	}
	t := &Tracker{
		key:    append([]byte(nil), key...),
		prefix: DefaultCookiePrefix,
		path:   logout.Path(),
		secure: u.Scheme == "https",
		slots:  DefaultSlots,
		maxAge: DefaultMaxAge,

		maxCookiesSize: DefaultMaxCookiesSize,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(t)
		}
	}
	if t.maxAge <= 0 {
		return nil, errors.New("pendinglogout: the max age must be positive")
	}
	if t.slots < 1 || t.slots > MaxSlots {
		return nil, fmt.Errorf("pendinglogout: the number of slots must be from 1 to %d, not %d", MaxSlots, t.slots)
	}
	if t.maxCookieSize() < minCookieSize {
		return nil, fmt.Errorf("pendinglogout: %d bytes for %d slot cookies leaves too little for each (see WithMaxCookiesSize)", t.maxCookiesSize, t.slots)
	}
	if t.prefix == "" || strings.ContainsAny(t.prefix, "()<>@,;:\\\"/[]?={} \t") {
		return nil, fmt.Errorf("pendinglogout: invalid cookie prefix %q", t.prefix)
	}
	// Browsers match the prefixes case-insensitively (RFC 6265bis §4.1.3).
	switch prefix := strings.ToLower(t.prefix); {
	case strings.HasPrefix(prefix, "__host-") && (!t.secure || t.path != "/" || t.domain != ""):
		return nil, fmt.Errorf("pendinglogout: browsers reject cookies whose names begin with %q unless the SLO URL uses https, its Path is \"/\" (WithPath) and it has no Domain", t.prefix)
	case strings.HasPrefix(prefix, "__secure-") && !t.secure:
		return nil, fmt.Errorf("pendinglogout: browsers reject cookies whose names begin with %q unless the SLO URL uses https", t.prefix)
	}
	return t, nil
}

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

// Remember sets the slot cookie that remembers msg, a LogoutRequest made
// by slo.Service.Request, until Find finds it, with data for the
// application, such as where to send the user once logged out. Call it
// before msg.Write. It replaces the logout in progress in the same slot,
// if any, and leaves the other slots alone.
//
// It returns an error if msg has no ID, or if the cookie would take more
// than its share of the Cookie header (see WithMaxCookiesSize): keep data
// short.
func (t *Tracker) Remember(w http.ResponseWriter, msg *samlsp.Message, data string) error {
	if msg == nil || msg.ID == "" {
		return errors.New("pendinglogout: the message has no ID")
	}
	body, err := json.Marshal(payload{
		ID:         msg.ID,
		RelayState: msg.RelayState,
		Expires:    t.clock.Now().Add(t.maxAge).Unix(),
		Data:       data,
	})
	if err != nil {
		return err
	}
	name := t.cookieName(t.slot(msg.RelayState))
	value := base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(t.mac(name, body))
	// The cookie takes "name=value; " of the Cookie header.
	if size := len(name) + 1 + len(value) + 2; size > t.maxCookieSize() {
		return fmt.Errorf("pendinglogout: the logout cookie would take %d bytes of the Cookie header, more than %d (see WithMaxCookiesSize)", size, t.maxCookieSize())
	}
	http.SetCookie(w, t.cookie(name, value, int(t.maxAge/time.Second)))
	return nil
}

// Find returns the logout in progress that the LogoutResponse in r
// answers, found by the response's RelayState among the slots, without
// clearing its slot. Call it in the SLO handler, before
// slo.Service.ParseResponse, and call Forget once ParseResponse has
// verified the response (see Answered). Find clears, with w, the slots of
// expired and invalid logouts, but no slot of a logout in progress.
//
// It returns ErrNotFound if there is no logout in progress for the
// RelayState in this browser, ErrInvalid if there is none and the cookie
// of the RelayState's slot is not valid, and another error if the form
// cannot be read. It reads the RelayState with r.ParseForm, from the
// urlencoded body of a POST or else from the query, as ParseResponse
// does; it does not read a multipart body, whose files could be spooled to
// disk.
func (t *Tracker) Find(w http.ResponseWriter, r *http.Request) (*Logout, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("pendinglogout: cannot read the form: %w", err)
	}
	relayState := r.Form.Get("RelayState")
	own := t.cookieName(t.slot(relayState))
	now := t.clock.Now().Unix()
	var (
		found            *Logout
		expired, invalid bool
		stale            []string // the slots of expired and invalid logouts
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
		case found == nil && subtle.ConstantTimeCompare([]byte(p.RelayState), []byte(relayState)) == 1:
			found = &Logout{ID: p.ID, RelayState: p.RelayState, Data: p.Data, Expires: time.Unix(p.Expires, 0), slot: c.Name}
		}
	}
	// A browser may send two cookies of one name, such as one tossed by
	// another host of the domain: clearing either clears the logout's.
	cleared := map[string]bool{}
	for _, name := range stale {
		if !cleared[name] && (found == nil || name != found.slot) {
			cleared[name] = true
			http.SetCookie(w, t.cookie(name, "", -1))
		}
	}
	switch {
	case found != nil:
		return found, nil
	case invalid && !expired:
		return nil, ErrInvalid
	default:
		return nil, ErrNotFound
	}
}

// Forget clears the slot of l, a logout that Find returned, so that it is
// found no more. Call it once slo.Service.ParseResponse has verified the
// LogoutResponse that l answers, whatever its status (see Answered). It
// does nothing if l is nil.
//
// A browser that ignores the clearing can present the cookie again until
// it expires; ParseResponse still accepts each response only once (see
// samlsp.WithReplayState).
func (t *Tracker) Forget(w http.ResponseWriter, l *Logout) {
	if l == nil {
		return
	}
	name := l.slot
	if name == "" {
		name = t.cookieName(t.slot(l.RelayState))
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
// bits.
const macSize = 16

// macLabel separates the MACs of this package from those of package
// pending, so that both may use one key.
const macLabel = "crewjam/saml/x/samlsp/slo/pendinglogout v1\x00"

// mac authenticates body as the content of the cookie named name.
func (t *Tracker) mac(name string, body []byte) []byte {
	h := hmac.New(sha256.New, t.key)
	h.Write([]byte(macLabel))
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write(body)
	return h.Sum(nil)[:macSize]
}

func (t *Tracker) cookie(name, value string, maxAge int) *http.Cookie {
	c := &http.Cookie{ //nolint:gosec // G124: Secure and SameSite=None are set below when the SLO URL is https; plain http keeps the browser default
		Name:     name,
		Value:    value,
		Path:     t.path,
		Domain:   t.domain,
		MaxAge:   maxAge,
		HttpOnly: true,
	}
	if t.secure {
		// The IdP's LogoutResponse may arrive with a cross-site POST.
		c.Secure, c.SameSite = true, http.SameSiteNoneMode
	}
	return c
}
