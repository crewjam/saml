// Package idppending keeps the AuthnRequest that an identity provider
// (IdP) has yet to answer, while the user logs in, in an encrypted cookie
// in the user's browser, so that it is answered in that browser only, and
// only once.
//
// ParseAuthnRequest in github.com/crewjam/saml/x/samlidp returns a
// samlidp.AuthnRequest: plain data, whose fields Response trusts. When the
// user must first log in, or consent, the application must keep it across
// the login page, where the browser cannot change it, and delete it once it
// is answered: Response does not stop it from being answered twice. Kept in
// a hidden form field or an unauthenticated cookie, it could be swapped for
// another request, such as one whose RelayState or ForceAuthn suits an
// attacker; kept after it is answered, a second tab, or the back button,
// could get a second assertion for it. A Tracker keeps it in one of a fixed
// set of cookies, its slots, and gives the application a handle that names
// it, to carry to the login page in the URL or in a form field:
//
//	tracker, err := idppending.New(config, cookieKey)
//
//	func sso(w http.ResponseWriter, r *http.Request) {
//		req, err := config.ParseAuthnRequest(r.Context(), r)
//		... // answer at once if the user has a session it can use
//		handle, err := tracker.Remember(w, r, req)
//		if err != nil { ... }
//		http.Redirect(w, r, "/login?"+url.Values{"p": {handle}}.Encode(), http.StatusFound)
//	}
//
//	func login(w http.ResponseWriter, r *http.Request) {
//		if err := r.ParseForm(); err != nil { ... }
//		user := checkPassword(r.PostForm) // and render the form again if wrong
//		req, err := tracker.Take(w, r, r.PostForm.Get("p"))
//		if err != nil { ... } // expired, already answered, or from another browser
//		msg, err := config.Response(r.Context(), req, subjectOf(user))
//		...
//		msg.Write(w)
//	}
//
// Take clears the cookie, so that a second Take of the same handle in this
// browser fails with ErrNotFound, and Peek reads the request without
// clearing it, such as to name the SP on a consent page.
//
// # Cookies
//
// The cookie is encrypted and authenticated with AES-256-GCM, under a key
// derived from the key passed to New, and bound to its slot: the browser
// cannot read it, change it, or move it to another slot. It is encrypted,
// not only authenticated as the cookies of x/samlsp/pending are, because
// what it holds is not the application's to choose: it is whatever the SP
// put in its request, which may name the user (Subject), carry the SP's
// RelayState, or carry extensions with personal data, and cookies are
// logged and stored on disk more often than URLs are kept. Every server
// that serves the login must use the same key. The cookie expires
// DefaultMaxAge after Remember (WithMaxAge), however long the request
// itself had to live: ParseAuthnRequest has already checked that it was
// current, and Response does not check it again. It is not compressed
// before it is encrypted, since its length would then tell something of
// its content.
//
// The cookie is HttpOnly and SameSite=Lax, and Secure when the SSO URL
// uses https; its Path is "/" unless WithPath says otherwise, so that it
// reaches the login page wherever it is. SameSite=Lax keeps another site
// from making the browser Take a request with a form it posts; the browser
// still sends the cookie when an SP sends it to the SSO URL with the
// HTTP-Redirect binding, so that Remember sees the slots in use.
//
// # Slots
//
// There are DefaultSlots slot cookies, or as many as WithSlots says,
// named the cookie prefix followed by the slot's number. Remember puts the
// request in a slot that the browser sent no request in progress in, chosen
// at random, or, if all are in use, in the one that expires first; it does
// not read or rewrite the others. With the HTTP-POST binding, which
// browsers do not send SameSite=Lax cookies with, Remember sees no slot in
// use and picks one at random. Each handle names its slot and carries a
// random value that the cookie holds too, so a handle whose request was
// replaced by a later one fails with ErrNotFound, rather than answering
// the later request, and the user must start again.
//
// Logins in several tabs of one browser therefore do not disturb each
// other while the browser has a free slot. Each slot cookie takes about
// 400 bytes of the Cookie header for a typical request, and Remember
// refuses one larger than its share of DefaultMaxCookiesSize
// (WithMaxCookiesSize): 1.5 KB with 4 slots, which is room for a RelayState
// of about 900 bytes, but not for large extensions. Without that
// bound, a site that can send the browser to the SSO URL with a large
// request could fill every slot with a large cookie, until the requests
// to the IdP are too large for the servers in front of it. Keep a request
// that Remember refuses on the server, or answer it with an error
// Response.
//
// # Answered once
//
// Since the state is in the browser, Take alone can refuse a second
// answer only in a browser that honours the clearing of the cookie: a
// browser, or a user, that keeps a copy of the cookie can present it again
// until it expires and Take the request again, and get a second assertion
// for the same request. That matters little to an SP that accepts each
// assertion, and each InResponseTo, only once, as x/samlsp does; for SPs
// that do not, pass RecordTaken to New. Take then also records each
// request it returns in the samlidp.ReplayState of the Config (see
// samlidp.WithReplayState), under samlidp.ReplayKey of the SP and the
// request's ID prefixed with "AuthnRequestTaken:" (or, for an
// IdP-initiated login, which has no ID, the handle's random value prefixed
// with "IDPInitiatedTaken:"), until the cookie expires, and refuses one
// already recorded with ErrTaken. The record must be shared by every
// server that serves the login, which the default, in memory, is not. A
// request that the SP sends again, unsigned, is a new request to Remember,
// but its ID is the same, so with RecordTaken it is refused once its first
// copy has been taken. (ParseAuthnRequest already accepts a signed request
// only once.)
//
// # Security
//
// The cookie ties the request to the browser only as strongly as cookies
// are tied to the site. A host that can set cookies for the IdP's domain,
// such as a sibling subdomain, can plant in the browser a cookie that
// Remember set in the attacker's browser, with its handle, so that the
// user logs in to answer the attacker's request: the assertion then goes to
// the SP's assertion consumer service in the user's browser, which logs the
// user in to the SP, but with the attacker's RelayState. Where other hosts
// of the domain are not trusted, begin the cookie prefix with __Host-
// (WithCookiePrefix): browsers accept such a cookie only from the host
// itself, over https, with Path "/" and no Domain.
//
// Take does not read the request's form: pass it the handle. Read it with
// r.ParseForm and r.Form or r.PostForm, rather than r.FormValue or
// r.PostFormValue, which parse a multipart body, whose files may be
// spooled to disk.
//
// This package is built only on the public API of x/samlidp. Applications
// that keep pending requests elsewhere, such as in a server-side session,
// need not use it.
package idppending

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
)

// DefaultMaxAge is how long a request may wait for the user, unless
// WithMaxAge says otherwise. It leaves the user time to log in, including
// with a second factor, or to recover a forgotten password.
const DefaultMaxAge = 15 * time.Minute

// DefaultCookiePrefix begins the name of each slot cookie, unless
// WithCookiePrefix says otherwise.
const DefaultCookiePrefix = "saml_idp_pending_"

// MinKeyLength is the shortest key that New accepts, in bytes.
const MinKeyLength = 32

// DefaultSlots is how many slot cookies keep requests, unless WithSlots
// says otherwise: how many logins a browser can have waiting at once
// before a new one replaces one of them.
const DefaultSlots = 4

// MaxSlots is the most slot cookies WithSlots accepts.
const MaxSlots = 32

// DefaultMaxCookiesSize is how many bytes of the Cookie header all the
// slot cookies together may take, unless WithMaxCookiesSize says
// otherwise: each takes at most this divided by the number of slots.
const DefaultMaxCookiesSize = 6 << 10

// browserCookieLimit is the largest cookie Remember writes. Browsers keep
// cookies of at least 4096 bytes, name and attributes included.
const browserCookieLimit = 3800

// minCookieSize is the least room for a slot cookie that New accepts:
// enough for a typical request.
const minCookieSize = 512

// ErrNotFound is returned by Take and Peek when the browser has no
// request for the handle: it was never remembered in this browser, it was
// already taken, it was replaced by a later request in its slot, or the
// handle is malformed.
var ErrNotFound = errors.New("idppending: no request is waiting for this handle")

// ErrExpired is returned by Take and Peek when the request for the handle
// waited longer than the max age (see WithMaxAge).
var ErrExpired = errors.New("idppending: the request has expired")

// ErrInvalid is returned by Take and Peek when the slot of the handle
// holds a cookie that was not made by Remember with this Tracker's key: it
// was changed, made with another key, or made for another slot.
var ErrInvalid = errors.New("idppending: the request cookie is not valid")

// ErrTaken is returned by Take, with RecordTaken, when the request was
// already taken, in this browser or another. It also matches
// saml.ErrAssertionReplayed.
var ErrTaken = errors.New("idppending: the request was already taken")

// Tracker keeps the requests waiting for their users in cookies. Create
// one with New. It is safe for concurrent use.
type Tracker struct {
	config *samlidp.Config
	aead   cipher.AEAD
	prefix string
	path   string
	domain string
	secure bool
	slots  int
	maxAge time.Duration
	record bool

	maxCookiesSize int
}

// Option configures New.
type Option func(*Tracker)

// WithMaxAge sets how long a request may wait for the user. The default
// is DefaultMaxAge.
func WithMaxAge(d time.Duration) Option { return func(t *Tracker) { t.maxAge = d } }

// WithSlots sets how many slot cookies keep requests, from 1 to MaxSlots.
// The default is DefaultSlots.
func WithSlots(n int) Option { return func(t *Tracker) { t.slots = n } }

// WithMaxCookiesSize sets how many bytes of the Cookie header all the slot
// cookies together may take: Remember refuses a cookie larger than this
// divided by the number of slots. The default is DefaultMaxCookiesSize.
// Keep it well below the header size the servers and proxies in front of
// the IdP allow.
func WithMaxCookiesSize(n int) Option { return func(t *Tracker) { t.maxCookiesSize = n } }

// WithCookiePrefix sets what the name of each slot cookie begins with,
// before the slot's number. The default is DefaultCookiePrefix.
//
// Browsers reject a cookie whose name begins with __Secure- unless it is
// Secure, and one whose name begins with __Host- unless it is also
// host-only, with Path "/" (RFC 6265bis §4.1.3), whatever the case of the
// prefix. New returns an error for such a prefix unless the SSO URL uses
// https and, for __Host-, the path is "/" and WithDomain is not used:
// otherwise browsers would reject every slot cookie, and every login fail.
func WithCookiePrefix(prefix string) Option { return func(t *Tracker) { t.prefix = prefix } }

// WithDomain sets the Domain attribute of the cookies, so that hosts below
// it receive them too. By default they are host-only.
func WithDomain(domain string) Option { return func(t *Tracker) { t.domain = domain } }

// WithPath sets the Path attribute of the cookies. The default is "/". It
// must cover both the handler that calls Remember and those that call Take
// and Peek.
func WithPath(path string) Option { return func(t *Tracker) { t.path = path } }

// RecordTaken makes Take record each request it returns in the
// samlidp.ReplayState of the Config, and refuse one already recorded, so
// that a request is taken only once even by a browser that keeps a copy
// of its cookie (see "Answered once" in the package documentation).
func RecordTaken(t *Tracker) { t.record = true }

// deriveKeyLabel separates keys derived by DeriveKey from other uses of
// HMAC-SHA256 with the same secret, and from those of x/samlsp/pending.
const deriveKeyLabel = "github.com/crewjam/saml/x/samlidp/idppending key\x00"

// DeriveKey returns a key for New derived from secret, a secret the
// application already has: for example, the key that signs its sessions,
// or the IdP's private key, encoded with x509.MarshalPKCS8PrivateKey.
// label names the use, such as "idp.example.com saml pending request", so
// that the key differs from any other derived from the same secret.
//
// The key is as strong as secret, which must be random, kept secret and
// the same on every server; changing it fails the requests waiting. It
// returns an error if secret is shorter than MinKeyLength or label is
// empty.
func DeriveKey(secret []byte, label string) ([]byte, error) {
	if len(secret) < MinKeyLength {
		return nil, fmt.Errorf("idppending: the secret must be at least %d bytes, not %d", MinKeyLength, len(secret))
	}
	if label == "" {
		return nil, errors.New("idppending: the label is empty")
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(deriveKeyLabel))
	h.Write([]byte(label))
	return h.Sum(nil), nil
}

// cipherKeyLabel derives the AES key of the cookies from the key passed to
// New, so that the key itself is used for nothing else.
const cipherKeyLabel = "github.com/crewjam/saml/x/samlidp/idppending AES-256-GCM v1"

// New returns a Tracker for the requests of config, whose cookies are
// encrypted under key. key must be at least MinKeyLength random bytes,
// kept secret and shared by every server that serves the login. Changing
// it fails the requests waiting. The Tracker reads the time with
// config.Now and random values from config.Rand.
func New(config *samlidp.Config, key []byte, opts ...Option) (*Tracker, error) {
	if config == nil {
		return nil, errors.New("idppending: the config is nil")
	}
	if len(key) < MinKeyLength {
		return nil, fmt.Errorf("idppending: the key must be at least %d bytes, not %d", MinKeyLength, len(key))
	}
	sso, err := url.Parse(config.SSOURL())
	if err != nil {
		return nil, fmt.Errorf("idppending: invalid SSO URL: %w", err)
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte(cipherKeyLabel))
	block, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	t := &Tracker{
		config: config,
		aead:   aead,
		prefix: DefaultCookiePrefix,
		path:   "/",
		secure: sso.Scheme == "https",
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
		return nil, errors.New("idppending: the max age must be positive")
	}
	if t.slots < 1 || t.slots > MaxSlots {
		return nil, fmt.Errorf("idppending: the number of slots must be from 1 to %d, not %d", MaxSlots, t.slots)
	}
	if t.maxCookieSize() < minCookieSize {
		return nil, fmt.Errorf("idppending: %d bytes for %d slot cookies leaves too little for each (see WithMaxCookiesSize)", t.maxCookiesSize, t.slots)
	}
	if t.prefix == "" || strings.ContainsAny(t.prefix, "()<>@,;:\\\"/[]?={} \t") {
		return nil, fmt.Errorf("idppending: invalid cookie prefix %q", t.prefix)
	}
	if t.path == "" || !strings.HasPrefix(t.path, "/") || strings.ContainsAny(t.path, ";\x00\r\n") {
		return nil, fmt.Errorf("idppending: invalid cookie path %q", t.path)
	}
	// Browsers match the prefixes case-insensitively (RFC 6265bis §4.1.3).
	switch prefix := strings.ToLower(t.prefix); {
	case strings.HasPrefix(prefix, "__host-") && (!t.secure || t.path != "/" || t.domain != ""):
		return nil, fmt.Errorf("idppending: browsers reject cookies whose names begin with %q unless the SSO URL uses https, the Path is \"/\" (WithPath) and there is no Domain", t.prefix)
	case strings.HasPrefix(prefix, "__secure-") && !t.secure:
		return nil, fmt.Errorf("idppending: browsers reject cookies whose names begin with %q unless the SSO URL uses https", t.prefix)
	}
	return t, nil
}

// maxCookieSize returns how many bytes of the Cookie header one slot
// cookie may take.
func (t *Tracker) maxCookieSize() int {
	return min(browserCookieLimit, t.maxCookiesSize/t.slots)
}

// tokenSize is the length of the random value that a handle and its
// cookie share, in bytes.
const tokenSize = 9

// Remember sets a slot cookie that keeps req until Take takes it, and
// returns the handle that names it: a short string of URL-safe characters
// to carry to the login page, in its URL or in a form field. r is the
// request being served, whose cookies tell which slots are in use; it may
// be nil. Call it before writing the response.
//
// The handle is not a secret, and is of no use without the cookie, but it
// tells which login a page continues: carry it with the page rather than
// in another cookie, so that logins in several tabs each find their own.
//
// It returns an error if req is nil or names no SP, or if the cookie would
// take more than its share of the Cookie header (see WithMaxCookiesSize),
// such as for a request with a very long RelayState or large extensions.
func (t *Tracker) Remember(w http.ResponseWriter, r *http.Request, req *samlidp.AuthnRequest) (string, error) {
	if req == nil || req.ServiceProvider == "" {
		return "", errors.New("idppending: the request names no service provider")
	}
	for i, x := range req.Extensions {
		if !utf8.Valid(x) {
			return "", fmt.Errorf("idppending: AuthnRequest.Extensions[%d] is not UTF-8", i)
		}
	}
	var token [tokenSize]byte
	if _, err := io.ReadFull(t.config.Rand(), token[:]); err != nil {
		return "", fmt.Errorf("idppending: %w", err)
	}
	p := compact(req)
	p.Token = base64.RawURLEncoding.EncodeToString(token[:])
	p.Expires = t.config.Now().Add(t.maxAge).Unix()
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	slot, err := t.chooseSlot(r)
	if err != nil {
		return "", err
	}
	// The sealed body is longer than body, and its base64 longer still, so
	// a body longer than the cookie budget cannot fit: refuse it before
	// allocating and sealing.
	if len(body) > t.maxCookieSize() {
		return "", fmt.Errorf("idppending: the request takes %d bytes, more than the %d a request cookie may (see WithMaxCookiesSize)", len(body), t.maxCookieSize())
	}
	name := t.cookieName(slot)
	nonce := make([]byte, t.aead.NonceSize(), t.aead.NonceSize()+len(body)+t.aead.Overhead())
	if _, err := io.ReadFull(t.config.Rand(), nonce); err != nil {
		return "", fmt.Errorf("idppending: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(t.aead.Seal(nonce, nonce, body, t.additionalData(name)))
	// The cookie takes "name=value; " of the Cookie header.
	if size := len(name) + 1 + len(value) + 2; size > t.maxCookieSize() {
		return "", fmt.Errorf("idppending: the request cookie would take %d bytes of the Cookie header, more than %d (see WithMaxCookiesSize)", size, t.maxCookieSize())
	}
	http.SetCookie(w, t.cookie(name, value, int(t.maxAge/time.Second)))
	return strconv.Itoa(slot) + "." + p.Token, nil
}

// chooseSlot returns a slot that r carries no request in progress in,
// chosen at random, or, if every slot is in use, the one that expires
// first.
func (t *Tracker) chooseSlot(r *http.Request) (int, error) {
	expires := make([]int64, t.slots) // 0 for a free slot
	if r != nil {
		now := t.config.Now().Unix()
		for _, c := range r.Cookies() {
			i, ok := t.slotOf(c.Name)
			if !ok || i >= t.slots {
				continue
			}
			if p, ok := t.open(c.Name, c.Value); ok && now < p.Expires {
				// Of two cookies of one name, the browser keeps the
				// later; count the slot in use if either is.
				expires[i] = max(expires[i], p.Expires)
			}
		}
	}
	var free []int
	oldest := 0
	for i, e := range expires {
		if e == 0 {
			free = append(free, i)
		} else if e < expires[oldest] {
			oldest = i
		}
	}
	if len(free) == 0 {
		return oldest, nil
	}
	var b [8]byte
	if _, err := io.ReadFull(t.config.Rand(), b[:]); err != nil {
		return 0, fmt.Errorf("idppending: %w", err)
	}
	return free[binary.BigEndian.Uint64(b[:])%uint64(len(free))], nil
}

// Take returns the request that handle names, a handle that Remember
// returned in this browser, and clears its cookie with w, so that a second
// Take of it fails. Call it once the user is authenticated, when the
// request is to be answered with Response or ErrorResponse. A request that
// Take cannot return need not be answered: the SP will time it out.
//
// It returns ErrNotFound if the browser has no request for handle,
// ErrExpired if it waited longer than the max age, ErrInvalid if the
// handle's slot holds a cookie that is not valid, and, with RecordTaken,
// ErrTaken if it was already taken, or another error if it cannot be
// recorded. It clears the cookie in all those cases but the first, which
// leaves the slot to the request in it.
func (t *Tracker) Take(w http.ResponseWriter, r *http.Request, handle string) (*samlidp.AuthnRequest, error) {
	name, p, err := t.find(r, handle)
	if name != "" {
		http.SetCookie(w, t.cookie(name, "", -1))
	}
	if err != nil {
		return nil, err
	}
	req, _ := p.expand() // open checked it
	if t.record {
		id := "AuthnRequestTaken:" + req.ID
		if req.ID == "" {
			id = "IDPInitiatedTaken:" + p.Token
		}
		if err := t.config.Consume(r.Context(), req.ServiceProvider, id, time.Unix(p.Expires, 0)); err != nil {
			if errors.Is(err, saml.ErrAssertionReplayed) {
				return nil, fmt.Errorf("%w (%w)", ErrTaken, err)
			}
			return nil, fmt.Errorf("idppending: cannot record the request: %w", err)
		}
	}
	return req, nil
}

// Peek returns the request that handle names, as Take does, but leaves it
// in its cookie, for Take. Use it to show what is asked before the request
// is answered, such as the name of the SP on a consent page, or to check
// that the request is still waiting before showing the login page. It
// does not consult the record of RecordTaken.
func (t *Tracker) Peek(r *http.Request, handle string) (*samlidp.AuthnRequest, error) {
	_, p, err := t.find(r, handle)
	if err != nil {
		return nil, err
	}
	req, _ := p.expand() // open checked it
	return req, nil
}

// find returns the payload of the cookie of r that handle names. name is
// the name of a cookie to clear: that of the handle's slot, if it holds
// the request but it expired, or a cookie that is not valid.
func (t *Tracker) find(r *http.Request, handle string) (name string, _ payload, _ error) {
	slotText, token, ok := strings.Cut(handle, ".")
	if !ok || len(token) != base64.RawURLEncoding.EncodedLen(tokenSize) {
		return "", payload{}, ErrNotFound
	}
	slot, ok := t.slotOf(t.prefix + slotText)
	if !ok {
		return "", payload{}, ErrNotFound
	}
	name = t.cookieName(slot)
	var (
		invalid, other bool
		expired        *payload
	)
	// A browser may send two cookies of one name, such as one tossed by
	// another host of the domain: look at each.
	for _, c := range r.Cookies() {
		if c.Name != name {
			continue
		}
		p, ok := t.open(c.Name, c.Value)
		switch {
		case !ok:
			invalid = true
		case !hmac.Equal([]byte(p.Token), []byte(token)):
			other = true // a later request replaced it
		case t.config.Now().Unix() >= p.Expires:
			expired = &p
		default:
			return name, p, nil
		}
	}
	switch {
	case expired != nil:
		return name, payload{}, ErrExpired
	case other:
		return "", payload{}, ErrNotFound
	case invalid:
		return name, payload{}, ErrInvalid
	default:
		return "", payload{}, ErrNotFound
	}
}

// additionalData binds a cookie's content to its name, and so to its slot.
func (t *Tracker) additionalData(name string) []byte {
	return []byte("crewjam/saml/x/samlidp/idppending v1\x00" + name)
}

// open returns the payload of the cookie named name whose value is value,
// and false if the cookie was not made by Remember with t's key.
func (t *Tracker) open(name, value string) (payload, bool) {
	var p payload
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(sealed) < t.aead.NonceSize()+t.aead.Overhead() {
		return p, false
	}
	nonce, ciphertext := sealed[:t.aead.NonceSize()], sealed[t.aead.NonceSize():]
	body, err := t.aead.Open(nil, nonce, ciphertext, t.additionalData(name))
	if err != nil {
		return p, false
	}
	if err := json.Unmarshal(body, &p); err != nil || p.ServiceProvider == "" || p.Token == "" {
		return p, false
	}
	if _, ok := p.expand(); !ok {
		return p, false
	}
	return p, true
}

// slotOf returns the slot of the cookie named name, and false if it is not
// that of a slot cookie, of this Tracker or of one with other WithSlots,
// up to MaxSlots.
func (t *Tracker) slotOf(name string) (int, bool) {
	n, ok := strings.CutPrefix(name, t.prefix)
	if !ok {
		return 0, false
	}
	i, err := strconv.Atoi(n)
	return i, err == nil && i >= 0 && i < MaxSlots && t.cookieName(i) == name
}

// cookieName returns the name of the cookie of slot.
func (t *Tracker) cookieName(slot int) string {
	return t.prefix + strconv.Itoa(slot)
}

func (t *Tracker) cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure is set when the SSO URL uses https; plain http is for local development
		Name:     name,
		Value:    value,
		Path:     t.path,
		Domain:   t.domain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   t.secure,
		SameSite: http.SameSiteLaxMode,
	}
}
