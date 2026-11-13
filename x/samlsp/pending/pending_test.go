package pending_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

const entityID = "https://sp.example.com/saml/metadata"

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

// testIDP is an in-process identity provider with one logged-in user.
type testIDP struct {
	idp    *saml.IdentityProvider
	spMeta *saml.EntityDescriptor
}

func (ti *testIDP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if ti.spMeta != nil && id == ti.spMeta.EntityID {
		return ti.spMeta, nil
	}
	return nil, errors.New("unknown service provider")
}

func (ti *testIDP) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	return &saml.Session{
		ID: "session-1", Index: "index-1",
		CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID: "alice@example.com", NameIDFormat: string(saml.EmailAddressNameIDFormat),
	}
}

func newConfig(t *testing.T, opts ...samlsp.Option) (*samlsp.Config, *testIDP) {
	t.Helper()
	idpKey, idpCert := newKeyPair(t)
	ti := &testIDP{}
	ti.idp = &saml.IdentityProvider{
		Key: idpKey, Certificate: idpCert,
		MetadataURL:             mustURL("https://idp.example.com/metadata"),
		SSOURL:                  mustURL("https://idp.example.com/sso"),
		ServiceProviderProvider: ti,
		SessionProvider:         ti,
	}
	key, cert := newKeyPair(t)
	idp := func(context.Context) (*saml.EntityDescriptor, error) { return ti.idp.Metadata(), nil }
	cfg, err := samlsp.New(entityID, idp, append([]samlsp.Option{samlsp.WithSigningKey(key, cert)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	ti.spMeta = cfg.Metadata(t.Context())
	return cfg, ti
}

func newTracker(t *testing.T, cfg *samlsp.Config, opts ...pending.Option) *pending.Tracker {
	t.Helper()
	tr, err := pending.New(cfg, testKey, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

var formInput = regexp.MustCompile(`name="([A-Za-z]+)" value="([^"]*)"`)

func formValues(body string) url.Values {
	v := url.Values{}
	for _, m := range formInput.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

// acsRequest returns the POST to the ACS with the given RelayState that
// carries the cookies set in w.
func acsRequest(form url.Values, w *httptest.ResponseRecorder) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/acs", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range w.Result().Cookies() {
		if c.MaxAge >= 0 {
			r.AddCookie(c)
		}
	}
	return r
}

// remember makes an AuthnRequest with relayState and remembers it.
func remember(t *testing.T, cfg *samlsp.Config, tr *pending.Tracker, relayState, data string) (*samlsp.Message, *httptest.ResponseRecorder) {
	t.Helper()
	msg, err := cfg.AuthnRequest(t.Context(), relayState)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := tr.Remember(w, msg, data); err != nil {
		t.Fatal(err)
	}
	return msg, w
}

func onlyCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

// TestLogin runs a whole login: the request is remembered, the IdP
// answers, and the ACS finds the request and accepts the Response.
func TestLogin(t *testing.T) {
	cfg, ti := newConfig(t)
	tr := newTracker(t, cfg)

	msg, w := remember(t, cfg, tr, "state-1", "/reports?id=7")

	// The browser goes to the IdP, which posts its Response to the ACS.
	idpW := httptest.NewRecorder()
	ti.idp.ServeSSO(idpW, httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), nil))
	form := formValues(idpW.Body.String())
	if form.Get("SAMLResponse") == "" {
		t.Fatalf("the IdP did not answer: %s", idpW.Body.String())
	}
	r := acsRequest(form, w)

	acsW := httptest.NewRecorder()
	login, err := take(tr, acsW, r)
	if err != nil {
		t.Fatal(err)
	}
	if login.ID != msg.ID || login.RelayState != "state-1" || login.Data != "/reports?id=7" {
		t.Errorf("Find = %+v, want ID %q", login, msg.ID)
	}
	if _, err := cfg.ParseResponse(t.Context(), r, samlsp.WithRequestID(login.ID)); err != nil {
		t.Fatal(err)
	}

	// The cookie is cleared, so the login is found once.
	cleared := onlyCookie(t, acsW)
	if cleared.MaxAge >= 0 || cleared.Value != "" || cleared.Path != "/saml/acs" {
		t.Errorf("Forget did not clear the cookie: %+v", cleared)
	}
	if _, err := take(tr, httptest.NewRecorder(), acsRequest(form, acsW)); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("second Find: err = %v, want ErrNotFound", err)
	}
}

func TestCookieAttributes(t *testing.T) {
	t.Run("https", func(t *testing.T) {
		cfg, _ := newConfig(t)
		_, w := remember(t, cfg, newTracker(t, cfg), "s", "")
		c := onlyCookie(t, w)
		if c.Path != "/saml/acs" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteNoneMode ||
			c.MaxAge != int(pending.DefaultMaxAge/time.Second) || c.Domain != "" ||
			!strings.HasPrefix(c.Name, pending.DefaultCookiePrefix) {
			t.Errorf("cookie = %+v", c)
		}
	})
	t.Run("http", func(t *testing.T) {
		cfg, _ := newConfig(t, samlsp.WithACSURL("http://localhost:8080/auth/acs"))
		_, w := remember(t, cfg, newTracker(t, cfg), "s", "")
		c := onlyCookie(t, w)
		if c.Path != "/auth/acs" || c.Secure || c.SameSite == http.SameSiteNoneMode || !c.HttpOnly {
			t.Errorf("cookie = %+v", c)
		}
	})
	t.Run("options", func(t *testing.T) {
		cfg, _ := newConfig(t)
		tr := newTracker(t, cfg, pending.WithCookiePrefix("p_"), pending.WithDomain("example.com"),
			pending.WithPath("/"), pending.WithMaxAge(time.Minute))
		_, w := remember(t, cfg, tr, "s", "")
		c := onlyCookie(t, w)
		if !strings.HasPrefix(c.Name, "p_") || c.Domain != "example.com" || c.Path != "/" || c.MaxAge != 60 {
			t.Errorf("cookie = %+v", c)
		}
	})
}

// TestRelayStates checks that any RelayState works, with enough slots that
// these do not share one.
func TestRelayStates(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg, pending.WithSlots(pending.MaxSlots), pending.WithMaxCookiesSize(pending.MaxSlots*512))
	states := []string{"", "a", "https://sp.example.com/next?x=1&y=2", "with space; and=equals"}
	browser := httptest.NewRecorder()
	ids := map[string]string{}
	for _, s := range states {
		msg, err := cfg.AuthnRequest(t.Context(), s)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Remember(browser, msg, ""); err != nil {
			t.Fatal(err)
		}
		ids[s] = msg.ID
	}
	for _, s := range states {
		login, err := take(tr, httptest.NewRecorder(), acsRequest(url.Values{"RelayState": {s}}, browser))
		if err != nil {
			t.Fatalf("RelayState %q: %v", s, err)
		}
		if login.ID != ids[s] {
			t.Errorf("RelayState %q: ID = %q, want %q", s, login.ID, ids[s])
		}
	}
}

func TestInvalid(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	_, w := remember(t, cfg, tr, "s", "/home")
	c := onlyCookie(t, w)

	take := func(t *testing.T, tr *pending.Tracker, relayState string, cookies ...*http.Cookie) error {
		t.Helper()
		r := acsRequest(url.Values{"RelayState": {relayState}}, httptest.NewRecorder())
		for _, c := range cookies {
			r.AddCookie(c)
		}
		_, err := take(tr, httptest.NewRecorder(), r)
		return err
	}
	// requestCookie is a cookie as the browser sends it, by name and value.
	requestCookie := func(name, value string) *http.Cookie {
		return &http.Cookie{Name: name, Value: value} //nolint:gosec // G124: a request cookie carries no attributes
	}
	with := func(value string) *http.Cookie { return requestCookie(c.Name, value) }
	body, mac, _ := strings.Cut(c.Value, ".")

	for _, tc := range []struct {
		name string
		err  error
		run  func(t *testing.T) error
	}{
		{"no cookie", pending.ErrNotFound, func(t *testing.T) error { return take(t, tr, "s") }},
		{"other RelayState", pending.ErrNotFound, func(t *testing.T) error { return take(t, tr, "other", c) }},
		{"moved to other RelayState", pending.ErrInvalid, func(t *testing.T) error {
			_, w := remember(t, cfg, tr, "other", "")
			return take(t, tr, "other", requestCookie(onlyCookie(t, w).Name, c.Value))
		}},
		{"changed body", pending.ErrInvalid, func(t *testing.T) error {
			return take(t, tr, "s", with(body+"x."+mac))
		}},
		{"changed mac", pending.ErrInvalid, func(t *testing.T) error {
			// Change the first character: all 6 of its bits decode, whereas the
			// last character of an unpadded MAC carries bits that decoding
			// ignores. The replacement always differs from the original.
			flipped := "A"
			if mac[0] == 'A' {
				flipped = "B"
			}
			return take(t, tr, "s", with(body+"."+flipped+mac[1:]))
		}},
		{"no mac", pending.ErrInvalid, func(t *testing.T) error { return take(t, tr, "s", with(body)) }},
		{"garbage", pending.ErrInvalid, func(t *testing.T) error { return take(t, tr, "s", with("!!.!!")) }},
		{"other key", pending.ErrInvalid, func(t *testing.T) error {
			other, err := pending.New(cfg, []byte("another key that is 32 bytes lon"))
			if err != nil {
				t.Fatal(err)
			}
			return take(t, other, "s", c)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(t); !errors.Is(err, tc.err) {
				t.Errorf("err = %v, want %v", err, tc.err)
			}
		})
	}
}

func TestExpiry(t *testing.T) {
	cfg, _ := newConfig(t)
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	at := func(d time.Duration) *pending.Tracker {
		return newTracker(t, cfg, pending.WithClock(dsig.NewFakeClockAt(start.Add(d))), pending.WithMaxAge(5*time.Minute))
	}
	_, w := remember(t, cfg, at(0), "s", "")
	r := func() *http.Request { return acsRequest(url.Values{"RelayState": {"s"}}, w) }

	login, err := take(at(5*time.Minute-time.Second), httptest.NewRecorder(), r())
	if err != nil {
		t.Fatal(err)
	}
	if want := start.Add(5 * time.Minute); !login.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v", login.Expires, want)
	}

	// The browser should have dropped the cookie by now, but the server
	// does not rely on that.
	if _, err := take(at(5*time.Minute), httptest.NewRecorder(), r()); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("expired: err = %v, want ErrNotFound", err)
	}
}

// jar is a browser's cookies for the ACS, by name.
type jar map[string]*http.Cookie

// set stores the cookies that w sets, and drops those it clears.
func (j jar) set(w *httptest.ResponseRecorder) {
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(j, c.Name)
		} else {
			j[c.Name] = c
		}
	}
}

// request returns the POST to the ACS with relayState that carries the
// cookies of j.
func (j jar) request(relayState string) *http.Request {
	r := acsRequest(url.Values{"RelayState": {relayState}}, httptest.NewRecorder())
	for _, c := range j {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // G124: a request cookie carries no attributes
	}
	return r
}

// slotName returns the name of the slot cookie of relayState.
func slotName(t *testing.T, cfg *samlsp.Config, tr *pending.Tracker, relayState string) string {
	t.Helper()
	_, w := remember(t, cfg, tr, relayState, "")
	return onlyCookie(t, w).Name
}

// relayStates returns two RelayStates whose slots are the same, or differ.
func relayStates(t *testing.T, cfg *samlsp.Config, tr *pending.Tracker, same bool) (string, string) {
	t.Helper()
	first := slotName(t, cfg, tr, "tab-0")
	for i := 1; i < 1000; i++ {
		s := fmt.Sprintf("tab-%d", i)
		if (slotName(t, cfg, tr, s) == first) == same {
			return "tab-0", s
		}
	}
	t.Fatal("no such RelayStates")
	return "", ""
}

// TestCookieSize measures the slot cookie of a typical login, as the
// browser sends it in the Cookie header, for the figures in the package
// documentation: the IdP of newConfig has a 32-byte https entity ID.
func TestCookieSize(t *testing.T) {
	cfg, _ := newConfig(t)
	_, w := remember(t, cfg, newTracker(t, cfg), rand.Text(), "/reports/2026?id=123")
	c := onlyCookie(t, w)
	size := len(c.Name) + len("=") + len(c.Value) + len("; ")
	t.Logf("slot cookie: %d bytes; %d slots: %d bytes", size, pending.DefaultSlots, pending.DefaultSlots*size)
	if total := pending.DefaultSlots * size; total > 4200 {
		t.Errorf("%d slots of %d bytes take %d bytes, more than 4200", pending.DefaultSlots, size, total)
	}
}

// TestConcurrentLogins starts logins in two tabs, in different slots, and
// finishes them in either order.
func TestConcurrentLogins(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	a, b := relayStates(t, cfg, tr, false)
	for _, order := range [][2]string{{a, b}, {b, a}} {
		browser := jar{}
		ids := map[string]string{}
		for _, s := range []string{a, b} {
			msg, w := remember(t, cfg, tr, s, "/"+s)
			browser.set(w)
			ids[s] = msg.ID
		}
		for _, s := range order {
			w := httptest.NewRecorder()
			login, err := take(tr, w, browser.request(s))
			if err != nil {
				t.Fatalf("%s: %v", s, err)
			}
			if login.ID != ids[s] || login.Data != "/"+s {
				t.Errorf("%s: Find = %+v, want ID %q", s, login, ids[s])
			}
			// Forget clears its own slot only.
			if c := onlyCookie(t, w); c.MaxAge >= 0 {
				t.Errorf("%s: set %+v", s, c)
			}
			browser.set(w)
		}
		if len(browser) != 0 {
			t.Errorf("cookies left: %v", browser)
		}
	}
}

// TestSameSlot starts two logins whose RelayStates share a slot: the later
// one replaces the earlier one.
func TestSameSlot(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	a, b := relayStates(t, cfg, tr, true)
	browser := jar{}
	_, w := remember(t, cfg, tr, a, "")
	browser.set(w)
	msg, w := remember(t, cfg, tr, b, "")
	browser.set(w)
	if len(browser) != 1 {
		t.Fatalf("got %d cookies, want 1", len(browser))
	}

	w = httptest.NewRecorder()
	if _, err := take(tr, w, browser.request(a)); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("replaced login: err = %v, want ErrNotFound", err)
	}
	if n := len(w.Result().Cookies()); n != 0 {
		t.Errorf("Find of the replaced login set %d cookies, want 0", n)
	}
	login, err := take(tr, httptest.NewRecorder(), browser.request(b))
	if err != nil {
		t.Fatal(err)
	}
	if login.ID != msg.ID {
		t.Errorf("ID = %q, want %q", login.ID, msg.ID)
	}
}

// TestManyAbandoned checks that however many logins a browser starts and
// abandons, it keeps at most one cookie per slot.
func TestManyAbandoned(t *testing.T) {
	cfg, _ := newConfig(t)
	for _, slots := range []int{1, 4, pending.DefaultSlots, pending.MaxSlots} {
		tr := newTracker(t, cfg, pending.WithSlots(slots), pending.WithMaxCookiesSize(pending.MaxSlots*512))
		browser := jar{}
		var last *samlsp.Message
		for i := range 1000 {
			last = &samlsp.Message{ID: fmt.Sprintf("id-%d", i), RelayState: fmt.Sprintf("s%d", i)}
			w := httptest.NewRecorder()
			if err := tr.Remember(w, last, "/somewhere"); err != nil {
				t.Fatal(err)
			}
			browser.set(w)
		}
		if len(browser) > slots {
			t.Errorf("%d slots: %d cookies", slots, len(browser))
		}
		login, err := take(tr, httptest.NewRecorder(), browser.request(last.RelayState))
		if err != nil || login.ID != last.ID {
			t.Errorf("%d slots: Find = %+v, %v; want ID %q", slots, login, err, last.ID)
		}
	}
}

// TestFindClears checks that Find clears the slots of expired and invalid
// logins, and Forget the login's own, but not those of other logins in
// progress or other cookies.
func TestFindClears(t *testing.T) {
	cfg, _ := newConfig(t)
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	at := func(d time.Duration) *pending.Tracker {
		return newTracker(t, cfg, pending.WithClock(dsig.NewFakeClockAt(start.Add(d))))
	}
	browser := jar{}
	names := map[string]string{}
	for i, s := range []string{"old", "live", "taken"} {
		// "live" is remembered after "old" has expired, "taken" last,
		// each at a RelayState of its own slot.
		tr := at([]time.Duration{0, pending.DefaultMaxAge + time.Minute, 2 * pending.DefaultMaxAge}[i])
		for n := 0; ; n++ {
			rs := fmt.Sprintf("%s-%d", s, n)
			if _, used := names[slotName(t, cfg, tr, rs)]; used {
				continue
			}
			_, w := remember(t, cfg, tr, rs, "")
			browser.set(w)
			names[onlyCookie(t, w).Name] = s
			names[s] = rs
			break
		}
	}
	invalid := pending.DefaultCookiePrefix + "63"
	names[invalid] = "invalid"
	browser[invalid] = &http.Cookie{Name: invalid, Value: "x.y"}                                                           //nolint:gosec // G124: a request cookie carries no attributes
	browser[pending.DefaultCookiePrefix+"other"] = &http.Cookie{Name: pending.DefaultCookiePrefix + "other", Value: "x.y"} //nolint:gosec // G124: a request cookie carries no attributes
	browser["session"] = &http.Cookie{Name: "session", Value: "keep"}                                                      //nolint:gosec // G124: a request cookie carries no attributes

	// "old" has expired when "taken" is taken; "live" has not.
	w := httptest.NewRecorder()
	if _, err := take(at(2*pending.DefaultMaxAge), w, browser.request(names["taken"])); err != nil {
		t.Fatal(err)
	}
	cleared := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge >= 0 {
			t.Errorf("set %+v", c)
		}
		cleared[names[c.Name]] = true
	}
	if len(cleared) != 3 || !cleared["old"] || !cleared["taken"] || !cleared["invalid"] {
		t.Errorf("cleared %v, want old, taken and invalid", cleared)
	}
}

// TestChangeSlots checks that a login remembered before a change of
// WithSlots is still found.
func TestChangeSlots(t *testing.T) {
	cfg, _ := newConfig(t)
	msg, w := remember(t, cfg, newTracker(t, cfg, pending.WithSlots(pending.MaxSlots), pending.WithMaxCookiesSize(pending.MaxSlots*512)), "s", "")
	browser := jar{}
	browser.set(w)
	login, err := take(newTracker(t, cfg, pending.WithSlots(1)), httptest.NewRecorder(), browser.request("s"))
	if err != nil || login.ID != msg.ID {
		t.Errorf("Find = %+v, %v; want ID %q", login, err, msg.ID)
	}
}

func TestRememberErrors(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	if err := tr.Remember(httptest.NewRecorder(), nil, ""); err == nil {
		t.Error("nil message accepted")
	}
	if err := tr.Remember(httptest.NewRecorder(), &samlsp.Message{RelayState: "s"}, ""); err == nil {
		t.Error("message without ID accepted")
	}
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := tr.Remember(w, msg, strings.Repeat("x", 4000)); err == nil {
		t.Error("data too large for a cookie accepted")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Error("a cookie was set despite the error")
	}
}

func TestNewErrors(t *testing.T) {
	cfg, _ := newConfig(t)
	httpCfg, _ := newConfig(t, samlsp.WithACSURL("http://localhost:8080/saml/acs"))
	for name, f := range map[string]func() (*pending.Tracker, error){
		"nil config": func() (*pending.Tracker, error) { return pending.New(nil, testKey) },
		"short key":  func() (*pending.Tracker, error) { return pending.New(cfg, testKey[:31]) },
		"max age":    func() (*pending.Tracker, error) { return pending.New(cfg, testKey, pending.WithMaxAge(0)) },
		"empty prefix": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithCookiePrefix(""))
		},
		"bad prefix": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithCookiePrefix("a;b"))
		},
		"no slots": func() (*pending.Tracker, error) { return pending.New(cfg, testKey, pending.WithSlots(0)) },
		"too many slots": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithSlots(pending.MaxSlots+1))
		},
		"too many slots for the cookie budget": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithSlots(pending.MaxSlots))
		},
		"cookie budget too small": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithMaxCookiesSize(1000))
		},
		// Browsers would reject every slot cookie (RFC 6265bis §4.1.3).
		"__Host- with the ACS path": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithCookiePrefix("__Host-p_"))
		},
		"__Host- with a Domain": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithCookiePrefix("__Host-p_"), pending.WithPath("/"), pending.WithDomain("example.com"))
		},
		"__host- with the ACS path": func() (*pending.Tracker, error) {
			return pending.New(cfg, testKey, pending.WithCookiePrefix("__host-p_"))
		},
		"__Host- over http": func() (*pending.Tracker, error) {
			return pending.New(httpCfg, testKey, pending.WithCookiePrefix("__Host-p_"), pending.WithPath("/"))
		},
		"__Secure- over http": func() (*pending.Tracker, error) {
			return pending.New(httpCfg, testKey, pending.WithCookiePrefix("__SECURE-p_"))
		},
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestCookiePrefixes checks that New accepts __Host- and __Secure- prefixes
// with the cookie attributes browsers require of them, and that the
// cookies have them.
func TestCookiePrefixes(t *testing.T) {
	cfg, _ := newConfig(t)
	for _, tr := range []*pending.Tracker{
		newTracker(t, cfg, pending.WithCookiePrefix("__Host-saml_"), pending.WithPath("/")),
		newTracker(t, cfg, pending.WithCookiePrefix("__Secure-saml_")),
		newTracker(t, cfg, pending.WithCookiePrefix("__Secure-saml_"), pending.WithDomain("example.com")),
	} {
		_, w := remember(t, cfg, tr, "s", "")
		if c := onlyCookie(t, w); !c.Secure || (strings.HasPrefix(c.Name, "__Host-") && (c.Path != "/" || c.Domain != "")) {
			t.Errorf("cookie = %+v", c)
		}
	}
}

// TestKeyCopied checks that changing the caller's key slice afterwards
// does not change the Tracker's key.
func TestKeyCopied(t *testing.T) {
	cfg, _ := newConfig(t)
	key := append([]byte(nil), testKey...)
	tr, err := pending.New(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	_, w := remember(t, cfg, tr, "s", "")
	key[0] ^= 1
	if _, err := take(tr, httptest.NewRecorder(), acsRequest(url.Values{"RelayState": {"s"}}, w)); err != nil {
		t.Error(err)
	}
}

func TestDeriveKey(t *testing.T) {
	secret := []byte("an application secret of more than 32 bytes")
	key, err := pending.DeriveKey(secret, "example saml pending login")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("len = %d, want 32", len(key))
	}
	again, _ := pending.DeriveKey(secret, "example saml pending login")
	if string(again) != string(key) {
		t.Error("DeriveKey is not deterministic")
	}
	other, _ := pending.DeriveKey(secret, "another use")
	if string(other) == string(key) {
		t.Error("two labels give the same key")
	}
	if string(key) == string(secret[:32]) {
		t.Error("the key is the secret")
	}

	// The key works with New.
	cfg, _ := newConfig(t)
	if _, err := pending.New(cfg, key); err != nil {
		t.Errorf("New with a derived key: %v", err)
	}

	if _, err := pending.DeriveKey(secret[:31], "label"); err == nil {
		t.Error("a short secret was accepted")
	}
	if _, err := pending.DeriveKey(secret, ""); err == nil {
		t.Error("an empty label was accepted")
	}
}

// However large the data that forced logins pass to Remember, the slot
// cookies together never take more of the Cookie header than the budget,
// so the ACS stays reachable.
func TestCookiesSizeBounded(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	browser := jar{}
	// A short return path fits.
	msg := &samlsp.Message{ID: "id-ok", RelayState: rand.Text()}
	w := httptest.NewRecorder()
	if err := tr.Remember(w, msg, "/a/return/path?with=query"); err != nil {
		t.Fatal(err)
	}
	browser.set(w)
	// Long data, as an attacker's "next" parameter, is refused.
	for i := range 200 {
		w := httptest.NewRecorder()
		err := tr.Remember(w, &samlsp.Message{ID: fmt.Sprintf("id-%d", i), RelayState: rand.Text()}, "/"+strings.Repeat("x", 300))
		if err == nil {
			t.Fatal("data of 300 bytes accepted")
		}
		browser.set(w)
	}
	// Fill every slot with the largest data each accepts.
	for i := range 200 {
		m := &samlsp.Message{ID: fmt.Sprintf("id-big-%d", i), RelayState: rand.Text()}
		data := strings.Repeat("y", 400)
		for data != "" {
			w := httptest.NewRecorder()
			if tr.Remember(w, m, data) == nil {
				browser.set(w)
				break
			}
			data = data[1:]
		}
	}
	header := browser.request("x").Header.Get("Cookie")
	if len(header) > pending.DefaultMaxCookiesSize {
		t.Fatalf("Cookie header of %d bytes, more than %d", len(header), pending.DefaultMaxCookiesSize)
	}
}

// take finds the login of r, as an ACS does, and forgets it, writing the
// cookies of both to w.
func take(tr *pending.Tracker, w http.ResponseWriter, r *http.Request) (*pending.Login, error) {
	login, err := tr.Find(w, r)
	if err == nil {
		tr.Forget(w, login)
	}
	return login, err
}
