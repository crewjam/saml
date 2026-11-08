package pending_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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
	cfg, err := samlsp.New(idp, entityID, append([]samlsp.Option{samlsp.WithSigningKey(key, cert)}, opts...)...)
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
	login, err := tr.Take(acsW, r)
	if err != nil {
		t.Fatal(err)
	}
	if login.ID != msg.ID || login.RelayState != "state-1" || login.Data != "/reports?id=7" {
		t.Errorf("Take = %+v, want ID %q", login, msg.ID)
	}
	if _, err := cfg.ParseResponse(t.Context(), r, samlsp.WithRequestID(login.ID)); err != nil {
		t.Fatal(err)
	}

	// The cookie is cleared, so the login is found once.
	cleared := onlyCookie(t, acsW)
	if cleared.MaxAge >= 0 || cleared.Value != "" || cleared.Path != "/saml/acs" {
		t.Errorf("Take did not clear the cookie: %+v", cleared)
	}
	if _, err := tr.Take(httptest.NewRecorder(), acsRequest(form, acsW)); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("second Take: err = %v, want ErrNotFound", err)
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

// TestRelayStates checks that logins with different RelayStates, as in
// several tabs, have their own cookies, and that any RelayState works.
func TestRelayStates(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
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
		login, err := tr.Take(httptest.NewRecorder(), acsRequest(url.Values{"RelayState": {s}}, browser))
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
		_, err := tr.Take(httptest.NewRecorder(), r)
		return err
	}
	with := func(value string) *http.Cookie { return &http.Cookie{Name: c.Name, Value: value} }
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
			moved := onlyCookie(t, w)
			moved.Value = c.Value
			return take(t, tr, "other", moved)
		}},
		{"changed body", pending.ErrInvalid, func(t *testing.T) error {
			return take(t, tr, "s", with(body+"x."+mac))
		}},
		{"changed mac", pending.ErrInvalid, func(t *testing.T) error {
			return take(t, tr, "s", with(body+"."+mac[:len(mac)-2]+"AA"))
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

	login, err := at(5*time.Minute-time.Second).Take(httptest.NewRecorder(), r())
	if err != nil {
		t.Fatal(err)
	}
	if want := start.Add(5 * time.Minute); !login.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v", login.Expires, want)
	}

	// The browser should have dropped the cookie by now, but the server
	// does not rely on that.
	if _, err := at(5*time.Minute).Take(httptest.NewRecorder(), r()); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("expired: err = %v, want ErrNotFound", err)
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
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: no error", name)
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
	if _, err := tr.Take(httptest.NewRecorder(), acsRequest(url.Values{"RelayState": {"s"}}, w)); err != nil {
		t.Error(err)
	}
}
