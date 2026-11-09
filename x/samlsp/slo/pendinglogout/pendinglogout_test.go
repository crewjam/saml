package pendinglogout_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"html"
	"math/big"
	"mime/multipart"
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
	"github.com/crewjam/saml/x/samlsp/slo"
	"github.com/crewjam/saml/x/samlsp/slo/pendinglogout"
)

const (
	spEntityID = "https://sp.example.com/saml/metadata"
	spSLOURL   = "https://sp.example.com/saml/slo"
)

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

// testIDP is an in-process identity provider that ends any session.
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
	return nil
}

func (ti *testIDP) InvalidateSession(http.ResponseWriter, *http.Request, *saml.IdpLogoutRequest) error {
	return nil
}

// newService returns the Service of an SP whose SLO URL is sloURL, and an
// IdP that trusts it.
func newService(t *testing.T, sloURL string) (*slo.Service, *testIDP) {
	t.Helper()
	idpKey, idpCert := newKeyPair(t)
	ti := &testIDP{}
	ti.idp = &saml.IdentityProvider{
		Key: idpKey, Certificate: idpCert,
		MetadataURL:             mustURL("https://idp.example.com/metadata"),
		SSOURL:                  mustURL("https://idp.example.com/sso"),
		LogoutURL:               mustURL("https://idp.example.com/slo"),
		LogoutBindings:          []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding},
		ServiceProviderProvider: ti,
		SessionProvider:         ti,
	}
	key, cert := newKeyPair(t)
	idp := func(context.Context) (*saml.EntityDescriptor, error) { return ti.idp.Metadata(), nil }
	cfg, err := samlsp.New(spEntityID, idp, samlsp.WithSigningKey(key, cert), slo.Endpoint(sloURL))
	if err != nil {
		t.Fatal(err)
	}
	ti.spMeta = cfg.Metadata(t.Context())
	s, err := slo.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s, ti
}

func newTracker(t *testing.T, s *slo.Service, opts ...pendinglogout.Option) *pendinglogout.Tracker {
	t.Helper()
	tr, err := pendinglogout.New(s, testKey, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// jar is the browser's cookies for the SLO URL, by name.
type jar map[string]*http.Cookie

// set applies the Set-Cookie headers of w.
func (j jar) set(w *httptest.ResponseRecorder) {
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(j, c.Name)
		} else {
			j[c.Name] = c
		}
	}
}

func (j jar) addTo(r *http.Request) *http.Request {
	for _, c := range j {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // G124: a request cookie carries no attributes
	}
	return r
}

// request returns a POST to the SLO URL with relayState and the jar's
// cookies.
func (j jar) request(relayState string) *http.Request {
	return j.addTo(postForm(spSLOURL, url.Values{"SAMLResponse": {"junk"}, "RelayState": {relayState}}))
}

func postForm(target string, v url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

var formInput = regexp.MustCompile(`name="([A-Za-z]+)" value="([^"]*)"`)

func formValues(body string) url.Values {
	v := url.Values{}
	for _, m := range formInput.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

// remember remembers a logout with relayState and data in browser, as a
// message made without an IdP.
func remember(t *testing.T, tr *pendinglogout.Tracker, browser jar, id, relayState, data string) {
	t.Helper()
	w := httptest.NewRecorder()
	if err := tr.Remember(w, &samlsp.Message{ID: id, RelayState: relayState}, data); err != nil {
		t.Fatal(err)
	}
	browser.set(w)
}

// TestRoundTrip starts a logout, has the IdP answer it, and checks that
// the answer is found, verified and forgotten.
func TestRoundTrip(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			s, ti := newService(t, spSLOURL)
			tr := newTracker(t, s)
			browser := jar{}

			msg, err := s.Request(t.Context(), saml.NameID{Value: "alice@example.com"}, "state-1", samlsp.WithBinding(binding))
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			if err := tr.Remember(w, msg, "/bye"); err != nil {
				t.Fatal(err)
			}
			browser.set(w)
			if len(browser) != 1 {
				t.Fatalf("Remember set %d cookies", len(browser))
			}
			for _, c := range browser {
				if c.Path != "/saml/slo" || !c.Secure || c.SameSite != http.SameSiteNoneMode || !c.HttpOnly {
					t.Errorf("cookie attributes: %+v", c)
				}
			}

			// The browser takes the request to the IdP, and its answer back.
			var toIDP *http.Request
			if u := msg.RedirectURL(); u != nil {
				toIDP = httptest.NewRequest(http.MethodGet, u.String(), nil)
			} else {
				mw := httptest.NewRecorder()
				msg.Write(mw)
				toIDP = postForm(msg.Destination, formValues(mw.Body.String()))
			}
			iw := httptest.NewRecorder()
			ti.idp.ServeSLO(iw, toIDP)
			var back *http.Request
			if loc := iw.Header().Get("Location"); loc != "" {
				back = httptest.NewRequest(http.MethodGet, loc, nil)
			} else {
				back = postForm(spSLOURL, formValues(iw.Body.String()))
			}
			browser.addTo(back)

			fw := httptest.NewRecorder()
			l, err := tr.Find(fw, back)
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			if l.ID != msg.ID || l.RelayState != "state-1" || l.Data != "/bye" {
				t.Errorf("Find = %+v", l)
			}
			if len(fw.Result().Cookies()) != 0 {
				t.Error("Find cleared the slot of the logout in progress")
			}
			_, err = s.ParseResponse(t.Context(), back, l.RequestIDs()...)
			if err != nil {
				t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
			}
			if !pendinglogout.Answered(err) {
				t.Error("Answered(nil) = false")
			}
			fw = httptest.NewRecorder()
			tr.Forget(fw, l)
			browser.set(fw)
			if len(browser) != 0 {
				t.Errorf("Forget left %v", browser)
			}
			if _, err := tr.Find(httptest.NewRecorder(), browser.request("state-1")); !errors.Is(err, pendinglogout.ErrNotFound) {
				t.Errorf("Find after Forget: %v", err)
			}
		})
	}
}

func TestWrongRelayState(t *testing.T) {
	s, _ := newService(t, spSLOURL)
	tr := newTracker(t, s)
	browser := jar{}
	remember(t, tr, browser, "id-1", "state-1", "")
	for _, rs := range []string{"state-2", "", "STATE-1"} {
		if _, err := tr.Find(httptest.NewRecorder(), browser.request(rs)); !errors.Is(err, pendinglogout.ErrNotFound) {
			t.Errorf("Find(%q): %v, want ErrNotFound", rs, err)
		}
	}
	if _, err := tr.Find(httptest.NewRecorder(), jar{}.request("state-1")); !errors.Is(err, pendinglogout.ErrNotFound) {
		t.Errorf("Find without cookies: %v, want ErrNotFound", err)
	}
}

func TestTamperedCookie(t *testing.T) {
	s, _ := newService(t, spSLOURL)
	tr := newTracker(t, s)
	browser := jar{}
	remember(t, tr, browser, "id-1", "state-1", "data")
	var name, value string
	for n, c := range browser {
		name, value = n, c.Value
	}

	other, err := pendinglogout.New(s, bytes.Repeat([]byte("k"), 32))
	if err != nil {
		t.Fatal(err)
	}
	otherJar := jar{}
	remember(t, other, otherJar, "id-1", "state-1", "data")

	body, mac, _ := strings.Cut(value, ".")
	flip := []byte(body)
	flip[len(flip)/2] ^= 1
	for desc, v := range map[string]string{
		"body changed": string(flip) + "." + mac,
		"no MAC":       body,
		"empty":        "",
		"other key":    otherJar[name].Value,
	} {
		t.Run(desc, func(t *testing.T) {
			r := jar{name: {Name: name, Value: v}}.request("state-1")
			w := httptest.NewRecorder()
			if _, err := tr.Find(w, r); !errors.Is(err, pendinglogout.ErrInvalid) {
				t.Errorf("Find: %v, want ErrInvalid", err)
			}
			if cs := w.Result().Cookies(); len(cs) != 1 || cs[0].Name != name || cs[0].MaxAge >= 0 {
				t.Errorf("Find did not clear the invalid slot: %v", cs)
			}
		})
	}

	// A valid cookie moved to another slot is not valid there.
	moved := name[:len(name)-1] + "9"
	if moved == name {
		moved = name[:len(name)-1] + "8"
	}
	r := jar{moved: {Name: moved, Value: value}}.request("state-1")
	if _, err := tr.Find(httptest.NewRecorder(), r); err == nil {
		t.Error("a cookie moved to another slot was accepted")
	}
}

func TestExpired(t *testing.T) {
	s, _ := newService(t, spSLOURL)
	start := time.Now()
	at := func(d time.Duration) *pendinglogout.Tracker {
		return newTracker(t, s, pendinglogout.WithClock(dsig.NewFakeClockAt(start.Add(d))), pendinglogout.WithMaxAge(5*time.Minute))
	}
	browser := jar{}
	remember(t, at(0), browser, "id-1", "state-1", "")
	if _, err := at(4*time.Minute).Find(httptest.NewRecorder(), browser.request("state-1")); err != nil {
		t.Errorf("Find before expiry: %v", err)
	}
	w := httptest.NewRecorder()
	if _, err := at(5*time.Minute).Find(w, browser.request("state-1")); !errors.Is(err, pendinglogout.ErrNotFound) {
		t.Errorf("Find after expiry: %v, want ErrNotFound", err)
	}
	if cs := w.Result().Cookies(); len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Errorf("Find did not clear the expired slot: %v", cs)
	}
}

// TestForgetOnlyAfterVerify checks that a junk LogoutResponse posted with
// the user's RelayState leaves the logout in progress for the real one.
func TestForgetOnlyAfterVerify(t *testing.T) {
	s, ti := newService(t, spSLOURL)
	tr := newTracker(t, s)
	browser := jar{}
	msg, err := s.Request(t.Context(), saml.NameID{Value: "alice@example.com"}, "state-1")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := tr.Remember(w, msg, ""); err != nil {
		t.Fatal(err)
	}
	browser.set(w)

	junk := browser.request("state-1")
	w = httptest.NewRecorder()
	l, err := tr.Find(w, junk)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ParseResponse(t.Context(), junk, l.RequestIDs()...)
	if err == nil || pendinglogout.Answered(err) {
		t.Fatalf("a junk response: ParseResponse %v, Answered %v", err, pendinglogout.Answered(err))
	}
	browser.set(w)

	// The real response is still accepted.
	iw := httptest.NewRecorder()
	ti.idp.ServeSLO(iw, httptest.NewRequest(http.MethodGet, msg.RedirectURL().String(), nil))
	back := browser.addTo(httptest.NewRequest(http.MethodGet, iw.Header().Get("Location"), nil))
	l, err = tr.Find(httptest.NewRecorder(), back)
	if err != nil {
		t.Fatalf("Find after a junk response: %v", err)
	}
	_, err = s.ParseResponse(t.Context(), back, l.RequestIDs()...)
	if !pendinglogout.Answered(err) {
		t.Fatalf("ParseResponse: %v", err)
	}
	// Sent again, it is refused as a replay, which is not an answer.
	_, err = s.ParseResponse(t.Context(), back, l.RequestIDs()...)
	if err == nil || pendinglogout.Answered(err) {
		t.Errorf("replayed: ParseResponse %v, Answered %v", err, pendinglogout.Answered(err))
	}
}

func TestAnswered(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, true},
		{fmt.Errorf("slo: logout response %q: %w", "id", slo.ErrPartialLogout), true},
		{saml.ErrBadStatus{Status: saml.StatusResponder}, true},
		{fmt.Errorf("wrapped: %w", saml.ErrBadStatus{Status: saml.StatusRequester}), true},
		{slo.ErrNoRequestID, false},
		{saml.ErrAssertionReplayed, false},
		{errors.New("bad signature"), false},
	} {
		if got := pendinglogout.Answered(tc.err); got != tc.want {
			t.Errorf("Answered(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestRequestIDs(t *testing.T) {
	var l *pendinglogout.Logout
	if ids := l.RequestIDs(); ids != nil {
		t.Errorf("nil Logout: %v", ids)
	}
	s, _ := newService(t, spSLOURL)
	if _, err := s.ParseResponse(t.Context(), jar{}.request("x"), l.RequestIDs()...); !errors.Is(err, slo.ErrNoRequestID) {
		t.Errorf("ParseResponse with a nil Logout: %v", err)
	}
	if ids := (&pendinglogout.Logout{ID: "id-1"}).RequestIDs(); len(ids) != 1 || ids[0] != "id-1" {
		t.Errorf("RequestIDs = %v", ids)
	}
}

// Find reads the RelayState as ParseResponse does: not from a multipart
// body, which r.FormValue would parse, spooling its files to disk.
func TestFindIgnoresMultipart(t *testing.T) {
	s, _ := newService(t, spSLOURL)
	tr := newTracker(t, s)
	browser := jar{}
	remember(t, tr, browser, "id-1", "state-1", "")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("RelayState", "state-1"); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("upload", "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(bytes.Repeat([]byte("x"), 1<<16)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, spSLOURL, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	browser.addTo(r)
	if _, err := tr.Find(httptest.NewRecorder(), r); !errors.Is(err, pendinglogout.ErrNotFound) {
		t.Errorf("Find with a multipart body: %v, want ErrNotFound", err)
	}
	if r.MultipartForm != nil {
		t.Error("Find parsed the multipart body")
	}

	// The query of an HTTP-Redirect response is read.
	get := browser.addTo(httptest.NewRequest(http.MethodGet, spSLOURL+"?SAMLResponse=x&RelayState=state-1", nil))
	if _, err := tr.Find(httptest.NewRecorder(), get); err != nil {
		t.Errorf("Find with a query: %v", err)
	}
}

// TestTwoLogouts checks that two logouts in progress in one browser are
// both found while their RelayStates fall in different slots, and that a
// later one replaces an earlier one in the same slot.
func TestTwoLogouts(t *testing.T) {
	s, _ := newService(t, spSLOURL)
	tr := newTracker(t, s)

	// Find two RelayStates in different slots, and two in the same.
	slotOf := func(rs string) string {
		w := httptest.NewRecorder()
		if err := tr.Remember(w, &samlsp.Message{ID: "x", RelayState: rs}, ""); err != nil {
			t.Fatal(err)
		}
		return w.Result().Cookies()[0].Name
	}
	var differ, same []string
	first := "state-0"
	for i := 1; differ == nil || same == nil; i++ {
		rs := fmt.Sprintf("state-%d", i)
		if slotOf(rs) == slotOf(first) {
			if same == nil {
				same = []string{first, rs}
			}
		} else if differ == nil {
			differ = []string{first, rs}
		}
	}

	browser := jar{}
	remember(t, tr, browser, "id-a", differ[0], "a")
	remember(t, tr, browser, "id-b", differ[1], "b")
	for i, rs := range differ {
		l, err := tr.Find(httptest.NewRecorder(), browser.request(rs))
		if err != nil {
			t.Fatalf("Find(%q): %v", rs, err)
		}
		if want := []string{"id-a", "id-b"}[i]; l.ID != want {
			t.Errorf("Find(%q).ID = %q, want %q", rs, l.ID, want)
		}
	}
	// Forgetting one leaves the other.
	l, _ := tr.Find(httptest.NewRecorder(), browser.request(differ[0]))
	w := httptest.NewRecorder()
	tr.Forget(w, l)
	browser.set(w)
	if _, err := tr.Find(httptest.NewRecorder(), browser.request(differ[1])); err != nil {
		t.Errorf("Find of the other logout after Forget: %v", err)
	}

	browser = jar{}
	remember(t, tr, browser, "id-a", same[0], "")
	remember(t, tr, browser, "id-b", same[1], "")
	if _, err := tr.Find(httptest.NewRecorder(), browser.request(same[0])); !errors.Is(err, pendinglogout.ErrNotFound) {
		t.Errorf("Find of the replaced logout: %v, want ErrNotFound", err)
	}
	if l, err := tr.Find(httptest.NewRecorder(), browser.request(same[1])); err != nil || l.ID != "id-b" {
		t.Errorf("Find of the later logout: %v, %v", l, err)
	}
}

func TestRememberSizeCap(t *testing.T) {
	s, _ := newService(t, spSLOURL)
	tr := newTracker(t, s)
	if err := tr.Remember(httptest.NewRecorder(), &samlsp.Message{ID: "id-1", RelayState: "s"}, strings.Repeat("x", 600)); err == nil {
		t.Error("Remember accepted a cookie larger than its share of the Cookie header")
	}
	if err := tr.Remember(httptest.NewRecorder(), &samlsp.Message{ID: "id-1", RelayState: "s"}, strings.Repeat("x", 200)); err != nil {
		t.Errorf("Remember with 200 bytes of data: %v", err)
	}
	if err := tr.Remember(httptest.NewRecorder(), &samlsp.Message{RelayState: "s"}, ""); err == nil {
		t.Error("Remember accepted a message without ID")
	}
	if err := tr.Remember(httptest.NewRecorder(), nil, ""); err == nil {
		t.Error("Remember accepted a nil message")
	}
}

func TestNew(t *testing.T) {
	s, _ := newService(t, spSLOURL)
	plain, _ := newService(t, "http://localhost:8000/saml/slo")
	for desc, tc := range map[string]struct {
		s    *slo.Service
		key  []byte
		opts []pendinglogout.Option
		ok   bool
	}{
		"default":                   {s, testKey, nil, true},
		"nil service":               {nil, testKey, nil, false},
		"short key":                 {s, testKey[:31], nil, false},
		"zero max age":              {s, testKey, []pendinglogout.Option{pendinglogout.WithMaxAge(0)}, false},
		"no slots":                  {s, testKey, []pendinglogout.Option{pendinglogout.WithSlots(0)}, false},
		"too many slots":            {s, testKey, []pendinglogout.Option{pendinglogout.WithSlots(pendinglogout.MaxSlots + 1)}, false},
		"too little room":           {s, testKey, []pendinglogout.Option{pendinglogout.WithMaxCookiesSize(100)}, false},
		"bad prefix":                {s, testKey, []pendinglogout.Option{pendinglogout.WithCookiePrefix("a b")}, false},
		"__Host- with SLO path":     {s, testKey, []pendinglogout.Option{pendinglogout.WithCookiePrefix("__Host-logout_")}, false},
		"__Host- with path /":       {s, testKey, []pendinglogout.Option{pendinglogout.WithCookiePrefix("__Host-logout_"), pendinglogout.WithPath("/")}, true},
		"__host- with domain":       {s, testKey, []pendinglogout.Option{pendinglogout.WithCookiePrefix("__host-logout_"), pendinglogout.WithPath("/"), pendinglogout.WithDomain("example.com")}, false},
		"__Host- over http":         {plain, testKey, []pendinglogout.Option{pendinglogout.WithCookiePrefix("__Host-logout_"), pendinglogout.WithPath("/")}, false},
		"__Secure- over http":       {plain, testKey, []pendinglogout.Option{pendinglogout.WithCookiePrefix("__Secure-logout_")}, false},
		"__Secure- over https":      {s, testKey, []pendinglogout.Option{pendinglogout.WithCookiePrefix("__Secure-logout_")}, true},
		"nil option is ignored":     {s, testKey, []pendinglogout.Option{nil}, true},
		"one slot":                  {s, testKey, []pendinglogout.Option{pendinglogout.WithSlots(1)}, true},
		"many slots with more room": {s, testKey, []pendinglogout.Option{pendinglogout.WithSlots(16), pendinglogout.WithMaxCookiesSize(6 << 10)}, true},
	} {
		_, err := pendinglogout.New(tc.s, tc.key, tc.opts...)
		if (err == nil) != tc.ok {
			t.Errorf("%s: New: %v", desc, err)
		}
	}

	// Over http, the cookie is neither Secure nor SameSite=None.
	w := httptest.NewRecorder()
	if err := newTracker(t, plain).Remember(w, &samlsp.Message{ID: "id-1", RelayState: "s"}, ""); err != nil {
		t.Fatal(err)
	}
	c := w.Result().Cookies()[0]
	if c.Secure || c.SameSite == http.SameSiteNoneMode || c.Path != "/saml/slo" {
		t.Errorf("cookie over http: %+v", c)
	}
}
