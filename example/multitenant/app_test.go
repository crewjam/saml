package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"html"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

const spBase = "https://sp.example.com"

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

// testIDP is a tenant's IdP, in process, with one logged-in user.
type testIDP struct {
	idp       *saml.IdentityProvider
	key       *rsa.PrivateKey
	cert      *x509.Certificate
	app       *App
	email     string // the user the IdP logs in
	loggedOut bool
}

func newTestIDP(t *testing.T, app *App, host, email string) *testIDP {
	t.Helper()
	key, cert := newKeyPair(t)
	ti := &testIDP{key: key, cert: cert, app: app, email: email}
	ti.idp = &saml.IdentityProvider{
		Key: key, Certificate: cert,
		MetadataURL:             *mustParseURL("https://" + host + "/metadata"),
		SSOURL:                  *mustParseURL("https://" + host + "/sso"),
		LogoutURL:               *mustParseURL("https://" + host + "/slo"),
		ServiceProviderProvider: ti,
		SessionProvider:         ti,
	}
	return ti
}

func (ti *testIDP) entityID() string { return ti.idp.Metadata().EntityID }

func (ti *testIDP) GetServiceProvider(r *http.Request, _ string) (*saml.EntityDescriptor, error) {
	return ti.app.config.Metadata(r.Context()), nil
}

func (ti *testIDP) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	return &saml.Session{
		ID: "session-1", Index: "index-1",
		CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID: ti.email, NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserEmail: ti.email,
	}
}

//nolint:unparam // implements saml.SessionInvalidator
func (ti *testIDP) InvalidateSession(http.ResponseWriter, *http.Request, *saml.IdpLogoutRequest) error {
	ti.loggedOut = true
	return nil
}

// browser is a user agent with its own cookies.
type browser struct {
	t   *testing.T
	app *App
	jar *cookiejar.Jar
}

func newBrowser(t *testing.T, app *App) *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, app: app, jar: jar}
}

// do sends r to the SP with the browser's cookies, and keeps those it sets.
func (b *browser) do(r *http.Request) *httptest.ResponseRecorder {
	for _, c := range b.jar.Cookies(r.URL) {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.app.Handler().ServeHTTP(w, r)
	b.jar.SetCookies(r.URL, w.Result().Cookies())
	return w
}

func (b *browser) get(target string) *httptest.ResponseRecorder {
	return b.do(httptest.NewRequest(http.MethodGet, target, nil))
}

func (b *browser) post(target string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(r)
}

// loggedInAs returns the email of the browser's session, or "".
func (b *browser) loggedInAs() string {
	body := b.get(spBase + "/").Body.String()
	if m := regexp.MustCompile(`Hello, ([^!]+)!`).FindStringSubmatch(body); m != nil {
		return html.UnescapeString(m[1])
	}
	return ""
}

var formInput = regexp.MustCompile(`name="([A-Za-z]+)" value="([^"]*)"`)

// formValues returns the hidden inputs of an auto-submitting POST form.
func formValues(body string) url.Values {
	v := url.Values{}
	for _, m := range formInput.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

// toIDP returns the request the browser makes to the IdP for an SP answer:
// a redirect, or a form that posts itself.
func toIDP(t *testing.T, w *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	if loc := w.Header().Get("Location"); loc != "" {
		return httptest.NewRequest(http.MethodGet, loc, nil)
	}
	v := formValues(w.Body.String())
	action := regexp.MustCompile(`action="([^"]*)"`).FindStringSubmatch(w.Body.String())
	if action == nil {
		t.Fatalf("not a redirect or a form: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest(http.MethodPost, html.UnescapeString(action[1]), strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// idpSSO returns the IdP's answer, as form values, to the SP's AuthnRequest.
func idpSSO(t *testing.T, ti *testIDP, toSP *httptest.ResponseRecorder) url.Values {
	t.Helper()
	w := httptest.NewRecorder()
	ti.idp.ServeSSO(w, toIDP(t, toSP))
	v := formValues(w.Body.String())
	if v.Get("SAMLResponse") == "" {
		t.Fatalf("the IdP did not answer: %d %s", w.Code, w.Body.String())
	}
	return v
}

// setup returns an App with two tenants, acme.example and globex.example,
// each with its own IdP.
func setup(t *testing.T) (*App, *testIDP, *testIDP) {
	t.Helper()
	key, cert := newKeyPair(t)
	app, err := NewApp(NewDB(), spBase, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	acme := newTestIDP(t, app, "idp.acme.example", "alice@acme.example")
	globex := newTestIDP(t, app, "idp.globex.example", "bob@globex.example")
	admin := newBrowser(t, app)
	for domain, ti := range map[string]*testIDP{"acme.example": acme, "globex.example": globex} {
		if w := admin.post(spBase+"/admin/providers", url.Values{
			"domain": {domain}, "metadata": {metadataXML(t, ti)}, "allow_idp_initiated": {"true"},
		}); w.Code != http.StatusCreated {
			t.Fatalf("adding %s: %d %s", domain, w.Code, w.Body.String())
		}
	}
	return app, acme, globex
}

func metadataXML(t *testing.T, ti *testIDP) string {
	t.Helper()
	buf, err := xml.Marshal(ti.idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}

// login logs b in through ti, the IdP of domain, and checks where it lands.
func login(t *testing.T, b *browser, ti *testIDP, domain string) {
	t.Helper()
	redirect := b.get(spBase + "/sso?domain=" + domain + "&redirect_to=/reports")
	w := b.post(spBase+"/saml/acs", idpSSO(t, ti, redirect))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/reports" {
		t.Fatalf("ACS: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
}

func TestLoginPerTenant(t *testing.T) {
	app, acme, globex := setup(t)

	alice := newBrowser(t, app)
	login(t, alice, acme, "acme.example")
	if got := alice.loggedInAs(); got != "alice@acme.example" {
		t.Errorf("alice is logged in as %q", got)
	}

	bob := newBrowser(t, app)
	login(t, bob, globex, "globex.example")
	if got := bob.loggedInAs(); got != "bob@globex.example" {
		t.Errorf("bob is logged in as %q", got)
	}
}

// A Response is verified against the IdP of the login's tenant: one from
// another tenant's IdP is refused, even with the right RelayState.
func TestOtherTenantsIdPRefused(t *testing.T) {
	app, acme, globex := setup(t)
	b := newBrowser(t, app)
	toAcme := b.get(spBase + "/sso?domain=acme.example")
	relayState := idpSSO(t, acme, toAcme).Get("RelayState")

	// globex's IdP answers a login of its own; its Response is posted
	// with acme's RelayState.
	fromGlobex := idpSSO(t, globex, newBrowser(t, app).get(spBase+"/sso?domain=globex.example"))
	fromGlobex.Set("RelayState", relayState)
	if w := b.post(spBase+"/saml/acs", fromGlobex); w.Code != http.StatusForbidden {
		t.Errorf("globex's Response for acme's login: %d", w.Code)
	}
	if b.loggedInAs() != "" {
		t.Error("logged in")
	}
}

// A tenant's IdP vouches only for its own domain.
func TestOtherDomainRefused(t *testing.T) {
	app, acme, _ := setup(t)
	acme.email = "mallory@globex.example"
	b := newBrowser(t, app)
	if w := b.post(spBase+"/saml/acs", idpSSO(t, acme, b.get(spBase+"/sso?domain=acme.example"))); w.Code != http.StatusForbidden {
		t.Errorf("ACS: %d", w.Code)
	}
}

// A Response to a login started in one browser is refused in another
// (login CSRF), and a login is used once.
func TestLoginBoundToBrowser(t *testing.T) {
	app, acme, _ := setup(t)
	attacker := newBrowser(t, app)
	form := idpSSO(t, acme, attacker.get(spBase+"/sso?domain=acme.example"))

	victim := newBrowser(t, app)
	if w := victim.post(spBase+"/saml/acs", form); w.Code != http.StatusForbidden {
		t.Errorf("another browser: %d", w.Code)
	}
	// The login was used up by that attempt.
	if w := attacker.post(spBase+"/saml/acs", form); w.Code != http.StatusForbidden {
		t.Errorf("used twice: %d", w.Code)
	}
}

func TestIdPInitiatedLogin(t *testing.T) {
	app, acme, _ := setup(t)

	unsolicited := func() url.Values {
		w := httptest.NewRecorder()
		acme.idp.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.acme.example/launch", nil),
			app.config.EntityID(), "/reports")
		return formValues(w.Body.String())
	}

	b := newBrowser(t, app)
	form := unsolicited()
	if w := b.post(spBase+"/saml/acs", form); w.Code != http.StatusFound || w.Header().Get("Location") != "/reports" {
		t.Fatalf("ACS: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if got := b.loggedInAs(); got != "alice@acme.example" {
		t.Errorf("logged in as %q", got)
	}

	// The same Response again is a replay, refused by the replay record.
	if w := newBrowser(t, app).post(spBase+"/saml/acs", form); w.Code != http.StatusForbidden {
		t.Errorf("replayed Response: %d", w.Code)
	}

	// An IdP RelayState that is not a local path is not followed.
	for _, relayState := range []string{"/\\evil.example", "/\t/evil.example"} {
		form = unsolicited()
		form.Set("RelayState", relayState)
		if w := newBrowser(t, app).post(spBase+"/saml/acs", form); w.Header().Get("Location") != "/" {
			t.Errorf("RelayState %q: redirected to %q", relayState, w.Header().Get("Location"))
		}
	}
}

func TestDuplicateEntityIDRefused(t *testing.T) {
	app, acme, _ := setup(t)
	w := newBrowser(t, app).post(spBase+"/admin/providers", url.Values{
		"domain": {"initech.example"}, "metadata": {metadataXML(t, acme)},
	})
	if w.Code != http.StatusConflict {
		t.Errorf("a second provider with acme's IdP: %d", w.Code)
	}
}

func TestSPInitiatedLogout(t *testing.T) {
	app, acme, _ := setup(t)
	b := newBrowser(t, app)
	login(t, b, acme, "acme.example")

	redirect := b.post(spBase+"/logout", nil)
	if b.loggedInAs() != "" {
		t.Fatal("the local session survived")
	}
	w := httptest.NewRecorder()
	acme.idp.ServeSLO(w, toIDP(t, redirect))
	if !acme.loggedOut {
		t.Fatalf("the IdP did not log out: %d %s", w.Code, w.Body.String())
	}

	// The IdP's LogoutResponse comes back to the SP.
	var back *httptest.ResponseRecorder
	if loc := w.Header().Get("Location"); loc != "" {
		back = b.get(loc)
	} else {
		back = b.post(spBase+"/saml/slo", formValues(w.Body.String()))
	}
	if back.Code != http.StatusFound || back.Header().Get("Location") != "/" {
		t.Errorf("LogoutResponse: %d %s", back.Code, back.Body.String())
	}
}

// idpLogoutRequest returns a LogoutRequest from ti for email, signed with
// ti's key, as the IdP would post it.
func idpLogoutRequest(t *testing.T, ti *testIDP, email string) url.Values {
	t.Helper()
	req := &saml.LogoutRequest{
		ID: "id-" + rand.Text(), Version: "2.0", IssueInstant: time.Now().UTC(), Destination: spBase + "/saml/slo",
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: ti.entityID()},
		NameID:       &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: email},
		SessionIndex: &saml.SessionIndex{Value: "index-1"},
	}
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: ti.key, Certificate: [][]byte{ti.cert.Raw}})
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := signer.SignEnveloped(req.Element())
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)}, "RelayState": {"idp-state"}}
}

func TestIdPInitiatedLogout(t *testing.T) {
	app, acme, globex := setup(t)
	alice := newBrowser(t, app)
	login(t, alice, acme, "acme.example")
	idp := newBrowser(t, app) // the IdP's front channel, without the user's cookies

	// globex's IdP cannot log out acme's users: it ends only sessions of
	// its own tenant.
	if w := idp.post(spBase+"/saml/slo", idpLogoutRequest(t, globex, "alice@acme.example")); w.Code >= 400 {
		t.Fatalf("globex's LogoutRequest: %d %s", w.Code, w.Body.String())
	}
	if alice.loggedInAs() == "" {
		t.Fatal("globex's IdP logged out acme's user")
	}

	// A LogoutRequest that claims to be acme's, but is signed by globex,
	// is refused.
	forged := idpLogoutRequest(t, globex, "alice@acme.example")
	forgedXML, _ := base64.StdEncoding.DecodeString(forged.Get("SAMLRequest"))
	forged.Set("SAMLRequest", base64.StdEncoding.EncodeToString(
		[]byte(strings.ReplaceAll(string(forgedXML), globex.entityID(), acme.entityID()))))
	if w := idp.post(spBase+"/saml/slo", forged); w.Code != http.StatusBadRequest {
		t.Errorf("forged LogoutRequest: %d", w.Code)
	}
	if alice.loggedInAs() == "" {
		t.Fatal("a forged LogoutRequest logged out the user")
	}

	// acme's IdP logs alice out, and gets a LogoutResponse.
	w := idp.post(spBase+"/saml/slo", idpLogoutRequest(t, acme, "alice@acme.example"))
	if w.Code >= 400 {
		t.Fatalf("acme's LogoutRequest: %d %s", w.Code, w.Body.String())
	}
	if alice.loggedInAs() != "" {
		t.Error("the session survived")
	}
	if r := toIDP(t, w); !strings.HasPrefix(r.URL.String(), "https://idp.acme.example/slo") {
		t.Errorf("the LogoutResponse goes to %s", r.URL)
	}
}
