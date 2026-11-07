package samlidp

import (
	"encoding/base64"
	"encoding/xml"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"golang.org/x/crypto/bcrypt"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

var samlResponseInputRe = regexp.MustCompile(`<input type="hidden" name="SAMLResponse" value="([^"]*)" />`)

// forceAuthnPassiveTest is a samlidp server with the user alice and a clock
// the test can move forward.
type forceAuthnPassiveTest struct {
	*ServerTest
	now time.Time
}

func newForceAuthnPassiveTest(t *testing.T) *forceAuthnPassiveTest {
	test := &forceAuthnPassiveTest{ServerTest: NewServerTest(t)}
	test.now = saml.TimeNow()
	saml.TimeNow = func() time.Time { return test.now }

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	assert.NilError(t, err)
	assert.NilError(t, test.Store.Put("/users/alice", User{
		Name:           "alice",
		HashedPassword: hashedPassword,
		Email:          "alice@example.com",
	}))
	return test
}

// login logs alice in with POST /login and returns the session cookie.
func (test *forceAuthnPassiveTest) login(t *testing.T) string {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://idp.example.com/login",
		strings.NewReader("user=alice&password=hunter2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	cookie := w.Result().Cookies()
	assert.Assert(t, is.Len(cookie, 1))
	return cookie[0].Name + "=" + cookie[0].Value
}

// sso sends an AuthnRequest with the given ForceAuthn and IsPassive
// attributes to /sso with the HTTP-Redirect binding, with cookie if it is
// not empty, and returns the request and the response.
func (test *forceAuthnPassiveTest) sso(t *testing.T, forceAuthn, isPassive *bool, cookie string) (*saml.AuthnRequest, *httptest.ResponseRecorder) {
	authnRequest, err := test.SP.MakeAuthenticationRequest(
		test.SP.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	assert.NilError(t, err)
	authnRequest.ForceAuthn = forceAuthn
	authnRequest.IsPassive = isPassive
	u, err := authnRequest.Redirect("frob", &test.SP)
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", u.String(), nil)
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	test.Server.ServeHTTP(w, r)
	return authnRequest, w
}

// submitLoginForm fills in the login form in body with alice's credentials
// and posts it.
func (test *forceAuthnPassiveTest) submitLoginForm(t *testing.T, body string, cookie string) *httptest.ResponseRecorder {
	action := loginFormActionRe.FindStringSubmatch(body)
	assert.Assert(t, action != nil, body)
	form := url.Values{"user": {"alice"}, "password": {"hunter2"}}
	for _, m := range loginFormInputRe.FindAllStringSubmatch(body, -1) {
		form.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", html.UnescapeString(action[1]), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	test.Server.ServeHTTP(w, r)
	return w
}

// samlResponse returns the decoded SAMLResponse posted by body.
func samlResponse(t *testing.T, body string) []byte {
	t.Helper()
	m := samlResponseInputRe.FindStringSubmatch(body)
	assert.Assert(t, m != nil, "no SAMLResponse in %s", body)
	buf, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
	assert.NilError(t, err)
	return buf
}

// assertion checks that body posts a successful Response to request and
// returns its assertion.
func (test *forceAuthnPassiveTest) assertion(t *testing.T, body string, request *saml.AuthnRequest) *saml.Assertion {
	t.Helper()
	// The test IdP certificate expired before the test clock's time.
	sp := test.SP
	sp.IgnoreCertificateExpiry = true
	assertion, err := sp.ParseXMLResponse(samlResponse(t, body), []string{request.ID}, sp.AcsURL)
	if ire, ok := err.(*saml.InvalidResponseError); ok {
		err = ire.PrivateErr
	}
	assert.NilError(t, err)
	assert.Assert(t, is.Len(assertion.AuthnStatements, 1))
	return assertion
}

// assertNoPassive checks that body posts an error Response to request with
// the status Responder and NoPassive, and shows no login form.
func assertNoPassive(t *testing.T, w *httptest.ResponseRecorder, request *saml.AuthnRequest) {
	t.Helper()
	body := w.Body.String()
	assert.Check(t, is.Equal(http.StatusOK, w.Code), body)
	assert.Check(t, !strings.Contains(body, `type="password"`), body)
	assert.Check(t, strings.Contains(body, `action="https://sp.example.com/saml2/acs"`), body)

	var response saml.Response
	assert.NilError(t, xml.Unmarshal(samlResponse(t, body), &response))
	assert.Check(t, is.Equal(request.ID, response.InResponseTo))
	assert.Check(t, is.Equal(saml.StatusResponder, response.Status.StatusCode.Value))
	assert.Assert(t, response.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(saml.StatusNoPassive, response.Status.StatusCode.StatusCode.Value))
	assert.Check(t, response.Assertion == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}

var (
	attrTrue  = func() *bool { b := true; return &b }()
	attrFalse = func() *bool { b := false; return &b }()
)

// TestForceAuthnIgnoresExistingSession checks that ForceAuthn="true" makes
// the user log in again although they have a session, and that the
// assertion carries the time of that new authentication.
func TestForceAuthnIgnoresExistingSession(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	loginTime := test.now
	cookie := test.login(t)

	test.now = loginTime.Add(10 * time.Minute)
	request, w := test.sso(t, attrTrue, nil, cookie)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	assert.Check(t, strings.Contains(w.Body.String(), `type="password"`), w.Body.String())
	assert.Assert(t, !strings.Contains(w.Body.String(), `name="SAMLResponse"`), w.Body.String())

	w = test.submitLoginForm(t, w.Body.String(), cookie)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	assertion := test.assertion(t, w.Body.String(), request)
	assert.Check(t, assertion.AuthnStatements[0].AuthnInstant.Equal(test.now),
		"AuthnInstant %s, want %s", assertion.AuthnStatements[0].AuthnInstant, test.now)
}

// TestForceAuthnFalseReusesSession checks that an existing session is still
// used when ForceAuthn is absent or "false".
func TestForceAuthnFalseReusesSession(t *testing.T) {
	for _, forceAuthn := range []*bool{nil, attrFalse} {
		test := newForceAuthnPassiveTest(t)
		loginTime := test.now
		cookie := test.login(t)

		test.now = loginTime.Add(10 * time.Minute)
		request, w := test.sso(t, forceAuthn, nil, cookie)
		assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
		assertion := test.assertion(t, w.Body.String(), request)
		assert.Check(t, assertion.AuthnStatements[0].AuthnInstant.Equal(loginTime))
	}
}

// TestIsPassiveWithoutSessionSendsNoPassive checks that IsPassive="true"
// without a session shows no login form and answers with NoPassive.
func TestIsPassiveWithoutSessionSendsNoPassive(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	request, w := test.sso(t, nil, attrTrue, "")
	assertNoPassive(t, w, request)
}

// TestIsPassiveWithUnknownSessionSendsNoPassive checks that a session cookie
// that names no session is treated as no session.
func TestIsPassiveWithUnknownSessionSendsNoPassive(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	request, w := test.sso(t, nil, attrTrue, sessionCookieName+"=unknown")
	assertNoPassive(t, w, request)
}

// TestIsPassiveWithExpiredSessionSendsNoPassive checks that an expired
// session is treated as no session.
func TestIsPassiveWithExpiredSessionSendsNoPassive(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	cookie := test.login(t)
	test.now = test.now.Add(sessionMaxAge + time.Minute)
	request, w := test.sso(t, nil, attrTrue, cookie)
	assertNoPassive(t, w, request)
}

// TestIsPassiveWithSessionUsesSession checks that IsPassive="true" with a
// session gets an assertion for that session.
func TestIsPassiveWithSessionUsesSession(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	loginTime := test.now
	cookie := test.login(t)

	test.now = loginTime.Add(10 * time.Minute)
	request, w := test.sso(t, nil, attrTrue, cookie)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	assert.Check(t, !strings.Contains(w.Body.String(), `type="password"`), w.Body.String())
	assertion := test.assertion(t, w.Body.String(), request)
	assert.Check(t, assertion.AuthnStatements[0].AuthnInstant.Equal(loginTime))
}

// TestForceAuthnAndIsPassiveSendsNoPassive checks that a request with both
// ForceAuthn and IsPassive set gets NoPassive, with or without a session,
// since samlidp cannot authenticate the user again without a login form.
func TestForceAuthnAndIsPassiveSendsNoPassive(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	cookie := test.login(t)
	request, w := test.sso(t, attrTrue, attrTrue, cookie)
	assertNoPassive(t, w, request)

	request, w = test.sso(t, attrTrue, attrTrue, "")
	assertNoPassive(t, w, request)
}

// TestIsPassiveWithInvalidCredentialsSendsNoPassive checks that invalid
// credentials posted with a passive request do not bring up the login form.
func TestIsPassiveWithInvalidCredentialsSendsNoPassive(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	authnRequest, err := test.SP.MakeAuthenticationRequest(
		test.SP.GetSSOBindingLocation(saml.HTTPPostBinding), saml.HTTPPostBinding, saml.HTTPPostBinding)
	assert.NilError(t, err)
	authnRequest.IsPassive = attrTrue
	doc := etree.NewDocument()
	doc.SetRoot(authnRequest.Element())
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	form := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)},
		"RelayState":  {"frob"},
		"user":        {"alice"},
		"password":    {"wrong"},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://idp.example.com/sso", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assertNoPassive(t, w, authnRequest)
}

// TestGetSessionIsPassiveShowsNoLoginForm calls GetSession directly, as in
// the issue's reproduction: a passive request it cannot answer with a SAML
// Response (it has no assertion consumer service) gets an HTTP error, never
// the login form.
func TestGetSessionIsPassiveShowsNoLoginForm(t *testing.T) {
	test := newForceAuthnPassiveTest(t)
	req := &saml.IdpAuthnRequest{
		IDP:           &test.Server.IDP,
		Request:       saml.AuthnRequest{IsPassive: attrTrue},
		RequestBuffer: []byte("<x/>"),
	}
	w := httptest.NewRecorder()
	session := test.Server.GetSession(w, httptest.NewRequest("GET", "https://idp.example.com/sso", nil), req)
	assert.Check(t, session == nil)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	assert.Check(t, !strings.Contains(w.Body.String(), `type="password"`), w.Body.String())
}
