package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// newSLOServerTest returns a ServerTest whose SP has single logout set up,
// signs its messages with its own key, and is registered with the IdP.
func newSLOServerTest(t *testing.T) *ServerTest {
	test := NewServerTest(t)

	// The default test SP shares the IdP's key, so give it its own.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	test.SP.Key = key
	test.SP.Certificate = cert
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.SP.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	test.SP.LogoutBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}
	test.SP.IgnoreCertificateExpiry = true // the IdP test certificate expired in 2014
	test.Server.serviceProviders[test.SP.MetadataURL.String()] = test.SP.Metadata()
	return test
}

// login creates the user and logs them in, returning the session and the
// session cookie.
func (test *ServerTest) login(t *testing.T, name, email string) (*saml.Session, *http.Cookie) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "https://idp.example.com/users/"+name,
		strings.NewReader(`{"name": "`+name+`", "email": "`+email+`", "password": "hunter2"}`))
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "https://idp.example.com/login",
		strings.NewReader("user="+name+"&password=hunter2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	session := &saml.Session{}
	assert.NilError(t, json.Unmarshal(w.Body.Bytes(), session))
	cookies := w.Result().Cookies()
	assert.Assert(t, is.Len(cookies, 1))
	return session, cookies[0]
}

func (test *ServerTest) sessionExists(t *testing.T, id string) bool {
	err := test.Store.Get(sessionKey(id), &saml.Session{})
	if errors.Is(err, ErrNotFound) {
		return false
	}
	assert.NilError(t, err)
	return true
}

func (test *ServerTest) logoutRequest(t *testing.T, nameID, sessionIndex string) *saml.LogoutRequest {
	req, err := test.SP.MakeLogoutRequest(test.Server.IDP.LogoutURL.String(), nameID, saml.WithSessionIndex(sessionIndex))
	assert.NilError(t, err)
	return req
}

func TestSLORedirectWithSessionCookie(t *testing.T) {
	test := newSLOServerTest(t)
	assert.Check(t, is.Equal("https://idp.example.com/slo", test.SP.GetSLOBindingLocation(saml.HTTPRedirectBinding)))
	assert.Check(t, is.Equal("https://idp.example.com/slo", test.SP.GetSLOBindingLocation(saml.HTTPPostBinding)))

	session, cookie := test.login(t, "alice", "alice@example.com")
	otherSession, _ := test.login(t, "alice", "alice@example.com")

	logoutRequest := test.logoutRequest(t, session.NameID, session.Index)
	u, err := test.SP.RedirectLogoutRequestURL(logoutRequest, "relay")
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u.String(), nil)
	r.AddCookie(cookie)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusFound, w.Code, w.Body.String())

	// The session cookie is expired and the session is deleted; the user's
	// other session is not.
	cookies := w.Result().Cookies()
	assert.Assert(t, is.Len(cookies, 1))
	assert.Check(t, is.Equal(sessionCookieName, cookies[0].Name))
	assert.Check(t, cookies[0].MaxAge < 0)
	assert.Check(t, !test.sessionExists(t, session.ID))
	assert.Check(t, test.sessionExists(t, otherSession.ID))

	// The SP accepts the LogoutResponse.
	spReq := httptest.NewRequest(http.MethodGet, w.Header().Get("Location"), nil)
	resp, err := test.SP.ParseLogoutResponse(spReq, []string{logoutRequest.ID})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(saml.StatusSuccess, resp.Status.StatusCode.Value))
	assert.Check(t, is.Equal("relay", spReq.URL.Query().Get("RelayState")))
}

func TestSLOPostWithoutSessionCookie(t *testing.T) {
	test := newSLOServerTest(t)
	session, _ := test.login(t, "alice", "alice@example.com")
	bobSession, _ := test.login(t, "bob", "bob@example.com")

	// A POST that does not carry the session cookie (for example from a
	// browser that blocks third-party cookies): the session is found by its
	// SessionIndex.
	form := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(test.logoutRequestBytes(t, session.NameID, session.Index))},
		"RelayState":  {"relay"},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Check(t, is.Contains(w.Body.String(), `action="https://sp.example.com/saml2/slo"`))
	assert.Check(t, !test.sessionExists(t, session.ID))
	assert.Check(t, test.sessionExists(t, bobSession.ID))
}

func TestSLODoesNotEndOtherUsersSession(t *testing.T) {
	test := newSLOServerTest(t)
	aliceSession, _ := test.login(t, "alice", "alice@example.com")
	bobSession, bobCookie := test.login(t, "bob", "bob@example.com")

	// A LogoutRequest for alice's NameID with bob's SessionIndex, sent by
	// bob's browser, ends neither session.
	u, err := test.SP.RedirectLogoutRequestURL(test.logoutRequest(t, aliceSession.NameID, bobSession.Index), "")
	assert.NilError(t, err)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u.String(), nil)
	r.AddCookie(bobCookie)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Check(t, test.sessionExists(t, aliceSession.ID))
	assert.Check(t, test.sessionExists(t, bobSession.ID))
	assert.Check(t, is.Len(w.Result().Cookies(), 0))
}

func TestSLORejectsUnsignedRequest(t *testing.T) {
	test := newSLOServerTest(t)
	session, cookie := test.login(t, "alice", "alice@example.com")

	unsigned := *test.logoutRequest(t, session.NameID, session.Index)
	unsigned.Signature = nil
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, unsigned.Redirect("").String(), nil)
	r.AddCookie(cookie)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, test.sessionExists(t, session.ID))
	assert.Check(t, is.Len(w.Result().Cookies(), 0))
}

func (test *ServerTest) logoutRequestBytes(t *testing.T, nameID, sessionIndex string) []byte {
	buf, err := test.logoutRequest(t, nameID, sessionIndex).Bytes()
	assert.NilError(t, err)
	return buf
}
