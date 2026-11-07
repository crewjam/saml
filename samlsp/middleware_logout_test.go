package samlsp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/golang-jwt/jwt/v5"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/testsaml"
)

const (
	logoutTestIDPEntityID = "https://idp.example.com/metadata"
	logoutTestIDPRedirect = "https://idp.example.com/slo/redirect"
	logoutTestIDPPost     = "https://idp.example.com/slo/post"
)

// logoutTestNow is inside the validity period of ../testdata/idp_cert.pem.
var logoutTestNow = time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC)

type logoutTest struct {
	m       *Middleware
	idpKey  *rsa.PrivateKey
	idpCert *x509.Certificate
}

// newLogoutTest returns a middleware whose IDP supports single logout with
// the given bindings, and which trusts ../testdata/idp_cert.pem.
func newLogoutTest(t *testing.T, sloBindings ...string) *logoutTest {
	t.Helper()
	oldTimeNow, oldClock, oldRandReader := saml.TimeNow, saml.Clock, saml.RandReader
	t.Cleanup(func() {
		saml.TimeNow, saml.Clock, saml.RandReader = oldTimeNow, oldClock, oldRandReader
	})
	saml.TimeNow = func() time.Time { return logoutTestNow }
	saml.Clock = dsig.NewFakeClockAt(logoutTestNow)
	saml.RandReader = &testRandomReader{}

	idpKeyPEM, err := os.ReadFile("../testdata/idp_key.pem")
	assert.NilError(t, err)
	idpCertPEM, err := os.ReadFile("../testdata/idp_cert.pem")
	assert.NilError(t, err)
	idpKey := mustParsePrivateKey(idpKeyPEM).(*rsa.PrivateKey)
	idpCert := mustParseCertificate(idpCertPEM)

	var sloEndpoints []saml.Endpoint
	for _, binding := range sloBindings {
		location := logoutTestIDPPost
		if binding == saml.HTTPRedirectBinding {
			location = logoutTestIDPRedirect
		}
		sloEndpoints = append(sloEndpoints, saml.Endpoint{Binding: binding, Location: location})
	}
	idpMetadata := &saml.EntityDescriptor{
		EntityID: logoutTestIDPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					KeyDescriptors: []saml.KeyDescriptor{{
						Use: "signing",
						KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(idpCert.Raw)},
						}}},
					}},
				},
				SingleLogoutServices: sloEndpoints,
			},
			SingleSignOnServices: []saml.Endpoint{
				{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.com/sso"},
			},
		}},
	}

	m, err := New(Options{
		URL:         mustParseURL("https://sp.example.com/"),
		Key:         mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey),
		Certificate: mustParseCertificate(golden.Get(t, "cert.pem")),
		IDPMetadata: idpMetadata,
	})
	assert.NilError(t, err)
	return &logoutTest{m: m, idpKey: idpKey, idpCert: idpCert}
}

// sessionCookie returns a session cookie for alice, with the given SessionIndex.
func (lt *logoutTest) sessionCookie(t *testing.T, sessionIndex string) *http.Cookie {
	t.Helper()
	provider := lt.m.Session.(CookieSessionProvider)
	codec := provider.Codec.(JWTSessionCodec)
	claims := JWTSessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{codec.Audience},
			Issuer:    codec.Issuer,
			Subject:   "alice@example.com",
			IssuedAt:  jwt.NewNumericDate(logoutTestNow),
			ExpiresAt: jwt.NewNumericDate(logoutTestNow.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(logoutTestNow),
		},
		Attributes:  Attributes{claimNameSessionIndex: {sessionIndex}},
		SAMLSession: true,
	}
	value, err := codec.Encode(claims)
	assert.NilError(t, err)
	return &http.Cookie{Name: provider.Name, Value: value}
}

// signedIDPMessage returns the base64 encoding of el, signed by the IDP.
func (lt *logoutTest) signedIDPMessage(t *testing.T, el *etree.Element) string {
	t.Helper()
	ctx, err := dsig.NewSigningContext(lt.idpKey, [][]byte{lt.idpCert.Raw})
	assert.NilError(t, err)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	assert.NilError(t, ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
	signed, err := ctx.SignEnveloped(el)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return base64.StdEncoding.EncodeToString(buf)
}

func (lt *logoutTest) postToSLO(form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, lt.m.ServiceProvider.SloURL.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	lt.m.ServeHTTP(resp, req)
	return resp
}

func (lt *logoutTest) logoutResponse(status string) *saml.LogoutResponse {
	return &saml.LogoutResponse{
		ID:           "id-idp-logout-response",
		InResponseTo: "id-sp-logout-request",
		Version:      "2.0",
		IssueInstant: logoutTestNow,
		Destination:  lt.m.ServiceProvider.SloURL.String(),
		Issuer:       &saml.Issuer{Value: logoutTestIDPEntityID},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: status}},
	}
}

func (lt *logoutTest) logoutRequest() *saml.LogoutRequest {
	return &saml.LogoutRequest{
		ID:           "id-idp-logout-request",
		Version:      "2.0",
		IssueInstant: logoutTestNow,
		Destination:  lt.m.ServiceProvider.SloURL.String(),
		Issuer:       &saml.Issuer{Value: logoutTestIDPEntityID},
		NameID:       &saml.NameID{Value: "alice@example.com"},
	}
}

// assertSessionDeleted checks that resp expires the session cookie.
func assertSessionDeleted(t *testing.T, lt *logoutTest, resp *httptest.ResponseRecorder) {
	t.Helper()
	name := lt.m.Session.(CookieSessionProvider).Name
	for _, c := range resp.Result().Cookies() {
		if c.Name == name {
			assert.Check(t, is.Equal("", c.Value))
			assert.Check(t, c.Expires.Before(logoutTestNow))
			return
		}
	}
	t.Errorf("response does not delete the %s cookie: %v", name, resp.Header().Values("Set-Cookie"))
}

func TestHandleStartLogoutRedirectBinding(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding, saml.HTTPPostBinding)

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assertSessionDeleted(t, lt, resp)

	location, err := url.Parse(resp.Header().Get("Location"))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(logoutTestIDPRedirect, location.Scheme+"://"+location.Host+location.Path))
	buf, err := testsaml.ParseRedirectRequest(location)
	assert.NilError(t, err)
	var logoutRequest saml.LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &logoutRequest))
	assert.Check(t, is.Equal(logoutTestIDPRedirect, logoutRequest.Destination))
	assert.Check(t, is.Equal("alice@example.com", logoutRequest.NameID.Value))
	assert.Check(t, logoutRequest.SessionIndex != nil)
	assert.Check(t, is.Equal("session-index-1", logoutRequest.SessionIndex.Value))
}

func TestHandleStartLogoutPostBinding(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPPostBinding)
	lt.m.ScriptNonce = func(*http.Request) string { return "n0nce" }

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)

	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assertSessionDeleted(t, lt, resp)
	assert.Check(t, is.Contains(resp.Header().Get("Content-Security-Policy"), postRequestScriptHash))
	body := resp.Body.String()
	assert.Check(t, is.Contains(body, `action="`+logoutTestIDPPost+`"`))
	assert.Check(t, is.Contains(body, `name="SAMLRequest"`))
	assert.Check(t, is.Contains(body, `nonce="n0nce"`))
}

func TestHandleStartLogoutWithoutSession(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
}

func TestHandleStartLogoutIDPWithoutSLO(t *testing.T) {
	lt := newLogoutTest(t)

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
	assertSessionDeleted(t, lt, resp)
}

type sessionWithoutNameID struct{}

type staticSessionProvider struct{ session Session }

func (p staticSessionProvider) CreateSession(http.ResponseWriter, *http.Request, *saml.Assertion) error {
	return nil
}
func (p staticSessionProvider) DeleteSession(http.ResponseWriter, *http.Request) error { return nil }
func (p staticSessionProvider) GetSession(*http.Request) (Session, error) {
	return p.session, nil
}

func TestHandleStartLogoutSessionWithoutNameID(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	lt.m.Session = staticSessionProvider{session: sessionWithoutNameID{}}
	var gotErr error
	lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusForbidden)
	}

	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil))
	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	assert.Check(t, is.ErrorIs(gotErr, errLogoutNoNameID))
}

func TestServeSLOLogoutResponse(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)

	t.Run("redirects to /", func(t *testing.T) {
		resp := lt.postToSLO(url.Values{
			"SAMLResponse": {lt.signedIDPMessage(t, lt.logoutResponse(saml.StatusSuccess).Element())},
		}, lt.sessionCookie(t, "x"))
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
		assertSessionDeleted(t, lt, resp)
	})

	t.Run("follows a local RelayState", func(t *testing.T) {
		resp := lt.postToSLO(url.Values{
			"SAMLResponse": {lt.signedIDPMessage(t, lt.logoutResponse(saml.StatusSuccess).Element())},
			"RelayState":   {"/logged-out"},
		})
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		assert.Check(t, is.Equal("/logged-out", resp.Header().Get("Location")))
	})

	t.Run("ignores a foreign RelayState", func(t *testing.T) {
		resp := lt.postToSLO(url.Values{
			"SAMLResponse": {lt.signedIDPMessage(t, lt.logoutResponse(saml.StatusSuccess).Element())},
			"RelayState":   {"https://evil.example.com/"},
		})
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
	})

	t.Run("rejects an unsigned response", func(t *testing.T) {
		doc := etree.NewDocument()
		doc.SetRoot(lt.logoutResponse(saml.StatusSuccess).Element())
		buf, err := doc.WriteToBytes()
		assert.NilError(t, err)
		resp := lt.postToSLO(url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(buf)}})
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("rejects a failed logout", func(t *testing.T) {
		resp := lt.postToSLO(url.Values{
			"SAMLResponse": {lt.signedIDPMessage(t, lt.logoutResponse("urn:oasis:names:tc:SAML:2.0:status:Responder").Element())},
		})
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})
}

func TestServeSLOLogoutRequestRedirectBinding(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding, saml.HTTPPostBinding)

	resp := lt.postToSLO(url.Values{
		"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
		"RelayState":  {"idp-state"},
	}, lt.sessionCookie(t, "x"))

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assertSessionDeleted(t, lt, resp)
	location, err := url.Parse(resp.Header().Get("Location"))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(logoutTestIDPRedirect, location.Scheme+"://"+location.Host+location.Path))
	assert.Check(t, is.Equal("idp-state", location.Query().Get("RelayState")))

	buf, err := testsaml.ParseRedirectResponse(location)
	assert.NilError(t, err)
	var logoutResponse saml.LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &logoutResponse))
	assert.Check(t, is.Equal("id-idp-logout-request", logoutResponse.InResponseTo))
	assert.Check(t, is.Equal(saml.StatusSuccess, logoutResponse.Status.StatusCode.Value))
}

func TestServeSLOLogoutRequestPostBinding(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPPostBinding)

	resp := lt.postToSLO(url.Values{
		"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
		"RelayState":  {"idp-state"},
	}, lt.sessionCookie(t, "x"))

	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assertSessionDeleted(t, lt, resp)
	assert.Check(t, is.Contains(resp.Header().Get("Content-Security-Policy"), postResponseScriptHash))
	body := resp.Body.String()
	assert.Check(t, is.Contains(body, `action="`+logoutTestIDPPost+`"`))
	assert.Check(t, is.Contains(body, `name="SAMLResponse"`))
	assert.Check(t, is.Contains(body, `value="idp-state"`))
}

func TestServeSLOLogoutRequestUnsigned(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	doc := etree.NewDocument()
	doc.SetRoot(lt.logoutRequest().Element())
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	resp := lt.postToSLO(url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)}}, lt.sessionCookie(t, "x"))
	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	assert.Check(t, is.Len(resp.Result().Cookies(), 0))
}

func TestServeSLOEmpty(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	var gotErr error
	lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusBadRequest)
	}
	resp := lt.postToSLO(url.Values{})
	assert.Check(t, is.Equal(http.StatusBadRequest, resp.Code))
	assert.Check(t, is.ErrorIs(gotErr, errSLOUnexpectedMessage))
}
