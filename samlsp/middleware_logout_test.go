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

	sloEndpoints := make([]saml.Endpoint, 0, len(sloBindings))
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

// sessionCookie returns a session cookie for alice, with the given
// SessionIndexes.
func (lt *logoutTest) sessionCookie(t *testing.T, sessionIndexes ...string) *http.Cookie {
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
		Attributes:  Attributes{claimNameSessionIndex: sessionIndexes},
		SAMLSession: true,
	}
	value, err := codec.Encode(claims)
	assert.NilError(t, err)
	return &http.Cookie{Name: provider.Name, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
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

// trackLogoutRequest tracks a LogoutRequest with the given ID, as
// HandleStartLogout does, and returns the tracking cookie.
func (lt *logoutTest) trackLogoutRequest(t *testing.T, id string) *http.Cookie {
	t.Helper()
	resp := httptest.NewRecorder()
	_, err := lt.m.LogoutRequestTracker.TrackRequest(resp,
		httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil), id)
	assert.NilError(t, err)
	cookies := resp.Result().Cookies()
	assert.Assert(t, is.Len(cookies, 1))
	return cookies[0]
}

// logoutTrackingCookie returns the logout request tracking cookie set by resp.
func logoutTrackingCookie(t *testing.T, resp *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range resp.Result().Cookies() {
		if strings.HasPrefix(c.Name, "samlslo_") {
			return c
		}
	}
	t.Fatalf("response sets no logout tracking cookie: %v", resp.Header().Values("Set-Cookie"))
	return nil
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

	// The request is tracked, and the RelayState is the tracking index.
	cookie := logoutTrackingCookie(t, resp)
	assert.Check(t, is.Equal("/saml/slo", cookie.Path))
	assert.Check(t, is.Equal("samlslo_"+location.Query().Get("RelayState"), cookie.Name))
	sloReq := httptest.NewRequest(http.MethodGet, "https://sp.example.com/saml/slo", nil)
	sloReq.AddCookie(cookie)
	tracked := lt.m.LogoutRequestTracker.GetTrackedRequests(sloReq)
	assert.Assert(t, is.Len(tracked, 1))
	assert.Check(t, is.Equal(logoutRequest.ID, tracked[0].SAMLRequestID))
}

// A session made from an assertion with several AuthnStatements keeps the
// SessionIndex of each, and the LogoutRequest lists them all.
func TestHandleStartLogoutSeveralSessionIndexes(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1", "", "session-index-2"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)
	assert.Assert(t, is.Equal(http.StatusFound, resp.Code))

	location, err := url.Parse(resp.Header().Get("Location"))
	assert.NilError(t, err)
	buf, err := testsaml.ParseRedirectRequest(location)
	assert.NilError(t, err)
	var logoutRequest saml.LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &logoutRequest))
	assert.Check(t, is.DeepEqual([]saml.SessionIndex{{Value: "session-index-1"}, {Value: "session-index-2"}},
		logoutRequest.AllSessionIndexes()))
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
	cookie := logoutTrackingCookie(t, resp)
	assert.Check(t, is.Contains(body, `name="RelayState" value="`+strings.TrimPrefix(cookie.Name, "samlslo_")+`"`))
}

func TestHandleStartLogoutWithoutTracker(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	lt.m.LogoutRequestTracker = nil
	var gotErr error
	lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusInternalServerError)
	}

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)
	assert.Check(t, is.Equal(http.StatusInternalServerError, resp.Code))
	assert.Check(t, is.ErrorIs(gotErr, errNoLogoutRequestTracker))
	// The session is kept, since logout did not start.
	assert.Check(t, is.Len(resp.Result().Cookies(), 0))
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
	signedResponse := func(t *testing.T, mutate func(*saml.LogoutResponse)) url.Values {
		lr := lt.logoutResponse(saml.StatusSuccess)
		if mutate != nil {
			mutate(lr)
		}
		return url.Values{"SAMLResponse": {lt.signedIDPMessage(t, lr.Element())}}
	}

	t.Run("accepts a response to a tracked request", func(t *testing.T) {
		tracking := lt.trackLogoutRequest(t, "id-sp-logout-request")
		resp := lt.postToSLO(signedResponse(t, nil), lt.sessionCookie(t, "x"), tracking)
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
		assertSessionDeleted(t, lt, resp)

		// The request stops being tracked.
		cleared := logoutTrackingCookie(t, resp)
		assert.Check(t, is.Equal(tracking.Name, cleared.Name))
		assert.Check(t, is.Equal("", cleared.Value))
		assert.Check(t, is.Equal("/saml/slo", cleared.Path))
	})

	t.Run("ignores the RelayState", func(t *testing.T) {
		form := signedResponse(t, nil)
		form.Set("RelayState", "/elsewhere")
		resp := lt.postToSLO(form, lt.trackLogoutRequest(t, "id-sp-logout-request"))
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		assert.Check(t, is.Equal("/", resp.Header().Get("Location")))
	})

	t.Run("rejects an untracked response", func(t *testing.T) {
		resp := lt.postToSLO(signedResponse(t, nil), lt.sessionCookie(t, "x"))
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
		assert.Check(t, is.Len(resp.Result().Cookies(), 0))
	})

	t.Run("rejects a response to another request", func(t *testing.T) {
		resp := lt.postToSLO(signedResponse(t, nil), lt.trackLogoutRequest(t, "id-other-request"))
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("rejects a response without InResponseTo", func(t *testing.T) {
		resp := lt.postToSLO(
			signedResponse(t, func(lr *saml.LogoutResponse) { lr.InResponseTo = "" }),
			lt.trackLogoutRequest(t, "id-sp-logout-request"))
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("rejects a response to a tracked authentication request", func(t *testing.T) {
		authResp := httptest.NewRecorder()
		_, err := lt.m.RequestTracker.TrackRequest(authResp,
			httptest.NewRequest(http.MethodGet, "https://sp.example.com/hello", nil), "id-sp-logout-request")
		assert.NilError(t, err)
		resp := lt.postToSLO(signedResponse(t, nil), authResp.Result().Cookies()...)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("rejects an unsigned response", func(t *testing.T) {
		doc := etree.NewDocument()
		doc.SetRoot(lt.logoutResponse(saml.StatusSuccess).Element())
		buf, err := doc.WriteToBytes()
		assert.NilError(t, err)
		resp := lt.postToSLO(url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(buf)}},
			lt.trackLogoutRequest(t, "id-sp-logout-request"))
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("rejects a failed logout", func(t *testing.T) {
		resp := lt.postToSLO(
			signedResponse(t, func(lr *saml.LogoutResponse) {
				lr.Status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Responder"
			}),
			lt.trackLogoutRequest(t, "id-sp-logout-request"))
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("without a tracker", func(t *testing.T) {
		lt := newLogoutTest(t, saml.HTTPRedirectBinding)
		tracking := lt.trackLogoutRequest(t, "id-sp-logout-request")
		lt.m.LogoutRequestTracker = nil
		var gotErr error
		lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
			gotErr = err
			w.WriteHeader(http.StatusInternalServerError)
		}
		resp := lt.postToSLO(signedResponse(t, nil), tracking)
		assert.Check(t, is.Equal(http.StatusInternalServerError, resp.Code))
		assert.Check(t, is.ErrorIs(gotErr, errNoLogoutRequestTracker))
	})
}

// TestSPInitiatedLogoutRoundTrip starts logout, answers the LogoutRequest as
// the IDP would, and delivers the LogoutResponse with the cookies the browser
// keeps.
func TestSPInitiatedLogoutRoundTrip(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	start := httptest.NewRecorder()
	lt.m.HandleStartLogout(start, req)
	assert.Assert(t, is.Equal(http.StatusFound, start.Code))

	location, err := url.Parse(start.Header().Get("Location"))
	assert.NilError(t, err)
	buf, err := testsaml.ParseRedirectRequest(location)
	assert.NilError(t, err)
	var logoutRequest saml.LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &logoutRequest))

	lr := lt.logoutResponse(saml.StatusSuccess)
	lr.InResponseTo = logoutRequest.ID
	resp := lt.postToSLO(url.Values{
		"SAMLResponse": {lt.signedIDPMessage(t, lr.Element())},
		"RelayState":   {location.Query().Get("RelayState")},
	}, logoutTrackingCookie(t, start))
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.Equal("/", resp.Header().Get("Location")))

	// The response cannot be replayed once the request is no longer tracked.
	replay := lt.postToSLO(url.Values{"SAMLResponse": {lt.signedIDPMessage(t, lr.Element())}})
	assert.Check(t, is.Equal(http.StatusForbidden, replay.Code))
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
