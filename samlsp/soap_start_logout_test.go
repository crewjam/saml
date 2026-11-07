package samlsp

import (
	"context"
	"crypto/x509"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// soapStartLogoutIDP is a fake IdP SOAP SingleLogoutService for
// HandleStartLogout. It records the body of each request and answers with a
// LogoutResponse, signed by the IdP, with status.
type soapStartLogoutIDP struct {
	*httptest.Server
	lt     *logoutTest
	status string

	mu     sync.Mutex
	bodies [][]byte
}

// newSOAPStartLogoutTest returns a logoutTest whose IdP supports single
// logout with the given front-channel bindings and with the SOAP binding at
// a fake IdP, and whose middleware has LogoutBinding set to SOAP. OnError
// records its errors in errs.
func newSOAPStartLogoutTest(t *testing.T, errs *[]error, frontChannelBindings ...string) (*logoutTest, *soapStartLogoutIDP) {
	t.Helper()
	lt := newLogoutTest(t, frontChannelBindings...)
	idp := &soapStartLogoutIDP{lt: lt, status: saml.StatusSuccess}
	idp.Server = httptest.NewTLSServer(http.HandlerFunc(idp.serveHTTP))
	t.Cleanup(idp.Close)

	descriptor := &lt.m.ServiceProvider.IDPMetadata.IDPSSODescriptors[0]
	descriptor.SingleLogoutServices = append(descriptor.SingleLogoutServices,
		saml.Endpoint{Binding: saml.SOAPBinding, Location: idp.URL})
	lt.m.ServiceProvider.HTTPClient = idp.Client()
	lt.m.LogoutBinding = saml.SOAPBinding
	lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		*errs = append(*errs, err)
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return lt, idp
}

func (idp *soapStartLogoutIDP) serveHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	idp.mu.Lock()
	idp.bodies = append(idp.bodies, body)
	idp.mu.Unlock()

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	requestEl := doc.FindElement("/Envelope/Body/LogoutRequest")
	if requestEl == nil {
		http.Error(w, "no LogoutRequest", http.StatusBadRequest)
		return
	}
	resp := &saml.LogoutResponse{
		ID:           "id-idp-soap-logout-response",
		InResponseTo: requestEl.SelectAttrValue("ID", ""),
		Version:      "2.0",
		IssueInstant: logoutTestNow,
		Issuer:       &saml.Issuer{Value: logoutTestIDPEntityID},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: idp.status}},
	}
	ctx, err := dsig.NewSigningContext(idp.lt.idpKey, [][]byte{idp.lt.idpCert.Raw})
	if err != nil {
		http.Error(w, "cannot sign", http.StatusInternalServerError)
		return
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(resp.Element())
	if err != nil {
		http.Error(w, "cannot sign", http.StatusInternalServerError)
		return
	}
	envelope := etree.NewElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", soapEnvelopeNS)
	envelope.CreateElement("soapenv:Body").AddChild(signed)
	out := etree.NewDocument()
	out.SetRoot(envelope)
	w.Header().Set("Content-Type", "text/xml")
	_, _ = out.WriteTo(w)
}

// requests returns the LogoutRequests the IdP received, after checking that
// each is signed by the SP.
func (idp *soapStartLogoutIDP) requests(t *testing.T) []saml.LogoutRequest {
	t.Helper()
	idp.mu.Lock()
	defer idp.mu.Unlock()
	requests := make([]saml.LogoutRequest, 0, len(idp.bodies))
	for _, body := range idp.bodies {
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(body))
		requestEl := doc.FindElement("/Envelope/Body/LogoutRequest")
		assert.Assert(t, requestEl != nil, string(body))

		validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{idp.lt.m.ServiceProvider.Certificate},
		})
		validationContext.Clock = dsig.NewFakeClockAt(logoutTestNow)
		_, err := validationContext.Validate(requestEl)
		assert.NilError(t, err, "the LogoutRequest is not signed by the SP")

		requestDoc := etree.NewDocument()
		requestDoc.SetRoot(requestEl.Copy())
		buf, err := requestDoc.WriteToBytes()
		assert.NilError(t, err)
		var req saml.LogoutRequest
		assert.NilError(t, xml.Unmarshal(buf, &req))
		requests = append(requests, req)
	}
	return requests
}

// soapStartLogoutNameID is the NameID of the sessions of fullNameIDCookie.
var soapStartLogoutNameID = saml.NameID{
	Format:          string(saml.PersistentNameIDFormat),
	NameQualifier:   logoutTestIDPEntityID,
	SPNameQualifier: "https://sp.example.com/saml/metadata",
	Value:           "alice@example.com",
}

// fullNameIDCookie returns a session cookie for alice, as JWTSessionCodec
// makes it from an assertion, so that it records her full NameID, with the
// given SessionIndexes.
func (lt *logoutTest) fullNameIDCookie(t *testing.T, sessionIndexes ...string) *http.Cookie {
	t.Helper()
	provider := lt.m.Session.(CookieSessionProvider)
	nameID := soapStartLogoutNameID
	assertion := &saml.Assertion{Subject: &saml.Subject{NameID: &nameID}}
	for _, sessionIndex := range sessionIndexes {
		assertion.AuthnStatements = append(assertion.AuthnStatements, saml.AuthnStatement{SessionIndex: sessionIndex})
	}
	session, err := provider.Codec.New(assertion)
	assert.NilError(t, err)
	value, err := provider.Codec.Encode(session)
	assert.NilError(t, err)
	return &http.Cookie{Name: provider.Name, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
}

// startLogout calls HandleStartLogout with cookie and ctx.
func (lt *logoutTest) startLogout(ctx context.Context, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil).WithContext(ctx)
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)
	return resp
}

// checkSessionDeletedOnce checks that resp deletes the session cookie, and
// sets it no more times than DeleteSession does.
func checkSessionDeletedOnce(t *testing.T, lt *logoutTest, resp *httptest.ResponseRecorder, cookie *http.Cookie) {
	t.Helper()
	assertSessionDeleted(t, lt, resp)
	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(cookie)
	deleted := httptest.NewRecorder()
	assert.NilError(t, lt.m.Session.DeleteSession(deleted, req))
	assert.Check(t, is.Equal(sessionCookieHeaders(lt, resp), sessionCookieHeaders(lt, deleted)))
}

// sessionCookieHeaders returns how many Set-Cookie headers of resp are for
// the session cookie.
func sessionCookieHeaders(lt *logoutTest, resp *httptest.ResponseRecorder) int {
	name := lt.m.Session.(CookieSessionProvider).Name
	n := 0
	for _, c := range resp.Result().Cookies() {
		if c.Name == name {
			n++
		}
	}
	return n
}

// With LogoutBinding set to SOAP, HandleStartLogout sends the IdP a signed
// LogoutRequest from the server, with the full NameID and every
// SessionIndex of the session, deletes the local session and redirects the
// browser to "/".
func TestHandleStartLogoutSOAP(t *testing.T) {
	var errs []error
	lt, idp := newSOAPStartLogoutTest(t, &errs, saml.HTTPRedirectBinding)

	cookie := lt.fullNameIDCookie(t, "index-1", "index-2")
	resp := lt.startLogout(context.Background(), cookie)

	assert.Check(t, is.Len(errs, 0))
	assert.Check(t, is.Equal(resp.Code, http.StatusFound))
	assert.Check(t, is.Equal(resp.Header().Get("Location"), "/"))
	checkSessionDeletedOnce(t, lt, resp, cookie)
	// The request is not tracked: no LogoutResponse comes through the
	// browser.
	for _, c := range resp.Result().Cookies() {
		assert.Check(t, !strings.HasPrefix(c.Name, "samlslo_"), c.Name)
	}

	requests := idp.requests(t)
	assert.Assert(t, is.Len(requests, 1))
	assert.Check(t, is.Equal(requests[0].Destination, idp.URL))
	assert.Assert(t, requests[0].NameID != nil)
	assert.Check(t, is.DeepEqual(*requests[0].NameID, soapStartLogoutNameID))
	assert.Check(t, is.DeepEqual(requests[0].AllSessionIndexes(),
		[]saml.SessionIndex{{Value: "index-1"}, {Value: "index-2"}}))
}

// When the SOAP logout fails, the error is passed to OnError and the local
// session is deleted all the same. If the IdP has a front-channel
// SingleLogoutService, the browser is sent there with a LogoutRequest, so
// that the IdP can still end its session; otherwise it is redirected to "/".
func TestHandleStartLogoutSOAPFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		frontChannel bool
		setup        func(idp *soapStartLogoutIDP)
		ctx          func() context.Context
		wantErr      error
	}{
		{name: "non-Success status", frontChannel: true, setup: func(idp *soapStartLogoutIDP) {
			idp.status = saml.StatusResponder
		}, wantErr: saml.ErrBadStatus{Status: saml.StatusResponder}},
		{name: "non-Success status without front channel", setup: func(idp *soapStartLogoutIDP) {
			idp.status = saml.StatusResponder
		}, wantErr: saml.ErrBadStatus{Status: saml.StatusResponder}},
		{name: "IdP unreachable", frontChannel: true, setup: func(idp *soapStartLogoutIDP) {
			idp.Close()
		}},
		{name: "IdP unreachable without front channel", setup: func(idp *soapStartLogoutIDP) {
			idp.Close()
		}},
		{name: "request context is used", frontChannel: true, ctx: func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		}, wantErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var errs []error
			var bindings []string
			if tc.frontChannel {
				bindings = []string{saml.HTTPPostBinding}
			}
			lt, idp := newSOAPStartLogoutTest(t, &errs, bindings...)
			if tc.setup != nil {
				tc.setup(idp)
			}
			ctx := context.Background()
			if tc.ctx != nil {
				ctx = tc.ctx()
			}

			cookie := lt.fullNameIDCookie(t, "index-1")
			resp := lt.startLogout(ctx, cookie)

			assert.Assert(t, is.Len(errs, 1))
			assert.Check(t, is.ErrorIs(errs[0], errSOAPStartLogoutFailed))
			if tc.wantErr != nil {
				assert.Check(t, is.ErrorIs(errs[0], tc.wantErr))
			}
			checkSessionDeletedOnce(t, lt, resp, cookie)

			if !tc.frontChannel {
				assert.Check(t, is.Equal(resp.Code, http.StatusFound))
				assert.Check(t, is.Equal(resp.Header().Get("Location"), "/"))
				return
			}
			assert.Check(t, is.Equal(resp.Code, http.StatusOK))
			body := resp.Body.String()
			assert.Check(t, is.Contains(body, `action="`+logoutTestIDPPost+`"`))
			assert.Check(t, is.Contains(body, `name="SAMLRequest"`))
			// The front-channel request is tracked, for the LogoutResponse.
			logoutTrackingCookie(t, resp)
		})
	}
}

// A session that does not record the full NameID, made before samlsp
// recorded it, is logged out through the browser, as before.
func TestHandleStartLogoutSOAPSessionWithoutFullNameID(t *testing.T) {
	var errs []error
	lt, idp := newSOAPStartLogoutTest(t, &errs, saml.HTTPRedirectBinding)

	resp := lt.startLogout(context.Background(), lt.sessionCookie(t, "index-1"))

	assert.Check(t, is.Len(errs, 0))
	assert.Check(t, is.Len(idp.requests(t), 0))
	assertSessionDeleted(t, lt, resp)
	assert.Check(t, is.Equal(resp.Code, http.StatusFound))
	assert.Check(t, strings.HasPrefix(resp.Header().Get("Location"), logoutTestIDPRedirect+"?"), resp.Header().Get("Location"))
}

// The SOAP binding is used only when LogoutBinding selects it.
func TestHandleStartLogoutSOAPNotSelected(t *testing.T) {
	var errs []error
	lt, idp := newSOAPStartLogoutTest(t, &errs, saml.HTTPRedirectBinding)
	lt.m.LogoutBinding = ""

	resp := lt.startLogout(context.Background(), lt.fullNameIDCookie(t, "index-1"))

	assert.Check(t, is.Len(errs, 0))
	assert.Check(t, is.Len(idp.requests(t), 0))
	assert.Check(t, strings.HasPrefix(resp.Header().Get("Location"), logoutTestIDPRedirect+"?"), resp.Header().Get("Location"))
}

// With LogoutBinding set to SOAP but no SOAP SingleLogoutService at the
// IdP, HandleStartLogout uses the front channel.
func TestHandleStartLogoutSOAPNotSupportedByIDP(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPPostBinding)
	lt.m.LogoutBinding = saml.SOAPBinding

	resp := lt.startLogout(context.Background(), lt.fullNameIDCookie(t, "index-1"))

	assert.Check(t, is.Equal(resp.Code, http.StatusOK))
	assertSessionDeleted(t, lt, resp)
	assert.Check(t, is.Contains(resp.Body.String(), `action="`+logoutTestIDPPost+`"`))
}

// The LogoutResponse to IdP initiated front-channel logout is sent through
// the browser when LogoutBinding is SOAP.
func TestServeSLOLogoutRequestWithSOAPLogoutBinding(t *testing.T) {
	var errs []error
	lt, _ := newSOAPStartLogoutTest(t, &errs, saml.HTTPRedirectBinding)

	resp := lt.postToSLO(url.Values{
		"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
		"RelayState":  {"idp-state"},
	}, lt.sessionCookie(t, "x"))

	assert.Check(t, is.Len(errs, 0))
	assertSessionDeleted(t, lt, resp)
	assert.Check(t, is.Equal(resp.Code, http.StatusFound))
	assert.Check(t, strings.HasPrefix(resp.Header().Get("Location"), logoutTestIDPRedirect+"?"), resp.Header().Get("Location"))
}

func TestNewSOAPLogoutBindingOption(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/"), LogoutBinding: saml.SOAPBinding}
	m := &Middleware{}
	assert.NilError(t, applyBindingOptions(m, opts))
	assert.Check(t, is.Equal(m.LogoutBinding, saml.SOAPBinding))
}
