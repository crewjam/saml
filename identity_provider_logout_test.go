package saml

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

const (
	sloTestNameID       = "alice@example.com"
	sloTestSessionIndex = "session-index-1"
	sloTestRelayState   = "relay-state-1"
)

// fakeSLOSessionProvider is a SessionProvider that implements
// SessionInvalidator.
type fakeSLOSessionProvider struct {
	mockSessionProvider
	sessions    []*Session
	invalidated []*Session
	calls       int
	err         error
}

func (p *fakeSLOSessionProvider) InvalidateSession(w http.ResponseWriter, _ *http.Request, req *IdpLogoutRequest) error {
	p.calls++
	if p.err != nil {
		return p.err
	}
	for _, session := range p.sessions {
		if req.MatchesSession(session) {
			p.invalidated = append(p.invalidated, session)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "idp-session", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	return nil
}

type sloTest struct {
	*IdentityProviderTest
	sessions *fakeSLOSessionProvider
	// spMetadata, if set, replaces the SP metadata the IdP sees.
	spMetadata func(*EntityDescriptor) *EntityDescriptor
}

func newSLOTest(t *testing.T) *sloTest {
	test := &sloTest{IdentityProviderTest: NewIdentityProviderTest(t, applyKey)}
	test.IDP.LogoutURL = mustParseURL("https://idp.example.com/saml/slo")
	test.IDP.LogoutBindings = []string{HTTPRedirectBinding, HTTPPostBinding}

	// The default test SP shares the IdP's key pair. Give it its own, so that
	// a signature made with the wrong key is noticed.
	test.SP.Key = mustParsePrivateKey(golden.Get(t, "key_2017.pem")).(*rsa.PrivateKey)
	test.SP.Certificate = mustParseCertificate(golden.Get(t, "cert_2017.pem"))
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	test.SP.SloURL = mustParseURL("https://sp.example.com/saml2/slo")
	test.SP.LogoutBindings = []string{HTTPRedirectBinding, HTTPPostBinding}
	test.SP.IgnoreCertificateExpiry = true // the test certificates expired in 2014
	test.SP.IDPMetadata = test.IDP.Metadata()

	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID != test.SP.MetadataURL.String() {
				return nil, os.ErrNotExist
			}
			md := test.SP.Metadata()
			if test.spMetadata != nil {
				md = test.spMetadata(md)
			}
			return md, nil
		},
	}

	test.sessions = &fakeSLOSessionProvider{
		sessions: []*Session{
			{ID: "s1", NameID: sloTestNameID, Index: sloTestSessionIndex},
			{ID: "s2", NameID: sloTestNameID, Index: "other-index"},
			{ID: "s3", NameID: "bob@example.com", Index: sloTestSessionIndex},
		},
	}
	test.IDP.SessionProvider = test.sessions
	return test
}

// logoutRequest returns an unsigned LogoutRequest from the SP to the IdP.
func (test *sloTest) logoutRequest() *LogoutRequest {
	return test.SP.makeUnsignedLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID, WithSessionIndex(sloTestSessionIndex))
}

// redirectRequest returns an HTTP request carrying req with the HTTP-Redirect
// binding, signed with a query string signature if the SP has a
// SignatureMethod.
func (test *sloTest) redirectRequest(t *testing.T, req *LogoutRequest) *http.Request {
	u, err := test.SP.RedirectLogoutRequestURL(req, sloTestRelayState)
	assert.NilError(t, err)
	return httptest.NewRequest(http.MethodGet, u.String(), nil)
}

// postRequest returns an HTTP request carrying req with the HTTP-POST
// binding. req is sent as is: sign it first to send a signed request.
func (test *sloTest) postRequest(t *testing.T, req *LogoutRequest) *http.Request {
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return postRequestBytes(test.IDP.LogoutURL.String(), buf)
}

func postRequestBytes(target string, buf []byte) *http.Request {
	form := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)},
		"RelayState":  {sloTestRelayState},
	}
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func (test *sloTest) signedPostRequest(t *testing.T, req *LogoutRequest) *http.Request {
	assert.NilError(t, test.SP.SignLogoutRequest(req))
	return test.postRequest(t, req)
}

func (test *sloTest) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	test.IDP.ServeSLO(w, r)
	return w
}

var samlResponseInputRegexp = regexp.MustCompile(`name="SAMLResponse" value="([^"]*)"`)
var formActionRegexp = regexp.MustCompile(`action="([^"]*)"`)
var relayStateInputRegexp = regexp.MustCompile(`name="RelayState" value="([^"]*)"`)

// spRequestForResponse turns the IdP's HTTP response into the request the
// browser sends to the SP.
func spRequestForResponse(t *testing.T, w *httptest.ResponseRecorder) *http.Request {
	switch w.Code {
	case http.StatusFound:
		return httptest.NewRequest(http.MethodGet, w.Header().Get("Location"), nil)
	case http.StatusOK:
		body := w.Body.String()
		samlResponse := samlResponseInputRegexp.FindStringSubmatch(body)
		action := formActionRegexp.FindStringSubmatch(body)
		relayState := relayStateInputRegexp.FindStringSubmatch(body)
		assert.Assert(t, samlResponse != nil && action != nil && relayState != nil, body)
		form := url.Values{
			"SAMLResponse": {html.UnescapeString(samlResponse[1])},
			"RelayState":   {html.UnescapeString(relayState[1])},
		}
		r := httptest.NewRequest(http.MethodPost, html.UnescapeString(action[1]), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	default:
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		return nil
	}
}

// decodeLogoutResponse returns the LogoutResponse the IdP sent, without
// checking its signature.
func decodeLogoutResponse(t *testing.T, w *httptest.ResponseRecorder) *LogoutResponse {
	r := spRequestForResponse(t, w)
	var buf []byte
	if r.Method == http.MethodGet {
		compressed, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLResponse"))
		assert.NilError(t, err)
		buf, err = io.ReadAll(newSaferFlateReader(bytes.NewReader(compressed)))
		assert.NilError(t, err)
	} else {
		assert.NilError(t, r.ParseForm())
		var err error
		buf, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
		assert.NilError(t, err)
	}
	var resp LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &resp))
	return &resp
}

func TestIDPServeSLORoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name        string
		spBindings  []string
		makeRequest func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request
		wantCode    int
	}{
		{"redirect", []string{HTTPRedirectBinding, HTTPPostBinding},
			func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
				return test.redirectRequest(t, req)
			}, http.StatusFound},
		{"post", []string{HTTPRedirectBinding, HTTPPostBinding},
			func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
				return test.signedPostRequest(t, req)
			}, http.StatusOK},
		{"redirect request, SP only offers post", []string{HTTPPostBinding},
			func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
				return test.redirectRequest(t, req)
			}, http.StatusOK},
		{"post request, SP only offers redirect", []string{HTTPRedirectBinding},
			func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
				return test.signedPostRequest(t, req)
			}, http.StatusFound},
		{"redirect drops enveloped signature and is rejected", []string{HTTPRedirectBinding},
			func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
				assert.NilError(t, test.SP.SignLogoutRequest(req))
				return httptest.NewRequest(http.MethodGet, req.Redirect(sloTestRelayState).String(), nil)
			}, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			test.SP.LogoutBindings = tc.spBindings
			req := test.logoutRequest()

			w := test.serve(tc.makeRequest(t, test, req))
			assert.Equal(t, tc.wantCode, w.Code, w.Body.String())
			if tc.wantCode == http.StatusBadRequest {
				assert.Equal(t, 0, test.sessions.calls)
				assert.Assert(t, is.Len(test.sessions.invalidated, 0))
				return
			}

			// The SP accepts the response: it is signed by the IdP, addressed
			// to the SP's SLO URL, and answers the request.
			spReq := spRequestForResponse(t, w)
			resp, err := test.SP.ParseLogoutResponse(spReq, []string{req.ID})
			assert.NilError(t, err)
			assert.Check(t, is.Equal(req.ID, resp.InResponseTo))
			assert.Check(t, is.Equal(test.IDP.MetadataURL.String(), resp.Issuer.Value))
			assert.Check(t, is.Equal(test.SP.SloURL.String(), resp.Destination))
			assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))

			if spReq.Method == http.MethodGet {
				assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, spReq.URL.Query().Get("SigAlg")))
				assert.Check(t, is.Equal(sloTestRelayState, spReq.URL.Query().Get("RelayState")))
			} else {
				assert.Check(t, is.Equal(sloTestRelayState, spReq.PostForm.Get("RelayState")))
			}

			// Only the session named by NameID and SessionIndex is ended.
			assert.Check(t, is.Equal(1, test.sessions.calls))
			assert.Assert(t, is.Len(test.sessions.invalidated, 1))
			assert.Check(t, is.Equal("s1", test.sessions.invalidated[0].ID))
			assert.Check(t, is.Contains(w.Header().Get("Set-Cookie"), "idp-session="))
		})
	}
}

func TestIDPServeSLOPostResponseUsesSHA256(t *testing.T) {
	test := newSLOTest(t)
	w := test.serve(test.signedPostRequest(t, test.logoutRequest()))
	assert.Equal(t, http.StatusOK, w.Code)
	r := spRequestForResponse(t, w)
	assert.NilError(t, r.ParseForm())
	buf, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(buf), `Algorithm="`+dsig.RSASHA256SignatureMethod+`"`))
	assert.Check(t, !strings.Contains(string(buf), "rsa-sha1"))
}

func TestIDPServeSLOResponseLocation(t *testing.T) {
	test := newSLOTest(t)
	test.spMetadata = func(md *EntityDescriptor) *EntityDescriptor {
		md.SPSSODescriptors[0].SingleLogoutServices = []Endpoint{{
			Binding:          HTTPRedirectBinding,
			Location:         "https://sp.example.com/saml2/slo-request",
			ResponseLocation: "https://sp.example.com/saml2/slo-response",
		}}
		return md
	}
	w := test.serve(test.redirectRequest(t, test.logoutRequest()))
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Check(t, strings.HasPrefix(w.Header().Get("Location"), "https://sp.example.com/saml2/slo-response?SAMLResponse="))
	assert.Check(t, is.Equal("https://sp.example.com/saml2/slo-response", decodeLogoutResponse(t, w).Destination))
}

func TestIDPServeSLOWithoutSessionIndex(t *testing.T) {
	test := newSLOTest(t)
	req := test.logoutRequest()
	req.SessionIndex = nil
	w := test.serve(test.redirectRequest(t, req))
	assert.Equal(t, http.StatusFound, w.Code)
	// Without a SessionIndex, every session of the NameID matches.
	assert.Check(t, is.Len(test.sessions.invalidated, 2))
}

func TestIDPServeSLOSessionNotTerminated(t *testing.T) {
	t.Run("SessionProvider is not a SessionInvalidator", func(t *testing.T) {
		test := newSLOTest(t)
		test.IDP.SessionProvider = &mockSessionProvider{}
		w := test.serve(test.redirectRequest(t, test.logoutRequest()))
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Check(t, is.Equal(StatusResponder, decodeLogoutResponse(t, w).Status.StatusCode.Value))
		// The SP rejects a response that is not a success.
		assert.Check(t, test.SP.ValidateLogoutResponseRequest(spRequestForResponse(t, w)) != nil)
	})
	t.Run("InvalidateSession fails", func(t *testing.T) {
		test := newSLOTest(t)
		test.sessions.err = errors.New("store unavailable")
		w := test.serve(test.signedPostRequest(t, test.logoutRequest()))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Check(t, is.Equal(StatusResponder, decodeLogoutResponse(t, w).Status.StatusCode.Value))
	})
}

// TestIDPServeSLORejectsInvalidRequests checks that invalid logout requests
// are answered with HTTP 400, no LogoutResponse, and no session is ended.
func TestIDPServeSLORejectsInvalidRequests(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(t *testing.T, test *sloTest) *http.Request
	}{
		{"unsigned redirect", func(_ *testing.T, test *sloTest) *http.Request {
			return httptest.NewRequest(http.MethodGet, test.logoutRequest().Redirect(sloTestRelayState).String(), nil)
		}},
		{"unsigned post", func(t *testing.T, test *sloTest) *http.Request {
			return test.postRequest(t, test.logoutRequest())
		}},
		{"redirect signed by another key", func(t *testing.T, test *sloTest) *http.Request {
			test.SP.Key = mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey)
			return test.redirectRequest(t, test.logoutRequest())
		}},
		{"post signed by another key", func(t *testing.T, test *sloTest) *http.Request {
			test.SP.Key = mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey)
			return test.signedPostRequest(t, test.logoutRequest())
		}},
		{"redirect with corrupted signature", func(t *testing.T, test *sloTest) *http.Request {
			r := test.redirectRequest(t, test.logoutRequest())
			q := r.URL.Query()
			sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
			sig[0] ^= 0xff
			return withRawQueryParam(r, "Signature", base64.StdEncoding.EncodeToString(sig))
		}},
		{"redirect with tampered message", func(t *testing.T, test *sloTest) *http.Request {
			signed := test.redirectRequest(t, test.logoutRequest())
			tampered := test.logoutRequest()
			tampered.NameID.Value = "bob@example.com"
			return withRawQueryParam(signed, "SAMLRequest", tampered.Redirect("").Query().Get("SAMLRequest"))
		}},
		{"redirect with downgraded SigAlg", func(t *testing.T, test *sloTest) *http.Request {
			r := test.redirectRequest(t, test.logoutRequest())
			return withRawQueryParam(r, "SigAlg", dsig.RSASHA1SignatureMethod)
		}},
		{"post with tampered message", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			assert.NilError(t, test.SP.SignLogoutRequest(req))
			req.NameID.Value = "bob@example.com"
			return test.postRequest(t, req)
		}},
		{"unknown issuer", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.Issuer.Value = "https://evil.example.com/metadata"
			return test.redirectRequest(t, req)
		}},
		{"missing issuer", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.Issuer = nil
			return test.signedPostRequest(t, req)
		}},
		{"wrong destination", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.Destination = "https://other-idp.example.com/saml/slo"
			return test.redirectRequest(t, req)
		}},
		{"missing destination", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.Destination = ""
			return test.signedPostRequest(t, req)
		}},
		{"expired IssueInstant", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.IssueInstant = TimeNow().Add(-MaxIssueDelay - time.Second)
			return test.redirectRequest(t, req)
		}},
		{"IssueInstant in the future", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.IssueInstant = TimeNow().Add(MaxClockSkew + time.Minute)
			return test.redirectRequest(t, req)
		}},
		{"expired NotOnOrAfter", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			notOnOrAfter := TimeNow().Add(-MaxClockSkew - time.Second)
			req.NotOnOrAfter = &notOnOrAfter
			return test.redirectRequest(t, req)
		}},
		{"wrong version", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.Version = "1.1"
			return test.redirectRequest(t, req)
		}},
		{"missing NameID", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			req.NameID = nil
			return test.signedPostRequest(t, req)
		}},
		{"SP without SLO endpoint", func(t *testing.T, test *sloTest) *http.Request {
			test.SP.LogoutBindings = nil
			return test.redirectRequest(t, test.logoutRequest())
		}},
		{"SP SLO endpoint with unsupported scheme", func(t *testing.T, test *sloTest) *http.Request {
			test.spMetadata = func(md *EntityDescriptor) *EntityDescriptor {
				md.SPSSODescriptors[0].SingleLogoutServices = []Endpoint{{Binding: HTTPRedirectBinding, Location: "javascript:alert(1)"}}
				return md
			}
			return test.redirectRequest(t, test.logoutRequest())
		}},
		{"SP without signing certificate", func(t *testing.T, test *sloTest) *http.Request {
			r := test.redirectRequest(t, test.logoutRequest())
			test.spMetadata = func(md *EntityDescriptor) *EntityDescriptor {
				md.SPSSODescriptors[0].KeyDescriptors = nil
				return md
			}
			return r
		}},
		{"not a LogoutRequest", func(t *testing.T, test *sloTest) *http.Request {
			req := test.logoutRequest()
			el := req.Element()
			el.Tag = "AuthnRequest"
			return postRequestBytes(test.IDP.LogoutURL.String(), test.signElement(t, el))
		}},
		{"LogoutRequest in the wrong namespace", func(t *testing.T, test *sloTest) *http.Request {
			el := test.logoutRequest().Element()
			el.RemoveAttr("xmlns:samlp")
			el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:1.0:protocol")
			return postRequestBytes(test.IDP.LogoutURL.String(), test.signElement(t, el))
		}},
		{"duplicate SAMLRequest parameter", func(t *testing.T, test *sloTest) *http.Request {
			r := test.redirectRequest(t, test.logoutRequest())
			r.URL.RawQuery += "&SAMLRequest=" + url.QueryEscape(r.URL.Query().Get("SAMLRequest"))
			return r
		}},
		{"no SAMLRequest", func(_ *testing.T, test *sloTest) *http.Request {
			return httptest.NewRequest(http.MethodGet, test.IDP.LogoutURL.String(), nil)
		}},
		{"invalid base64", func(_ *testing.T, test *sloTest) *http.Request {
			return httptest.NewRequest(http.MethodGet, test.IDP.LogoutURL.String()+"?SAMLRequest=%21%21", nil)
		}},
		{"empty post", func(_ *testing.T, test *sloTest) *http.Request {
			return postRequestBytes(test.IDP.LogoutURL.String(), nil)
		}},
		{"unsupported method", func(_ *testing.T, test *sloTest) *http.Request {
			return httptest.NewRequest(http.MethodPut, test.IDP.LogoutURL.String(), nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			r := tc.request(t, test)
			w := test.serve(r)
			assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
			assert.Check(t, is.Equal("", w.Header().Get("Location")))
			assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
			assert.Check(t, is.Equal(0, test.sessions.calls))
		})
	}
}

func TestIDPServeSLONoLogoutURL(t *testing.T) {
	test := newSLOTest(t)
	r := test.redirectRequest(t, test.logoutRequest())
	test.IDP.LogoutURL = url.URL{}
	w := test.serve(r)
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, is.Equal(0, test.sessions.calls))
}

func TestIDPServeSLOUnknownSPLookupError(t *testing.T) {
	test := newSLOTest(t)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
			return nil, errors.New("database down")
		},
	}
	w := test.serve(test.redirectRequest(t, test.logoutRequest()))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
}

func TestIDPServeSLOSigningFailure(t *testing.T) {
	test := newSLOTest(t)
	r := test.redirectRequest(t, test.logoutRequest())
	test.IDP.Key = nil
	w := test.serve(r)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	assert.Check(t, is.Equal("", w.Header().Get("Location")))
}

func TestIDPHandlerServesSLO(t *testing.T) {
	test := newSLOTest(t)
	w := httptest.NewRecorder()
	test.IDP.Handler().ServeHTTP(w, test.redirectRequest(t, test.logoutRequest()))
	assert.Check(t, is.Equal(http.StatusFound, w.Code))
}

func TestIDPMetadataLogoutBindings(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.LogoutURL = mustParseURL("https://idp.example.com/saml/slo")
	assert.Check(t, is.DeepEqual([]Endpoint{{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/saml/slo"}},
		test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices))

	test.IDP.LogoutBindings = []string{HTTPRedirectBinding, HTTPPostBinding}
	assert.Check(t, is.DeepEqual([]Endpoint{
		{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/saml/slo"},
		{Binding: HTTPPostBinding, Location: "https://idp.example.com/saml/slo"},
	}, test.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices))
}

func TestIdpLogoutRequestMatchesSession(t *testing.T) {
	req := &IdpLogoutRequest{Request: LogoutRequest{
		NameID:       &NameID{Value: "alice"},
		SessionIndex: &SessionIndex{Value: "idx"},
	}}
	assert.Check(t, req.MatchesSession(&Session{NameID: "alice", Index: "idx"}))
	assert.Check(t, !req.MatchesSession(&Session{NameID: "alice", Index: "other"}))
	assert.Check(t, !req.MatchesSession(&Session{NameID: "bob", Index: "idx"}))
	assert.Check(t, !req.MatchesSession(nil))

	req.Request.SessionIndex = nil
	assert.Check(t, req.MatchesSession(&Session{NameID: "alice", Index: "other"}))

	req.Request.NameID = nil
	assert.Check(t, !req.MatchesSession(&Session{NameID: "", Index: "idx"}))
}

func TestIdpLogoutRequestMisuse(t *testing.T) {
	test := newSLOTest(t)
	req, err := NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, test.logoutRequest()))
	assert.NilError(t, err)
	// Making or writing a response before Validate does not panic.
	assert.Check(t, is.Equal("", req.MakeLogoutResponse(StatusSuccess).Destination))
	assert.Check(t, req.WriteLogoutResponse(httptest.NewRecorder(), req.MakeLogoutResponse(StatusSuccess)) != nil)

	test.IDP.ServiceProviderProvider = nil
	assert.Check(t, is.ErrorContains(req.Validate(), "ServiceProviderProvider is not set"))
}

// signElement signs el with the SP's key and returns it serialized.
func (test *sloTest) signElement(t *testing.T, el *etree.Element) []byte {
	signingContext, err := GetSigningContext(&test.SP)
	assert.NilError(t, err)
	signed, err := signingContext.SignEnveloped(el)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return buf
}

// withRawQueryParam returns a copy of r with the query parameter name
// replaced by value, keeping the order of the parameters.
func withRawQueryParam(r *http.Request, name, value string) *http.Request {
	parts := strings.Split(r.URL.RawQuery, "&")
	for i, part := range parts {
		if strings.HasPrefix(part, name+"=") {
			parts[i] = name + "=" + url.QueryEscape(value)
		}
	}
	u := *r.URL
	u.RawQuery = strings.Join(parts, "&")
	return httptest.NewRequest(r.Method, u.String(), nil)
}
