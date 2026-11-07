package samlidp

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
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

const soapEnvelopeNS = "http://schemas.xmlsoap.org/soap/envelope/"

// soapSP is a service provider with a SOAP SingleLogoutService on an
// httptest server, which accepts the IdP's LogoutRequests over SOAP.
type soapSP struct {
	sp     saml.ServiceProvider
	server *httptest.Server

	mu       sync.Mutex
	received []*saml.LogoutRequest
	errs     []string
}

func (pt *propagationServerTest) addSOAPSP(t *testing.T) *soapSP {
	p := &soapSP{}
	p.server = httptest.NewServer(http.HandlerFunc(p.serveSOAP))
	t.Cleanup(p.server.Close)
	p.sp = pt.SP
	p.sp.MetadataURL = mustParseURL(p.server.URL + "/saml2/metadata")
	p.sp.AcsURL = mustParseURL(p.server.URL + "/saml2/acs")
	p.sp.SloURL = mustParseURL(p.server.URL + "/saml2/slo")
	p.sp.LogoutBindings = []string{saml.SOAPBinding}
	pt.Server.serviceProviders[p.sp.MetadataURL.String()] = p.sp.Metadata()
	return p
}

// serveSOAP takes the LogoutRequest out of the SOAP envelope, has the SP
// validate it (as the HTTP-POST binding carries it, since both use an
// enveloped signature), and answers with a signed Success LogoutResponse.
func (p *soapSP) serveSOAP(w http.ResponseWriter, r *http.Request) {
	fail := func(msg string) {
		p.mu.Lock()
		p.errs = append(p.errs, msg)
		p.mu.Unlock()
		http.Error(w, msg, http.StatusBadRequest)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fail(err.Error())
		return
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		fail(err.Error())
		return
	}
	reqEl := doc.FindElement("/Envelope/Body/LogoutRequest")
	if reqEl == nil {
		fail("no LogoutRequest")
		return
	}
	reqDoc := etree.NewDocument()
	reqDoc.SetRoot(reqEl.Copy())
	reqXML, err := reqDoc.WriteToBytes()
	if err != nil {
		fail(err.Error())
		return
	}
	form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(reqXML)}}
	postReq := httptest.NewRequest(http.MethodPost, p.sp.SloURL.String(), strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req, err := p.sp.ValidateLogoutRequest(postReq)
	if err != nil {
		fail(err.Error())
		return
	}
	p.mu.Lock()
	p.received = append(p.received, req)
	p.mu.Unlock()

	resp, err := p.sp.MakeLogoutResponse("", req.ID)
	if err != nil {
		fail(err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = w.Write(soapEnvelopeOf(resp.Element()))
}

func (p *soapSP) requests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.received)
}

// soapEnvelopeOf returns el in a SOAP 1.1 envelope.
func soapEnvelopeOf(el *etree.Element) []byte {
	envelope := etree.NewElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", soapEnvelopeNS)
	envelope.CreateElement("soapenv:Body").AddChild(el)
	doc := etree.NewDocument()
	doc.SetRoot(envelope)
	buf, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	return buf
}

// soapLogout sends req to the IdP's /slo with the SOAP binding, without the
// browser's cookies, and returns the LogoutResponse, after checking its
// signature by the IdP.
func (pt *propagationServerTest) soapLogout(t *testing.T, req *saml.LogoutRequest) *saml.LogoutResponse {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", bytes.NewReader(soapEnvelopeOf(req.Element())))
	r.Header.Set("Content-Type", "text/xml")
	w := httptest.NewRecorder()
	pt.Server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(w.Body.Bytes()))
	respEl := doc.FindElement("/Envelope/Body/LogoutResponse")
	assert.Assert(t, respEl != nil, w.Body.String())
	respDoc := etree.NewDocument()
	respDoc.SetRoot(respEl.Copy())

	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{pt.Certificate}})
	validationContext.IdAttribute = "ID"
	validationContext.Clock = dsig.NewFakeClockAt(pt.Certificate.NotBefore)
	signed, err := validationContext.Validate(respDoc.Root())
	assert.NilError(t, err, "the LogoutResponse is signed by the IdP")
	signedDoc := etree.NewDocument()
	signedDoc.SetRoot(signed)
	buf, err := signedDoc.WriteToBytes()
	assert.NilError(t, err)
	var resp saml.LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &resp))
	assert.Check(t, is.Equal(req.ID, resp.InResponseTo))
	return &resp
}

func newSOAPLogoutServerTest(t *testing.T) *propagationServerTest {
	pt := newPropagationServerTest(t)
	pt.Server.IDP.LogoutBindings = append(pt.Server.IDP.LogoutBindings, saml.SOAPBinding)
	return pt
}

// An SP logs the user out over SOAP: samlidp ends the session without its
// cookie, the other SOAP participant is logged out over SOAP, and the
// front-channel only one cannot be, so the logout is partial.
func TestSOAPLogoutEndsSessionsAndPropagates(t *testing.T) {
	for _, tc := range []struct {
		name         string
		sessionIndex bool
		frontChannel bool
		wantPartial  bool
	}{
		{"with SessionIndex", true, false, false},
		{"without SessionIndex", false, false, false},
		{"with a front-channel only participant", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pt := newSOAPLogoutServerTest(t)
			other := pt.addSOAPSP(t)
			session, cookie := pt.login(t, "alice", "alice@example.com")
			pt.cookies[cookie.Name] = cookie
			pt.sso(t, &pt.SP)
			pt.sso(t, &other.sp)
			if tc.frontChannel {
				pt.sso(t, &pt.sp2)
			}

			var opts []saml.LogoutRequestOption
			if tc.sessionIndex {
				opts = append(opts, saml.WithSessionIndex(session.Index))
			}
			req, err := pt.SP.MakeLogoutRequest(pt.Server.IDP.LogoutURL.String(), session.NameID, opts...)
			assert.NilError(t, err)
			resp := pt.soapLogout(t, req)

			assert.Check(t, is.Equal(saml.StatusSuccess, resp.Status.StatusCode.Value))
			if tc.wantPartial {
				assert.Check(t, resp.Status.StatusCode.StatusCode != nil && resp.Status.StatusCode.StatusCode.Value == saml.StatusPartialLogout)
			} else {
				assert.Check(t, is.Nil(resp.Status.StatusCode.StatusCode))
			}
			assert.Check(t, !pt.sessionExists(t, session.ID))
			participants, err := pt.Server.storedSessionParticipants(session.ID)
			assert.NilError(t, err)
			assert.Check(t, is.Len(participants, 0))
			assert.Check(t, is.Equal(1, other.requests()))
			assert.Check(t, is.Len(other.errs, 0), "%v", other.errs)
		})
	}
}

// Without a SessionIndex, a SOAP LogoutRequest ends every session of its
// NameID, and the logout is propagated to their participants: here a
// front-channel only one, which cannot be reached without a browser.
func TestSOAPLogoutWithoutSessionIndexEndsEverySession(t *testing.T) {
	pt := newSOAPLogoutServerTest(t)
	session, cookie := pt.login(t, "alice", "alice@example.com")
	pt.cookies[cookie.Name] = cookie
	pt.sso(t, &pt.SP)
	// A second session of alice, used only for sp2.
	otherSession, otherCookie := pt.login(t, "alice", "alice@example.com")
	pt.cookies[otherCookie.Name] = otherCookie
	pt.sso(t, &pt.sp2)
	bob, bobCookie := pt.login(t, "bob", "bob@example.com")
	pt.cookies[bobCookie.Name] = bobCookie

	req, err := pt.SP.MakeLogoutRequest(pt.Server.IDP.LogoutURL.String(), session.NameID)
	assert.NilError(t, err)
	resp := pt.soapLogout(t, req)
	assert.Check(t, is.Equal(saml.StatusSuccess, resp.Status.StatusCode.Value))
	assert.Check(t, resp.Status.StatusCode.StatusCode != nil && resp.Status.StatusCode.StatusCode.Value == saml.StatusPartialLogout)
	assert.Check(t, !pt.sessionExists(t, session.ID))
	assert.Check(t, !pt.sessionExists(t, otherSession.ID))
	assert.Check(t, pt.sessionExists(t, bob.ID))
}

// samlidp accepts and advertises SOAP logout only with Options.SOAPLogout.
func TestSOAPLogoutOption(t *testing.T) {
	test := NewServerTest(t)
	soapBindings := func(s *Server) int {
		n := 0
		for _, endpoint := range s.IDP.Metadata().IDPSSODescriptors[0].SingleLogoutServices {
			if endpoint.Binding == saml.SOAPBinding {
				n++
				assert.Check(t, is.Equal("https://idp.example.com/slo", endpoint.Location))
			}
		}
		return n
	}
	assert.Check(t, is.Equal(0, soapBindings(test.Server)), "off by default")

	s, err := New(Options{
		Certificate: test.Certificate,
		Key:         test.Key,
		Store:       &MemoryStore{},
		URL:         url.URL{Scheme: "https", Host: "idp.example.com"},
		SOAPLogout:  true,
	})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(1, soapBindings(s)))
}

// By default, a SOAP LogoutRequest is refused and ends no session.
func TestSOAPLogoutRefusedByDefault(t *testing.T) {
	pt := newPropagationServerTest(t)
	session, cookie := pt.login(t, "alice", "alice@example.com")
	pt.cookies[cookie.Name] = cookie
	pt.sso(t, &pt.SP)

	req, err := pt.SP.MakeLogoutRequest(pt.Server.IDP.LogoutURL.String(), session.NameID, saml.WithSessionIndex(session.Index))
	assert.NilError(t, err)
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/slo", bytes.NewReader(soapEnvelopeOf(req.Element())))
	r.Header.Set("Content-Type", "text/xml")
	w := httptest.NewRecorder()
	pt.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, pt.sessionExists(t, session.ID))
}
