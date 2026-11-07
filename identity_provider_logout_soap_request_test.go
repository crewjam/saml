package saml

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// soapLogoutTest is a propagationTest whose IdP accepts LogoutRequests over
// SOAP, with a front-channel SP, initiator, that sends one.
type soapLogoutTest struct {
	*propagationTest
	initiator *ServiceProvider
}

func newSOAPLogoutTest(t *testing.T) *soapLogoutTest {
	pt := newPropagationTest(t)
	pt.idp.LogoutBindings = append(pt.idp.LogoutBindings, SOAPBinding)
	return &soapLogoutTest{propagationTest: pt, initiator: pt.sps[0]}
}

// logoutRequest returns a LogoutRequest from sp for the test session,
// signed by sp unless sp has no SignatureMethod. modify, if set, changes it
// before it is signed.
func (st *soapLogoutTest) logoutRequest(t *testing.T, sp *ServiceProvider, modify func(*LogoutRequest)) *LogoutRequest {
	t.Helper()
	req := sp.makeUnsignedLogoutRequest(st.idp.LogoutURL.String(), "alice@example.com", WithSessionIndex("idp-session-index"))
	if modify != nil {
		modify(req)
	}
	if sp.SignatureMethod != "" {
		assert.NilError(t, sp.SignLogoutRequest(req))
	}
	return req
}

// soapEnvelopeBytes wraps the LogoutRequest req in a SOAP 1.1 envelope, as
// a service provider sends it with the SOAP binding (saml-bindings §3.2).
func soapEnvelopeBytes(t *testing.T, req *LogoutRequest) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	inner, err := doc.WriteToString()
	assert.NilError(t, err)
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<SOAP-ENV:Body>` + inner + `</SOAP-ENV:Body></SOAP-ENV:Envelope>`)
}

// postSOAP sends body to the IdP's ServeSLO as a SOAP message, without any
// browser cookie.
func (st *soapLogoutTest) postSOAP(body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, st.idp.LogoutURL.String(), bytes.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.Header.Set("SOAPAction", "http://www.oasis-open.org/committees/security")
	w := httptest.NewRecorder()
	st.idp.ServeSLO(w, r)
	return w
}

// soapLogoutResponse checks that w holds a LogoutResponse in a SOAP
// envelope, signed by the IdP, as sp reads it, and returns it.
func soapLogoutResponse(t *testing.T, sp *ServiceProvider, w *httptest.ResponseRecorder) *LogoutResponse {
	t.Helper()
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Check(t, is.Equal(soapContentType, w.Header().Get("Content-Type")))
	el, err := soapBodyElement(w.Body.Bytes(), "LogoutResponse")
	assert.NilError(t, err)
	signed, err := sp.validatedElement(el)
	assert.NilError(t, err, "the response is signed by the IdP")
	var resp LogoutResponse
	assert.NilError(t, unmarshalElement(signed, &resp))
	assert.Check(t, is.Equal(sp.IDPMetadata.EntityID, resp.Issuer.Value))
	assert.Check(t, is.Equal("", resp.Destination))
	return &resp
}

// checkStatus checks the top-level and second-level status of resp.
func checkStatus(t *testing.T, resp *LogoutResponse, status, second string) {
	t.Helper()
	assert.Check(t, is.Equal(status, resp.Status.StatusCode.Value))
	if second == "" {
		assert.Check(t, is.Nil(resp.Status.StatusCode.StatusCode))
		return
	}
	if assert.Check(t, resp.Status.StatusCode.StatusCode != nil) {
		assert.Check(t, is.Equal(second, resp.Status.StatusCode.StatusCode.Value))
	}
}

// checkSOAPFault checks that w is a SOAP Client fault, with no
// LogoutResponse.
func checkSOAPFault(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	assert.Check(t, is.Equal(soapContentType, w.Header().Get("Content-Type")))
	assert.Check(t, is.Contains(w.Body.String(), "<faultcode>soapenv:Client</faultcode>"))
	assert.Check(t, !strings.Contains(w.Body.String(), "LogoutResponse"))
}

// An SP logs the user out over SOAP: the session is ended without a
// cookie, the other participants are logged out over SOAP, and the SP gets
// a signed Success LogoutResponse at once.
func TestIDPServeSLOOverSOAP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*LogoutRequest)
	}{
		{"with SessionIndex", nil},
		{"without SessionIndex", func(req *LogoutRequest) { req.setSessionIndexes(nil) }},
		{"without Destination", func(req *LogoutRequest) { req.Destination = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newSOAPLogoutTest(t)
			soapOnly := st.addSOAPParticipant(t)
			soapAndRedirect := st.addSOAPParticipant(t, HTTPRedirectBinding)
			st.login(t, st.initiator, soapOnly.sp, soapAndRedirect.sp)

			req := st.logoutRequest(t, st.initiator, tc.modify)
			w := st.postSOAP(soapEnvelopeBytes(t, req))

			resp := soapLogoutResponse(t, st.initiator, w)
			assert.Check(t, is.Equal(req.ID, resp.InResponseTo))
			checkStatus(t, resp, StatusSuccess, "")
			assert.Check(t, st.sessions.ended)
			for _, p := range []*soapParticipant{soapOnly, soapAndRedirect} {
				reqs := p.requests()
				if assert.Check(t, is.Len(reqs, 1)) {
					assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value))
					assert.Check(t, is.Equal("idp-session-index", reqs[0].SessionIndex.Value))
				}
				p.checkNoErrors(t)
			}
			assert.Check(t, is.Len(w.Result().Cookies(), 0), "no logout state cookie")
		})
	}
}

// The principal may be identified by an EncryptedID.
func TestIDPServeSLOOverSOAPEncryptedID(t *testing.T) {
	st := newSOAPLogoutTest(t)
	st.login(t, st.initiator)
	req := st.logoutRequest(t, st.initiator, func(req *LogoutRequest) {
		assert.NilError(t, st.initiator.EncryptLogoutRequestNameID(req))
	})
	assert.Assert(t, req.EncryptedID != nil && req.NameID == nil)

	resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, req)))
	checkStatus(t, resp, StatusSuccess, "")
	assert.Check(t, st.sessions.ended)
}

// Participants that cannot be logged out over SOAP make the logout partial:
// one that only offers front-channel logout, which cannot be reached
// without a browser, and one whose SOAP logout fails.
func TestIDPServeSLOOverSOAPPartialLogout(t *testing.T) {
	t.Run("front-channel only participant", func(t *testing.T) {
		st := newSOAPLogoutTest(t)
		soapSP := st.addSOAPParticipant(t)
		frontChannel := st.sps[1]
		st.login(t, st.initiator, soapSP.sp, frontChannel)

		req := st.logoutRequest(t, st.initiator, nil)
		w := st.postSOAP(soapEnvelopeBytes(t, req))
		resp := soapLogoutResponse(t, st.initiator, w)
		checkStatus(t, resp, StatusSuccess, StatusPartialLogout)
		assert.Check(t, st.sessions.ended)
		assert.Check(t, is.Len(soapSP.requests(), 1), "the SOAP participant is still logged out")
		assert.Check(t, is.Len(st.received[frontChannel.MetadataURL.String()], 0))
		assert.Check(t, is.Len(w.Result().Cookies(), 0))
	})
	t.Run("participant answers Responder", func(t *testing.T) {
		st := newSOAPLogoutTest(t)
		soapSP := st.addSOAPParticipant(t)
		soapSP.respond = func(sp *ServiceProvider, req *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, req.ID, StatusResponder, nil)
		}
		st.login(t, st.initiator, soapSP.sp)

		resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))))
		checkStatus(t, resp, StatusSuccess, StatusPartialLogout)
	})
	t.Run("participants cannot be listed", func(t *testing.T) {
		st := newSOAPLogoutTest(t)
		st.login(t, st.initiator)
		st.sessions.listErr = errors.New("store unavailable")

		resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))))
		checkStatus(t, resp, StatusSuccess, StatusPartialLogout)
		assert.Check(t, st.sessions.ended)
	})
}

// failingInvalidator is a trackingSessionProvider that cannot end sessions.
type failingInvalidator struct {
	*trackingSessionProvider
}

func (failingInvalidator) InvalidateSession(http.ResponseWriter, *http.Request, *IdpLogoutRequest) error {
	return errors.New("store unavailable")
}

// If the session cannot be ended, the SP gets Responder and the logout is
// not propagated.
func TestIDPServeSLOOverSOAPSessionNotEnded(t *testing.T) {
	st := newSOAPLogoutTest(t)
	soapSP := st.addSOAPParticipant(t)
	st.login(t, st.initiator, soapSP.sp)
	st.idp.SessionProvider = failingInvalidator{st.sessions}

	resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))))
	checkStatus(t, resp, StatusResponder, "")
	assert.Check(t, is.Len(soapSP.requests(), 0))
}

// A request that is signed by the SP but invalid is answered with a signed
// Requester LogoutResponse, and ends no session.
func TestIDPServeSLOOverSOAPRequester(t *testing.T) {
	t.Run("replayed", func(t *testing.T) {
		st := newSOAPLogoutTest(t)
		st.idp.ReplayCache = memoryReplayCache{}
		st.login(t, st.initiator)
		body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))

		checkStatus(t, soapLogoutResponse(t, st.initiator, st.postSOAP(body)), StatusSuccess, "")
		st.sessions.ended = false
		resp := soapLogoutResponse(t, st.initiator, st.postSOAP(body))
		checkStatus(t, resp, StatusRequester, "")
		assert.Check(t, !st.sessions.ended)
	})
	for _, tc := range []struct {
		name   string
		modify func(*LogoutRequest)
	}{
		{"expired", func(req *LogoutRequest) { req.IssueInstant = TimeNow().Add(-MaxIssueDelay - time.Second) }},
		{"wrong destination", func(req *LogoutRequest) { req.Destination = "https://other-idp.example.com/slo" }},
		{"no NameID", func(req *LogoutRequest) { req.NameID = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newSOAPLogoutTest(t)
			soapSP := st.addSOAPParticipant(t)
			st.login(t, st.initiator, soapSP.sp)
			req := st.logoutRequest(t, st.initiator, tc.modify)

			resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, req)))
			assert.Check(t, is.Equal(req.ID, resp.InResponseTo))
			checkStatus(t, resp, StatusRequester, "")
			assert.Check(t, !st.sessions.ended)
			assert.Check(t, is.Len(soapSP.requests(), 0))
		})
	}
}

// refusedReasons is what the IdP logs for each case of
// TestIDPServeSLOOverSOAPRefused, so that each fails for the reason tested.
var refusedReasons = map[string]string{
	"unsigned":                                  "signature element not present",
	"signed by a key not in the SP metadata":    "cannot verify signature",
	"issuer is another SP than the signer":      "cannot verify signature",
	"unknown issuer":                            "unknown service provider",
	"tampered":                                  "cannot verify signature",
	"SHA-1 signature with RejectSHA1Signatures": "SHA-1",
	"oversized":                                 "body is larger than 8192 bytes",
	"not XML":                                   "failed to parse SOAP logout request",
	"bare LogoutRequest without an envelope":    "expected a SOAP Envelope",
	"SOAP 1.2 envelope":                         "expected a SOAP Envelope",
	"two elements in the Body":                  "expected exactly one element in the SOAP Body",
	"Body holds another SAML request":           "LogoutRequest",
	"mandatory SOAP header":                     "mandatory SOAP header",
}

// A SOAP message that cannot be read or authenticated is answered with a
// SOAP fault, and ends no session.
func TestIDPServeSLOOverSOAPRefused(t *testing.T) {
	otherKey := mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
	otherCert := mustParseCertificate(golden.Get(t, "sp_cert.pem"))

	for _, tc := range []struct {
		name  string
		body  func(t *testing.T, st *soapLogoutTest) []byte
		setup func(t *testing.T, st *soapLogoutTest)
	}{
		{"unsigned", func(t *testing.T, st *soapLogoutTest) []byte {
			unsigned := *st.initiator
			unsigned.SignatureMethod = ""
			return soapEnvelopeBytes(t, st.logoutRequest(t, &unsigned, nil))
		}, nil},
		{"signed by a key not in the SP metadata", func(t *testing.T, st *soapLogoutTest) []byte {
			other := *st.initiator
			other.Key = otherKey
			other.Certificate = otherCert
			return soapEnvelopeBytes(t, st.logoutRequest(t, &other, nil))
		}, nil},
		{"issuer is another SP than the signer", func(t *testing.T, st *soapLogoutTest) []byte {
			// The request names the initiator as issuer but is signed by
			// another known SP with its own key.
			other := *st.initiator
			other.Key = otherKey
			other.Certificate = otherCert
			other.MetadataURL = mustParseURL("https://other-sp.example.com/metadata")
			st.sps = append(st.sps, &other)
			return soapEnvelopeBytes(t, st.logoutRequest(t, &other, func(req *LogoutRequest) {
				req.Issuer.Value = st.initiator.MetadataURL.String()
			}))
		}, nil},
		{"unknown issuer", func(t *testing.T, st *soapLogoutTest) []byte {
			return soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, func(req *LogoutRequest) {
				req.Issuer.Value = "https://unknown.example.com/metadata"
			}))
		}, nil},
		{"tampered", func(t *testing.T, st *soapLogoutTest) []byte {
			body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, func(req *LogoutRequest) {
				req.NameID.Value = "mallory@example.com"
			}))
			return bytes.Replace(body, []byte("mallory@example.com"), []byte("alice@example.com"), 1)
		}, nil},
		{"SHA-1 signature with RejectSHA1Signatures", func(t *testing.T, st *soapLogoutTest) []byte {
			sha1SP := *st.initiator
			sha1SP.SignatureMethod = dsig.RSASHA1SignatureMethod
			return soapEnvelopeBytes(t, st.logoutRequest(t, &sha1SP, nil))
		}, func(_ *testing.T, st *soapLogoutTest) { st.idp.RejectSHA1Signatures = true }},
		{"oversized", func(t *testing.T, st *soapLogoutTest) []byte {
			body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))
			return append(body, bytes.Repeat([]byte(" "), 8192)...)
		}, func(t *testing.T, _ *soapLogoutTest) {
			old := MaxSOAPLogoutMessageSize
			t.Cleanup(func() { MaxSOAPLogoutMessageSize = old })
			MaxSOAPLogoutMessageSize = 8192
		}},
		{"not XML", func(*testing.T, *soapLogoutTest) []byte {
			return []byte("SAMLRequest=abc")
		}, nil},
		{"bare LogoutRequest without an envelope", func(t *testing.T, st *soapLogoutTest) []byte {
			buf, err := elementToBytes(st.logoutRequest(t, st.initiator, nil).Element())
			assert.NilError(t, err)
			return buf
		}, nil},
		{"SOAP 1.2 envelope", func(t *testing.T, st *soapLogoutTest) []byte {
			body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))
			return bytes.Replace(body, []byte("http://schemas.xmlsoap.org/soap/envelope/"), []byte("http://www.w3.org/2003/05/soap-envelope"), 1)
		}, nil},
		{"two elements in the Body", func(t *testing.T, st *soapLogoutTest) []byte {
			body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))
			return bytes.Replace(body, []byte("</SOAP-ENV:Body>"), []byte("<extra/></SOAP-ENV:Body>"), 1)
		}, nil},
		{"Body holds another SAML request", func(t *testing.T, st *soapLogoutTest) []byte {
			body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))
			return bytes.ReplaceAll(body, []byte("samlp:LogoutRequest"), []byte("samlp:ManageNameIDRequest"))
		}, nil},
		{"mandatory SOAP header", func(t *testing.T, st *soapLogoutTest) []byte {
			body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))
			return bytes.Replace(body, []byte("<SOAP-ENV:Body>"),
				[]byte(`<SOAP-ENV:Header><x:Unknown xmlns:x="urn:x" SOAP-ENV:mustUnderstand="1"/></SOAP-ENV:Header><SOAP-ENV:Body>`), 1)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newSOAPLogoutTest(t)
			soapSP := st.addSOAPParticipant(t)
			st.login(t, st.initiator, soapSP.sp)
			if tc.setup != nil {
				tc.setup(t, st)
			}

			var logged bytes.Buffer
			st.idp.Logger = log.New(&logged, "", 0)
			w := st.postSOAP(tc.body(t, st))
			checkSOAPFault(t, w)
			assert.Check(t, is.Contains(logged.String(), refusedReasons[tc.name]))
			assert.Check(t, !st.sessions.ended)
			assert.Check(t, is.Len(soapSP.requests(), 0))
		})
	}
}

// Without the policy, a SHA-1 signature is accepted, as for the other
// bindings; and a SOAP header that need not be understood is ignored.
func TestIDPServeSLOOverSOAPAccepts(t *testing.T) {
	t.Run("SHA-1 signature", func(t *testing.T) {
		st := newSOAPLogoutTest(t)
		st.login(t, st.initiator)
		sha1SP := *st.initiator
		sha1SP.SignatureMethod = dsig.RSASHA1SignatureMethod
		resp := soapLogoutResponse(t, st.initiator, st.postSOAP(soapEnvelopeBytes(t, st.logoutRequest(t, &sha1SP, nil))))
		checkStatus(t, resp, StatusSuccess, "")
	})
	t.Run("optional SOAP header", func(t *testing.T) {
		st := newSOAPLogoutTest(t)
		st.login(t, st.initiator)
		body := soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil))
		body = bytes.Replace(body, []byte("<SOAP-ENV:Body>"),
			[]byte(`<SOAP-ENV:Header><x:Unknown xmlns:x="urn:x"/></SOAP-ENV:Header><SOAP-ENV:Body>`), 1)
		resp := soapLogoutResponse(t, st.initiator, st.postSOAP(body))
		checkStatus(t, resp, StatusSuccess, "")
	})
}

// Unless LogoutBindings includes SOAPBinding, a SOAP LogoutRequest is
// refused as before, and the metadata advertises no SOAP endpoint.
func TestIDPServeSLOOverSOAPNotEnabled(t *testing.T) {
	st := newSOAPLogoutTest(t)
	st.idp.LogoutBindings = []string{HTTPRedirectBinding, HTTPPostBinding}
	st.login(t, st.initiator)

	w := st.postSOAP(soapEnvelopeBytes(t, st.logoutRequest(t, st.initiator, nil)))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, !st.sessions.ended)
	for _, endpoint := range st.idp.Metadata().IDPSSODescriptors[0].SingleLogoutServices {
		assert.Check(t, endpoint.Binding != SOAPBinding)
	}
}

func TestIDPMetadataAdvertisesSOAPLogout(t *testing.T) {
	st := newSOAPLogoutTest(t)
	endpoints := st.idp.Metadata().IDPSSODescriptors[0].SingleLogoutServices
	bindings := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		bindings = append(bindings, endpoint.Binding)
		assert.Check(t, is.Equal(st.idp.LogoutURL.String(), endpoint.Location))
	}
	assert.Check(t, is.DeepEqual([]string{HTTPRedirectBinding, HTTPPostBinding, SOAPBinding}, bindings))
}

// Adding SOAP leaves the front-channel bindings working.
func TestIDPServeSLOFrontChannelWithSOAPEnabled(t *testing.T) {
	st := newSOAPLogoutTest(t)
	st.login(t, st.initiator)
	req := st.logoutRequest(t, st.initiator, nil)
	u, err := st.initiator.RedirectLogoutRequestURL(req, "relay")
	assert.NilError(t, err)
	w := st.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Check(t, is.Equal(http.StatusFound, w.Code))
	assert.Check(t, st.sessions.ended)
}
