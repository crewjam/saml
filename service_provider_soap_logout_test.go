package saml

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const soapLogoutIDPLocation = "https://idp.example.com/slo/soap"

// soapLogoutIDP returns this repository's IdentityProvider with the IdP key
// and certificate the SP of e trusts.
func (e *spcovEnv) soapLogoutIDP() *IdentityProvider {
	return &IdentityProvider{
		Key:         e.idpKey,
		Certificate: e.idpCert,
		MetadataURL: mustParseURL(spcovIDPEntityID),
	}
}

// idpSignedSOAPLogoutRequest returns req signed by the IdentityProvider and
// wrapped in a SOAP envelope, as a spec-conformant IdP sends it with the
// SOAP binding.
func (e *spcovEnv) idpSignedSOAPLogoutRequest(t *testing.T, req *LogoutRequest) []byte {
	t.Helper()
	signingContext, err := e.soapLogoutIDP().signingContext()
	assert.NilError(t, err)
	signed, err := signingContext.SignEnveloped(req.Element())
	assert.NilError(t, err)
	return spcovSerialize(t, soapEnvelope(signed))
}

func soapPost(target string, body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	r.Header.Set("SOAPAction", "http://www.oasis-open.org/committees/security")
	return r
}

// soapLogoutSP serves the SLO URL of e's SP: it answers a valid SOAP
// LogoutRequest with a signed Success LogoutResponse and anything else with
// a SOAP Fault, and records the requests it accepts.
func (e *spcovEnv) soapLogoutSP(t *testing.T, accepted *[]*LogoutRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := e.sp.ValidateSOAPLogoutRequest(r)
		if err != nil {
			_ = WriteSOAPFault(w, "refused")
			return
		}
		*accepted = append(*accepted, req)
		resp, err := e.sp.MakeSOAPLogoutResponse(req.ID, Status{StatusCode: StatusCode{Value: StatusSuccess}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = WriteSOAPLogoutResponse(w, resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The SP accepts a LogoutRequest that this repository's IdentityProvider
// signed, sent in a SOAP envelope over HTTP, and answers it with a SOAP
// envelope holding a LogoutResponse signed by the SP.
func TestSOAPLogoutRequestEndToEnd(t *testing.T) {
	e := spcovSetup(t)
	var accepted []*LogoutRequest
	srv := e.soapLogoutSP(t, &accepted)

	req := e.logoutRequest()
	req.Destination = "" // optional with the SOAP binding
	req.setSessionIndexes([]SessionIndex{{Value: "index-1"}, {Value: "index-2"}})
	body := e.idpSignedSOAPLogoutRequest(t, req)

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	assert.NilError(t, err)
	httpReq.Header.Set("Content-Type", "text/xml; charset=utf-8")
	httpResp, err := srv.Client().Do(httpReq)
	assert.NilError(t, err)
	defer func() { assert.Check(t, httpResp.Body.Close()) }()
	respBody, err := io.ReadAll(httpResp.Body)
	assert.NilError(t, err)

	assert.Check(t, is.Equal(httpResp.StatusCode, http.StatusOK))
	assert.Check(t, is.Equal(httpResp.Header.Get("Content-Type"), "text/xml; charset=utf-8"))
	assert.Assert(t, is.Len(accepted, 1))
	assert.Check(t, is.Equal(accepted[0].ID, req.ID))
	assert.Check(t, is.Equal(accepted[0].NameID.Value, "alice@example.com"))
	assert.Check(t, is.DeepEqual(accepted[0].AllSessionIndexes(), []SessionIndex{{Value: "index-1"}, {Value: "index-2"}}))

	// What the IdP gets back: a SOAP envelope with a LogoutResponse to its
	// request, signed by the SP.
	responseEl, err := soapBodyElement(respBody, "LogoutResponse")
	assert.NilError(t, err)
	verifySignedBySP(t, e, responseEl)
	var resp LogoutResponse
	assert.NilError(t, unmarshalElement(responseEl, &resp))
	assert.Check(t, is.Equal(resp.InResponseTo, req.ID))
	assert.Check(t, is.Equal(resp.Status.StatusCode.Value, StatusSuccess))
	assert.Check(t, is.Equal(resp.Issuer.Value, e.sp.MetadataURL.String()))
	assert.Check(t, is.Equal(resp.Destination, ""))
}

func verifySignedBySP(t *testing.T, e *spcovEnv, el *etree.Element) {
	t.Helper()
	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{e.sp.Certificate}})
	validationContext.Clock = dsig.NewFakeClockAt(spcovNow)
	_, err := validationContext.Validate(el)
	assert.NilError(t, err)
}

func TestValidateSOAPLogoutRequestAccepts(t *testing.T) {
	t.Run("Destination is SloURL", func(t *testing.T) {
		e := spcovSetup(t)
		req, err := e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), e.idpSignedSOAPLogoutRequest(t, e.logoutRequest())))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(req.ID, e.logoutRequest().ID))
	})
	t.Run("EncryptedID", func(t *testing.T) {
		e := spcovSetup(t)
		req := e.logoutRequest()
		req.EncryptedID = encryptedNameID(t, req.NameID.Element(), e.sp.Certificate)
		req.NameID = nil
		got, err := e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), e.idpSignedSOAPLogoutRequest(t, req)))
		assert.NilError(t, err)
		assert.Assert(t, got.NameID != nil)
		assert.Check(t, is.Equal(got.NameID.Value, "alice@example.com"))
	})
	t.Run("SHA-1 without the policy", func(t *testing.T) {
		e := spcovSetup(t)
		signed := signWithMethod(t, e.idpKey, e.idpCert, e.logoutRequest().Element(), dsig.RSASHA1SignatureMethod)
		_, err := e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), spcovSerialize(t, soapEnvelope(signed))))
		assert.NilError(t, err)
	})
}

func TestValidateSOAPLogoutRequestRejects(t *testing.T) {
	type testCase struct {
		name    string
		request func(t *testing.T, e *spcovEnv) *http.Request
		want    error
		wantMsg string
	}
	signedBody := func(t *testing.T, e *spcovEnv, mutate func(*LogoutRequest)) []byte {
		req := e.logoutRequest()
		if mutate != nil {
			mutate(req)
		}
		return e.idpSignedSOAPLogoutRequest(t, req)
	}
	post := func(mutate func(*LogoutRequest)) func(t *testing.T, e *spcovEnv) *http.Request {
		return func(t *testing.T, e *spcovEnv) *http.Request {
			return soapPost(e.sp.SloURL.String(), signedBody(t, e, mutate))
		}
	}
	for _, tc := range []testCase{
		{"unsigned", func(t *testing.T, e *spcovEnv) *http.Request {
			return soapPost(e.sp.SloURL.String(), spcovSerialize(t, soapEnvelope(e.logoutRequest().Element())))
		}, ErrInvalidSignature, "is not signed"},
		{"signed by someone else", func(t *testing.T, e *spcovEnv) *http.Request {
			key, cert := aqKeyPair(t)
			signed := spcovSign(t, key, cert, e.logoutRequest().Element())
			return soapPost(e.sp.SloURL.String(), spcovSerialize(t, soapEnvelope(signed)))
		}, ErrInvalidSignature, ""},
		{"wrong issuer", post(func(req *LogoutRequest) { req.Issuer.Value = "https://evil.example.com/" }), ErrIssuerMismatch, ""},
		{"no issuer", post(func(req *LogoutRequest) { req.Issuer = nil }), ErrIssuerMismatch, ""},
		{"wrong Destination", post(func(req *LogoutRequest) { req.Destination = "https://other.example.com/slo" }), ErrDestinationMismatch, ""},
		{"expired", post(func(req *LogoutRequest) { req.IssueInstant = spcovNow.Add(-time.Hour) }), ErrExpired, ""},
		{"issued in the future", post(func(req *LogoutRequest) { req.IssueInstant = spcovNow.Add(time.Hour) }), ErrNotYetValid, ""},
		{"not a SOAP envelope", func(t *testing.T, e *spcovEnv) *http.Request {
			return soapPost(e.sp.SloURL.String(), spcovSerialize(t, e.idpSign(t, e.logoutRequest().Element())))
		}, ErrMalformedMessage, "expected a SOAP Envelope"},
		{"a LogoutResponse", func(t *testing.T, e *spcovEnv) *http.Request {
			return soapPost(e.sp.SloURL.String(), spcovSerialize(t, soapEnvelope(e.idpSign(t, e.logoutResponse().Element()))))
		}, ErrMissingElement, ""},
		{"form content type", func(t *testing.T, e *spcovEnv) *http.Request {
			r := soapPost(e.sp.SloURL.String(), signedBody(t, e, nil))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r
		}, ErrMalformedMessage, "not a SOAP message"},
		{"SOAP 1.2 content type", func(t *testing.T, e *spcovEnv) *http.Request {
			r := soapPost(e.sp.SloURL.String(), signedBody(t, e, nil))
			r.Header.Set("Content-Type", "application/soap+xml")
			return r
		}, ErrMalformedMessage, "not a SOAP message"},
		{"GET", func(t *testing.T, e *spcovEnv) *http.Request {
			r := httptest.NewRequest(http.MethodGet, e.sp.SloURL.String(), nil)
			r.Header.Set("Content-Type", "text/xml")
			return r
		}, ErrMalformedMessage, "not a SOAP message"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			req, err := e.sp.ValidateSOAPLogoutRequest(tc.request(t, e))
			assert.Check(t, is.Nil(req))
			privateErr := spcovPrivateErr(t, err)
			assert.Check(t, is.ErrorIs(privateErr, tc.want))
			if tc.wantMsg != "" {
				assert.Check(t, is.ErrorContains(privateErr, tc.wantMsg))
			}
		})
	}
}

func TestValidateSOAPLogoutRequestRefusesReplay(t *testing.T) {
	e := spcovSetup(t)
	cache := memoryReplayCache{}
	e.sp.ReplayCache = cache
	body := e.idpSignedSOAPLogoutRequest(t, e.logoutRequest())

	_, err := e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), body))
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(memoryReplayCache{logoutRequestReplayKeyPrefix + e.logoutRequest().ID: spcovNow.Add(MaxIssueDelay)}, cache))

	_, err = e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), body))
	assert.Check(t, is.ErrorIs(spcovPrivateErr(t, err), ErrAssertionReplayed))
}

func TestValidateSOAPLogoutRequestRejectsSHA1(t *testing.T) {
	e := spcovSetup(t)
	e.sp.RejectSHA1Signatures = true
	signed := signWithMethod(t, e.idpKey, e.idpCert, e.logoutRequest().Element(), dsig.RSASHA1SignatureMethod)
	_, err := e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), spcovSerialize(t, soapEnvelope(signed))))
	privateErr := spcovPrivateErr(t, err)
	assert.Check(t, is.ErrorIs(privateErr, ErrUnsupported))
	assert.Check(t, is.ErrorIs(privateErr, ErrInvalidSignature))
}

func TestValidateSOAPLogoutRequestBodyLimit(t *testing.T) {
	e := spcovSetup(t)
	body := e.idpSignedSOAPLogoutRequest(t, e.logoutRequest())
	old := MaxSOAPLogoutMessageSize
	t.Cleanup(func() { MaxSOAPLogoutMessageSize = old })

	MaxSOAPLogoutMessageSize = int64(len(body) - 1)
	_, err := e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), body))
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "body is larger than"))

	MaxSOAPLogoutMessageSize = int64(len(body))
	_, err = e.sp.ValidateSOAPLogoutRequest(soapPost(e.sp.SloURL.String(), body))
	assert.NilError(t, err)
}

func TestMakeSOAPLogoutResponse(t *testing.T) {
	e := spcovSetup(t)
	resp, err := e.sp.MakeSOAPLogoutResponse("id-request", Status{
		StatusCode: StatusCode{Value: StatusResponder},
	})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(resp.InResponseTo, "id-request"))
	assert.Check(t, is.Equal(resp.Destination, ""))
	assert.Check(t, is.Equal(resp.Status.StatusCode.Value, StatusResponder))
	assert.Assert(t, resp.Signature != nil)
	verifySignedBySP(t, e, resp.Element())

	e.sp.Key = nil
	resp, err = e.sp.MakeSOAPLogoutResponse("id-request", Status{StatusCode: StatusCode{Value: StatusSuccess}})
	assert.NilError(t, err)
	assert.Check(t, resp.Signature == nil)
}

func TestWriteSOAPFault(t *testing.T) {
	w := httptest.NewRecorder()
	assert.NilError(t, WriteSOAPFault(w, "refused"))
	assert.Check(t, is.Equal(w.Code, http.StatusInternalServerError))
	assert.Check(t, is.Equal(w.Header().Get("Content-Type"), "text/xml; charset=utf-8"))
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(w.Body.Bytes()))
	fault := doc.FindElement("/Envelope/Body/Fault")
	assert.Assert(t, fault != nil)
	assert.Check(t, is.Equal(fault.NamespaceURI(), soapEnvelopeNamespace))
	assert.Check(t, is.Equal(fault.FindElement("faultcode").Text(), "soapenv:Client"))
	assert.Check(t, is.Equal(fault.FindElement("faultstring").Text(), "refused"))
}

func TestIsSOAPRequest(t *testing.T) {
	for _, tc := range []struct {
		method, contentType string
		want                bool
	}{
		{http.MethodPost, "text/xml", true},
		{http.MethodPost, "text/xml; charset=utf-8", true},
		{http.MethodPost, "TEXT/XML", true},
		{http.MethodPost, "application/x-www-form-urlencoded", false},
		{http.MethodPost, "application/soap+xml", false},
		{http.MethodPost, "", false},
		{http.MethodGet, "text/xml", false},
	} {
		r := httptest.NewRequest(tc.method, "https://sp.example.com/saml/slo", strings.NewReader(""))
		r.Header.Set("Content-Type", tc.contentType)
		assert.Check(t, is.Equal(IsSOAPRequest(r), tc.want), "%s %q", tc.method, tc.contentType)
	}
}

func TestMetadataSOAPSingleLogoutService(t *testing.T) {
	e := spcovSetup(t)
	e.sp.LogoutBindings = []string{HTTPPostBinding, SOAPBinding}
	slo := e.sp.Metadata().SPSSODescriptors[0].SingleLogoutServices
	assert.Check(t, is.DeepEqual(slo, []Endpoint{
		{Binding: HTTPPostBinding, Location: e.sp.SloURL.String(), ResponseLocation: e.sp.SloURL.String()},
		{Binding: SOAPBinding, Location: e.sp.SloURL.String()},
	}))
}

// soapLogoutIDPServer is a fake IdP SOAP SingleLogoutService. It records
// each LogoutRequest it receives and answers with respond.
type soapLogoutIDPServer struct {
	*httptest.Server
	requests []*LogoutRequest
	bodies   [][]byte
	headers  []http.Header
	status   int
	respond  func(req *LogoutRequest) []byte
}

func newSOAPLogoutIDPServer(t *testing.T, e *spcovEnv) *soapLogoutIDPServer {
	t.Helper()
	s := &soapLogoutIDPServer{status: http.StatusOK}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.bodies = append(s.bodies, body)
		s.headers = append(s.headers, r.Header.Clone())
		var req LogoutRequest
		if el, err := soapBodyElement(body, "LogoutRequest"); err == nil {
			_ = unmarshalElement(el, &req)
		}
		s.requests = append(s.requests, &req)
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(s.status)
		_, _ = w.Write(s.respond(&req))
	}))
	t.Cleanup(s.Close)
	e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = append(
		e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices,
		Endpoint{Binding: SOAPBinding, Location: s.URL})
	e.sp.HTTPClient = s.Client()
	return s
}

// idpSOAPLogoutResponse returns a SOAP envelope with a LogoutResponse to req
// from the IdP, signed by it if sign is set, after mutate.
func (e *spcovEnv) idpSOAPLogoutResponse(t *testing.T, req *LogoutRequest, sign bool, mutate func(*LogoutResponse)) []byte {
	t.Helper()
	resp := &LogoutResponse{
		ID:           "id-idp-logout-response",
		InResponseTo: req.ID,
		Version:      "2.0",
		IssueInstant: spcovNow,
		Issuer:       &Issuer{Value: spcovIDPEntityID},
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
	}
	if mutate != nil {
		mutate(resp)
	}
	el := resp.Element()
	if sign {
		el = e.idpSign(t, el)
	}
	return spcovSerialize(t, soapEnvelope(el))
}

func TestSendSOAPLogoutRequest(t *testing.T) {
	e := spcovSetup(t)
	s := newSOAPLogoutIDPServer(t, e)
	s.respond = func(req *LogoutRequest) []byte { return e.idpSOAPLogoutResponse(t, req, true, nil) }

	nameID := NameID{Format: string(PersistentNameIDFormat), NameQualifier: spcovIDPEntityID, Value: "alice"}
	req, err := e.sp.MakeSOAPLogoutRequest(nameID, WithSessionIndexes("index-1", "index-2"))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(req.Destination, s.URL))
	assert.Check(t, req.Signature != nil)

	resp, err := e.sp.SendSOAPLogoutRequest(context.Background(), req)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(resp.InResponseTo, req.ID))

	// What the IdP received: the SP-signed LogoutRequest in a SOAP envelope,
	// with the SOAP binding's headers and the full NameID.
	assert.Assert(t, is.Len(s.requests, 1))
	assert.Check(t, is.Equal(s.headers[0].Get("Content-Type"), "text/xml; charset=utf-8"))
	assert.Check(t, is.Equal(s.headers[0].Get("SOAPAction"), "http://www.oasis-open.org/committees/security"))
	assert.Check(t, is.DeepEqual(*s.requests[0].NameID, nameID))
	assert.Check(t, is.DeepEqual(s.requests[0].AllSessionIndexes(), []SessionIndex{{Value: "index-1"}, {Value: "index-2"}}))
	requestEl, err := soapBodyElement(s.bodies[0], "LogoutRequest")
	assert.NilError(t, err)
	verifySignedBySP(t, e, requestEl)
}

func TestSendSOAPLogoutRequestPartialLogout(t *testing.T) {
	e := spcovSetup(t)
	s := newSOAPLogoutIDPServer(t, e)
	s.respond = func(req *LogoutRequest) []byte {
		return e.idpSOAPLogoutResponse(t, req, true, func(resp *LogoutResponse) {
			resp.Status.StatusCode.StatusCode = &StatusCode{Value: StatusPartialLogout}
		})
	}
	req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
	assert.NilError(t, err)
	resp, err := e.sp.SendSOAPLogoutRequest(context.Background(), req)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(resp.Status.StatusCode.StatusCode.Value, StatusPartialLogout))
}

func TestSendSOAPLogoutRequestRejects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte
		want    error
		wantMsg string
	}{
		{"unsigned", func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte {
			return e.idpSOAPLogoutResponse(t, req, false, nil)
		}, ErrInvalidSignature, "is not signed"},
		{"signed by someone else", func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte {
			resp := e.idpSOAPLogoutResponse(t, req, false, nil)
			el, err := soapBodyElement(resp, "LogoutResponse")
			assert.NilError(t, err)
			key, cert := aqKeyPair(t)
			return spcovSerialize(t, soapEnvelope(spcovSign(t, key, cert, el.Copy())))
		}, ErrInvalidSignature, ""},
		{"wrong InResponseTo", func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte {
			return e.idpSOAPLogoutResponse(t, req, true, func(resp *LogoutResponse) { resp.InResponseTo = "id-other" })
		}, ErrRequestIDMismatch, ""},
		{"wrong issuer", func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte {
			return e.idpSOAPLogoutResponse(t, req, true, func(resp *LogoutResponse) { resp.Issuer.Value = "https://evil.example.com/" })
		}, ErrIssuerMismatch, ""},
		{"wrong Destination", func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte {
			return e.idpSOAPLogoutResponse(t, req, true, func(resp *LogoutResponse) { resp.Destination = "https://other.example.com/" })
		}, ErrDestinationMismatch, ""},
		{"expired", func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte {
			return e.idpSOAPLogoutResponse(t, req, true, func(resp *LogoutResponse) { resp.IssueInstant = spcovNow.Add(-time.Hour) })
		}, ErrExpired, ""},
		{"Responder status", func(t *testing.T, e *spcovEnv, req *LogoutRequest) []byte {
			return e.idpSOAPLogoutResponse(t, req, true, func(resp *LogoutResponse) { resp.Status.StatusCode.Value = StatusResponder })
		}, ErrBadStatus{Status: StatusResponder}, ""},
		{"SOAP Fault", func(t *testing.T, _ *spcovEnv, _ *LogoutRequest) []byte {
			w := httptest.NewRecorder()
			assert.NilError(t, WriteSOAPFault(w, "no"))
			return w.Body.Bytes()
		}, nil, "the SOAP Body holds a Fault"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			s := newSOAPLogoutIDPServer(t, e)
			s.respond = func(req *LogoutRequest) []byte { return tc.respond(t, e, req) }
			req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
			assert.NilError(t, err)
			resp, err := e.sp.SendSOAPLogoutRequest(context.Background(), req)
			assert.Check(t, is.Nil(resp))
			privateErr := spcovPrivateErr(t, err)
			if tc.want != nil {
				assert.Check(t, is.ErrorIs(privateErr, tc.want))
			}
			if tc.wantMsg != "" {
				assert.Check(t, is.ErrorContains(privateErr, tc.wantMsg))
			}
		})
	}
}

func TestSendSOAPLogoutRequestTransport(t *testing.T) {
	t.Run("HTTP error status", func(t *testing.T) {
		e := spcovSetup(t)
		s := newSOAPLogoutIDPServer(t, e)
		s.status = http.StatusInternalServerError
		s.respond = func(*LogoutRequest) []byte { return nil }
		req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.NilError(t, err)
		_, err = e.sp.SendSOAPLogoutRequest(context.Background(), req)
		assert.Check(t, is.ErrorContains(err, "HTTP status 500"))
	})
	t.Run("oversized response", func(t *testing.T) {
		e := spcovSetup(t)
		old := MaxSOAPLogoutMessageSize
		t.Cleanup(func() { MaxSOAPLogoutMessageSize = old })
		MaxSOAPLogoutMessageSize = 4096
		s := newSOAPLogoutIDPServer(t, e)
		s.respond = func(req *LogoutRequest) []byte {
			return append(e.idpSOAPLogoutResponse(t, req, true, nil), bytes.Repeat([]byte(" "), 4096)...)
		}
		req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.NilError(t, err)
		_, err = e.sp.SendSOAPLogoutRequest(context.Background(), req)
		assert.Check(t, is.ErrorContains(err, "response body is larger than 4096 bytes"))
	})
	t.Run("cancelled context", func(t *testing.T) {
		e := spcovSetup(t)
		s := newSOAPLogoutIDPServer(t, e)
		s.respond = func(req *LogoutRequest) []byte { return e.idpSOAPLogoutResponse(t, req, true, nil) }
		req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.NilError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = e.sp.SendSOAPLogoutRequest(ctx, req)
		assert.Check(t, errors.Is(err, context.Canceled), "%v", err)
		assert.Check(t, is.Len(s.requests, 0))
	})
}

func TestMakeSOAPLogoutRequest(t *testing.T) {
	t.Run("no SOAP SingleLogoutService", func(t *testing.T) {
		e := spcovSetup(t)
		_, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.Check(t, is.ErrorIs(err, ErrNoSOAPSingleLogoutService))
	})
	t.Run("no IDPMetadata", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.IDPMetadata = nil
		_, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.Check(t, is.ErrorContains(err, "IDPMetadata is not set"))
	})
	t.Run("empty NameID", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = []Endpoint{{Binding: SOAPBinding, Location: soapLogoutIDPLocation}}
		_, err := e.sp.MakeSOAPLogoutRequest(NameID{})
		assert.Check(t, is.ErrorContains(err, "the NameID is empty"))
	})
	t.Run("without Key it is unsigned", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = []Endpoint{{Binding: SOAPBinding, Location: soapLogoutIDPLocation}}
		e.sp.Key = nil
		req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.NilError(t, err)
		assert.Check(t, req.Signature == nil)
	})
	t.Run("EncryptLogoutNameID", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = []Endpoint{{Binding: SOAPBinding, Location: soapLogoutIDPLocation}}
		e.sp.EncryptLogoutNameID = true
		e.sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].Use = ""
		req, err := e.sp.MakeSOAPLogoutRequest(NameID{Value: "alice"})
		assert.NilError(t, err)
		assert.Check(t, req.NameID == nil)
		assert.Check(t, req.EncryptedID != nil)
	})
}
