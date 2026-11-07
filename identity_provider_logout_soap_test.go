package saml

import (
	"bytes"
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// soapParticipant is a service provider, this package's ServiceProvider,
// that serves a SOAP SingleLogoutService on an httptest server, as a
// session participant the IdP logs out over the back channel.
type soapParticipant struct {
	sp     *ServiceProvider
	server *httptest.Server

	mu sync.Mutex
	// received are the LogoutRequests the SP accepted over SOAP.
	received []*LogoutRequest
	// errs are the errors the SOAP endpoint met.
	errs []error
	// respond, if set, returns the SOAP body the SP answers req with, in
	// place of a signed Success LogoutResponse.
	respond func(sp *ServiceProvider, req *LogoutRequest) []byte
}

// addSOAPParticipant adds to pt an SP that lists an https SOAP
// SingleLogoutService after the given front-channel bindings. Unless pt.idp
// already has an HTTPClient, it is given one that trusts the test server
// certificate (which every httptest TLS server shares) and otherwise behaves
// like the default one.
func (pt *propagationTest) addSOAPParticipant(t *testing.T, frontChannelBindings ...string) *soapParticipant {
	p := &soapParticipant{}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serveSOAP))
	t.Cleanup(p.server.Close)
	if pt.idp.HTTPClient == nil {
		pt.idp.HTTPClient = &http.Client{
			Transport:     p.server.Client().Transport,
			Timeout:       defaultSOAPHTTPClient.Timeout,
			CheckRedirect: defaultSOAPHTTPClient.CheckRedirect,
		}
	}
	return pt.addSOAPParticipantAt(p, frontChannelBindings)
}

// addHTTPSOAPParticipant is addSOAPParticipant with a plain http SOAP
// SingleLogoutService, which the IdP ignores unless
// AllowInsecureSOAPEndpoints is set.
func (pt *propagationTest) addHTTPSOAPParticipant(t *testing.T, frontChannelBindings ...string) *soapParticipant {
	p := &soapParticipant{}
	p.server = httptest.NewServer(http.HandlerFunc(p.serveSOAP))
	t.Cleanup(p.server.Close)
	return pt.addSOAPParticipantAt(p, frontChannelBindings)
}

func (pt *propagationTest) addSOAPParticipantAt(p *soapParticipant, frontChannelBindings []string) *soapParticipant {

	template := pt.sps[0]
	p.sp = &ServiceProvider{
		Key:                     template.Key,
		Certificate:             template.Certificate,
		MetadataURL:             mustParseURL(p.server.URL + "/metadata"),
		AcsURL:                  mustParseURL(p.server.URL + "/acs"),
		SloURL:                  mustParseURL(p.server.URL + "/slo"),
		LogoutBindings:          append(frontChannelBindings, SOAPBinding),
		SignatureMethod:         dsig.RSASHA256SignatureMethod,
		IgnoreCertificateExpiry: true,
		IDPMetadata:             pt.idp.Metadata(),
	}
	pt.sps = append(pt.sps, p.sp)
	return p
}

func (p *soapParticipant) fail(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errs = append(p.errs, err)
}

// serveSOAP validates a LogoutRequest sent with the SOAP binding and answers
// it.
func (p *soapParticipant) serveSOAP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.fail(err)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/xml") {
		p.fail(errUnexpected("Content-Type " + ct))
	}
	el, err := soapBodyElement(body, "LogoutRequest")
	if err != nil {
		p.fail(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	signed, err := p.sp.validatedElement(el)
	if err != nil {
		p.fail(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := p.sp.unmarshalAndValidateLogoutRequest(signed, &InvalidResponseError{})
	if err != nil {
		p.fail(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.received = append(p.received, req)
	respond := p.respond
	p.mu.Unlock()

	var out []byte
	if respond != nil {
		out = respond(p.sp, req)
	} else {
		out = soapLogoutResponseBody(p.sp, req.ID, StatusSuccess, nil)
	}
	w.Header().Set("Content-Type", soapContentType)
	_, _ = w.Write(out)
}

type errUnexpected string

func (e errUnexpected) Error() string { return "unexpected " + string(e) }

// soapLogoutResponseBody returns a SOAP envelope holding a LogoutResponse
// from sp to requestID with status and no Destination, signed by sp unless
// sp has no SignatureMethod. modify, if set, changes the response before it
// is signed.
func soapLogoutResponseBody(sp *ServiceProvider, requestID, status string, modify func(*LogoutResponse)) []byte {
	resp := sp.makeUnsignedLogoutResponse("", requestID)
	resp.Status.StatusCode.Value = status
	if modify != nil {
		modify(resp)
	}
	if sp.SignatureMethod != "" {
		if err := sp.SignLogoutResponse(resp); err != nil {
			panic(err)
		}
	}
	buf, err := elementToBytes(soapEnvelope(resp.Element()))
	if err != nil {
		panic(err)
	}
	return buf
}

func (p *soapParticipant) requests() []*LogoutRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*LogoutRequest(nil), p.received...)
}

func (p *soapParticipant) checkNoErrors(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	assert.Check(t, is.Len(p.errs, 0), "%v", p.errs)
}

// IdP-initiated logout logs a participant with a SOAP SingleLogoutService
// out over the back channel, and the browser only visits the others.
func TestIDPInitiatedLogoutOverSOAP(t *testing.T) {
	pt := newPropagationTest(t)
	soapSP := pt.addSOAPParticipant(t, HTTPRedirectBinding)
	pt.login(t, soapSP.sp, pt.sps[0])

	w := pt.startLogout(propagationReturnURL)
	// The SOAP participant is done before the browser is sent anywhere.
	reqs := soapSP.requests()
	assert.Assert(t, is.Len(reqs, 1))
	assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value))
	assert.Check(t, is.Equal("idp-session-index", reqs[0].SessionIndex.Value))
	assert.Check(t, is.Equal(soapSP.sp.SloURL.String(), reqs[0].Destination))
	assert.Check(t, is.Equal(http.StatusFound, w.Code))
	assert.Check(t, strings.HasPrefix(w.Header().Get("Location"), pt.sps[0].SloURL.String()))

	w = pt.run(t, w)
	assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
	assert.Check(t, is.Len(pt.received[soapSP.sp.MetadataURL.String()], 0), "the SOAP participant is not visited by the browser")
	assert.Check(t, is.Len(pt.received[pt.sps[0].MetadataURL.String()], 1))
	assert.Check(t, is.Len(soapSP.requests(), 1))
	soapSP.checkNoErrors(t)
}

// With only SOAP participants, the logout finishes without the browser
// leaving the IdP.
func TestIDPInitiatedLogoutOnlySOAP(t *testing.T) {
	pt := newPropagationTest(t)
	first := pt.addSOAPParticipant(t)
	second := pt.addSOAPParticipant(t)
	pt.login(t, first.sp, second.sp)

	w := pt.startLogout("")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Contains(w.Body.String(), "You have been logged out"))
	assert.Check(t, !strings.Contains(w.Body.String(), "could not be confirmed"), w.Body.String())
	assert.Check(t, is.Len(w.Result().Cookies(), 0), "no logout state is needed")
	assert.Check(t, is.Len(first.requests(), 1))
	assert.Check(t, is.Len(second.requests(), 1))
	first.checkNoErrors(t)
	second.checkNoErrors(t)
}

// SP-initiated logout is propagated over SOAP, and the initiator gets its
// LogoutResponse at once.
func TestSPInitiatedLogoutPropagationOverSOAP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      string
		wantPartial bool
	}{
		{"success", StatusSuccess, false},
		{"participant fails", StatusResponder, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pt := newPropagationTest(t)
			soapSP := pt.addSOAPParticipant(t)
			soapSP.respond = func(sp *ServiceProvider, req *LogoutRequest) []byte {
				return soapLogoutResponseBody(sp, req.ID, tc.status, nil)
			}
			initiator := pt.sps[0]
			pt.login(t, initiator, soapSP.sp)

			logoutRequest, err := initiator.MakeLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com", WithSessionIndex("idp-session-index"))
			assert.NilError(t, err)
			u, err := initiator.RedirectLogoutRequestURL(logoutRequest, "relay")
			assert.NilError(t, err)
			w := pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil))

			assert.Check(t, pt.sessions.ended)
			assert.Check(t, is.Len(soapSP.requests(), 1))
			r := next(t, w)
			assert.Check(t, is.Equal(initiator.SloURL.Host, r.URL.Host))
			resp, err := initiator.ParseLogoutResponse(r, []string{logoutRequest.ID})
			assert.NilError(t, err)
			if tc.wantPartial {
				assert.Assert(t, resp.Status.StatusCode.StatusCode != nil)
				assert.Check(t, is.Equal(StatusPartialLogout, resp.Status.StatusCode.StatusCode.Value))
			} else {
				assert.Check(t, is.Nil(resp.Status.StatusCode.StatusCode))
			}
			assert.Check(t, is.Len(pt.cookies, 0))
		})
	}
}

// SOAP LogoutResponses that are not a valid, signed answer from the
// participant are failures: the participant is reported as not logged out,
// or, if it also lists a front-channel endpoint, the browser is sent there.
func TestIDPRejectsBadSOAPLogoutResponses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte
		setup   func(pt *propagationTest)
	}{
		{"unsigned", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			unsigned := *sp
			unsigned.SignatureMethod = ""
			return soapLogoutResponseBody(&unsigned, req.ID, StatusSuccess, nil)
		}, nil},
		{"signed by another key", func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			other := *sp
			other.Key = mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
			return soapLogoutResponseBody(&other, req.ID, StatusSuccess, nil)
		}, nil},
		{"tampered", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			body := soapLogoutResponseBody(sp, req.ID, StatusResponder, nil)
			return bytes.Replace(body, []byte(StatusResponder), []byte(StatusSuccess), 1)
		}, nil},
		{"wrong issuer", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, req.ID, StatusSuccess, func(resp *LogoutResponse) {
				resp.Issuer.Value = "https://sp1.example.com/metadata"
			})
		}, nil},
		{"wrong InResponseTo (replayed response)", func(_ *testing.T, sp *ServiceProvider, _ *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, "id-an-earlier-request", StatusSuccess, nil)
		}, nil},
		{"wrong destination", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, req.ID, StatusSuccess, func(resp *LogoutResponse) {
				resp.Destination = "https://other-idp.example.com/slo"
			})
		}, nil},
		{"expired", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, req.ID, StatusSuccess, func(resp *LogoutResponse) {
				resp.IssueInstant = TimeNow().Add(-MaxIssueDelay - time.Second)
			})
		}, nil},
		{"status Responder", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, req.ID, StatusResponder, nil)
		}, nil},
		{"SOAP fault", func(*testing.T, *ServiceProvider, *LogoutRequest) []byte {
			return []byte(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><soapenv:Fault><faultcode>soapenv:Server</faultcode><faultstring>no</faultstring></soapenv:Fault></soapenv:Body></soapenv:Envelope>`)
		}, nil},
		{"bare LogoutResponse", func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			resp := sp.makeUnsignedLogoutResponse("", req.ID)
			assert.NilError(t, sp.SignLogoutResponse(resp))
			buf, err := elementToBytes(resp.Element())
			assert.NilError(t, err)
			return buf
		}, nil},
		{"oversized", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			body := soapLogoutResponseBody(sp, req.ID, StatusSuccess, nil)
			return append(body, bytes.Repeat([]byte(" "), 4096)...)
		}, func(*propagationTest) {
			old := MaxSOAPLogoutMessageSize
			t.Cleanup(func() { MaxSOAPLogoutMessageSize = old })
			MaxSOAPLogoutMessageSize = 4096
		}},
		{"SHA-1 signature with RejectSHA1Signatures", func(_ *testing.T, sp *ServiceProvider, req *LogoutRequest) []byte {
			sha1SP := *sp
			sha1SP.SignatureMethod = dsig.RSASHA1SignatureMethod
			return soapLogoutResponseBody(&sha1SP, req.ID, StatusSuccess, nil)
		}, func(pt *propagationTest) { pt.idp.RejectSHA1Signatures = true }},
	} {
		t.Run(tc.name+" (SOAP only)", func(t *testing.T) {
			pt := newPropagationTest(t)
			soapSP := pt.addSOAPParticipant(t)
			soapSP.respond = func(sp *ServiceProvider, req *LogoutRequest) []byte { return tc.respond(t, sp, req) }
			if tc.setup != nil {
				tc.setup(pt)
			}
			pt.login(t, soapSP.sp)

			w := pt.startLogout("")
			assert.Check(t, is.Len(soapSP.requests(), 1))
			assert.Check(t, is.Equal(http.StatusOK, w.Code))
			assert.Check(t, is.Contains(w.Body.String(), "could not be confirmed"))
			assert.Check(t, is.Contains(w.Body.String(), soapSP.sp.MetadataURL.String()))
			soapSP.checkNoErrors(t)
		})
		t.Run(tc.name+" (front-channel fallback)", func(t *testing.T) {
			pt := newPropagationTest(t)
			soapSP := pt.addSOAPParticipant(t, HTTPRedirectBinding)
			soapSP.respond = func(sp *ServiceProvider, req *LogoutRequest) []byte { return tc.respond(t, sp, req) }
			if tc.setup != nil {
				tc.setup(pt)
			}
			pt.login(t, soapSP.sp)

			w := pt.startLogout(propagationReturnURL)
			assert.Check(t, is.Len(soapSP.requests(), 1))
			assert.Check(t, is.Equal(http.StatusFound, w.Code))
			assert.Check(t, strings.HasPrefix(w.Header().Get("Location"), soapSP.sp.SloURL.String()+"?"))
			w = pt.run(t, w)
			assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
			assert.Check(t, is.Len(pt.received[soapSP.sp.MetadataURL.String()], 1))
		})
	}
}

// Responses the IdP accepts over SOAP: Destination may be absent or name
// the IdP, and SHA-1 signatures are accepted unless RejectSHA1Signatures is
// set.
func TestIDPAcceptsSOAPLogoutResponses(t *testing.T) {
	for _, tc := range []struct {
		name    string
		respond func(sp *ServiceProvider, req *LogoutRequest) []byte
	}{
		{"destination is the IdP entity ID", func(sp *ServiceProvider, req *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, req.ID, StatusSuccess, func(resp *LogoutResponse) {
				resp.Destination = "https://idp.example.com/saml/metadata"
			})
		}},
		{"destination is the IdP LogoutURL", func(sp *ServiceProvider, req *LogoutRequest) []byte {
			return soapLogoutResponseBody(sp, req.ID, StatusSuccess, func(resp *LogoutResponse) {
				resp.Destination = "https://idp.example.com/saml/slo"
			})
		}},
		{"SHA-1 signature", func(sp *ServiceProvider, req *LogoutRequest) []byte {
			sha1SP := *sp
			sha1SP.SignatureMethod = dsig.RSASHA1SignatureMethod
			return soapLogoutResponseBody(&sha1SP, req.ID, StatusSuccess, nil)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pt := newPropagationTest(t)
			soapSP := pt.addSOAPParticipant(t)
			soapSP.respond = tc.respond
			pt.login(t, soapSP.sp)

			w := pt.startLogout(propagationReturnURL)
			assert.Check(t, is.Len(soapSP.requests(), 1))
			assert.Check(t, is.Equal(http.StatusFound, w.Code))
			assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
		})
	}
}

// The IdP sends SOAP messages with HTTPClient, and its default client does
// not follow redirects.
func TestIDPSOAPLogoutHTTPClient(t *testing.T) {
	t.Run("redirect not followed", func(t *testing.T) {
		// Plain http servers, so that the default client is used.
		pt := newPropagationTest(t)
		pt.idp.AllowInsecureSOAPEndpoints = true
		target := pt.addHTTPSOAPParticipant(t)
		redirecting := pt.addHTTPSOAPParticipant(t)
		redirecting.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.sp.SloURL.String(), http.StatusTemporaryRedirect)
		})
		pt.login(t, redirecting.sp)

		w := pt.startLogout("")
		assert.Check(t, is.Contains(w.Body.String(), redirecting.sp.MetadataURL.String()))
		assert.Check(t, is.Len(target.requests(), 0))
	})
	t.Run("custom client", func(t *testing.T) {
		pt := newPropagationTest(t)
		soapSP := pt.addSOAPParticipant(t)
		var used bool
		transport := soapSP.server.Client().Transport
		pt.idp.HTTPClient = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			used = true
			return transport.RoundTrip(r)
		})}
		pt.login(t, soapSP.sp)

		w := pt.startLogout(propagationReturnURL)
		assert.Check(t, used)
		assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
		assert.Check(t, is.Len(soapSP.requests(), 1))
	})
	t.Run("unreachable", func(t *testing.T) {
		pt := newPropagationTest(t)
		soapSP := pt.addSOAPParticipant(t)
		pt.login(t, soapSP.sp)
		soapSP.server.Close()

		w := pt.startLogout("")
		assert.Check(t, is.Contains(w.Body.String(), soapSP.sp.MetadataURL.String()))
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// A SOAP SingleLogoutService that is not https is ignored, so that the
// LogoutRequest with the user's NameID does not cross the network in the
// clear: the participant is logged out through the browser if it lists a
// front-channel endpoint, and is reported as not logged out if it does not.
// AllowInsecureSOAPEndpoints lets the IdP use the http endpoint.
func TestIDPIgnoresInsecureSOAPLogoutEndpoint(t *testing.T) {
	t.Run("front-channel fallback", func(t *testing.T) {
		pt := newPropagationTest(t)
		soapSP := pt.addHTTPSOAPParticipant(t, HTTPRedirectBinding)
		pt.login(t, soapSP.sp)

		w := pt.startLogout(propagationReturnURL)
		assert.Check(t, is.Len(soapSP.requests(), 0))
		assert.Check(t, is.Equal(http.StatusFound, w.Code))
		assert.Check(t, strings.HasPrefix(w.Header().Get("Location"), soapSP.sp.SloURL.String()), w.Header().Get("Location"))
	})
	t.Run("no front channel", func(t *testing.T) {
		pt := newPropagationTest(t)
		soapSP := pt.addHTTPSOAPParticipant(t)
		pt.login(t, soapSP.sp)

		w := pt.startLogout("")
		assert.Check(t, is.Len(soapSP.requests(), 0))
		assert.Check(t, is.Contains(w.Body.String(), soapSP.sp.MetadataURL.String()))
	})
	t.Run("allowed", func(t *testing.T) {
		pt := newPropagationTest(t)
		pt.idp.AllowInsecureSOAPEndpoints = true
		soapSP := pt.addHTTPSOAPParticipant(t, HTTPRedirectBinding)
		pt.login(t, soapSP.sp)

		w := pt.startLogout(propagationReturnURL)
		assert.Check(t, is.Len(soapSP.requests(), 1))
		assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
		soapSP.checkNoErrors(t)
	})
}

func TestCheckSOAPEndpoint(t *testing.T) {
	for _, tc := range []struct {
		location      string
		allowInsecure bool
		wantErr       bool
	}{
		{"https://idp.example.com/soap", false, false},
		{"HTTPS://idp.example.com/soap", false, false},
		{"http://idp.example.com/soap", false, true},
		{"http://idp.example.com/soap", true, false},
		{"ftp://idp.example.com/soap", true, true},
		{"/soap", true, true},
		{"", false, true},
	} {
		err := checkSOAPEndpoint(tc.location, tc.allowInsecure)
		if tc.wantErr {
			assert.Check(t, is.ErrorIs(err, ErrInsecureSOAPEndpoint), "%q", tc.location)
		} else {
			assert.Check(t, is.Nil(err), "%q", tc.location)
		}
	}
	assert.Check(t, is.ErrorContains(checkSOAPEndpoint("http://[::1", true), "invalid SOAP endpoint"))
}
