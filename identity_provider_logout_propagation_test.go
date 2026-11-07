package saml

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// trackingSessionProvider is a SessionProvider with one IdP session that
// implements SessionInvalidator and SessionParticipantTracker.
type trackingSessionProvider struct {
	session      *Session
	ended        bool
	participants map[string][]SessionParticipant
	addErr       error
	listErr      error
}

func (p *trackingSessionProvider) GetSession(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
	return p.session
}

func (p *trackingSessionProvider) InvalidateSession(_ http.ResponseWriter, _ *http.Request, req *IdpLogoutRequest) error {
	if req.MatchesSession(p.session) {
		p.ended = true
	}
	return nil
}

func (p *trackingSessionProvider) AddSessionParticipant(_ *http.Request, session *Session, participant SessionParticipant) error {
	if p.addErr != nil {
		return p.addErr
	}
	p.participants[session.ID] = append(p.participants[session.ID], participant)
	return nil
}

func (p *trackingSessionProvider) SessionParticipants(_ *http.Request, match func(*Session) bool) ([]SessionParticipant, error) {
	if p.listErr != nil {
		return nil, p.listErr
	}
	if p.ended || !match(p.session) {
		return nil, nil
	}
	return p.participants[p.session.ID], nil
}

// propagationTest is an IdP with several service providers, all of them
// this package's ServiceProvider, and a browser that carries the IdP's
// cookies between them.
type propagationTest struct {
	idp      *IdentityProvider
	sessions *trackingSessionProvider
	sps      []*ServiceProvider
	cookies  map[string]*http.Cookie

	// received counts the LogoutRequests each SP accepted, by entity ID.
	received map[string][]*LogoutRequest
	// status is the status each SP answers a LogoutRequest with; default
	// StatusSuccess.
	status map[string]string
	// answer, if set for an SP, replaces its LogoutResponse.
	answer map[string]func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) *http.Request
}

const propagationReturnURL = "https://idp.example.com/logged-out"

func newPropagationTest(t *testing.T) *propagationTest {
	base := NewIdentityProviderTest(t, applyKey)
	pt := &propagationTest{
		idp: &base.IDP,
		sessions: &trackingSessionProvider{
			session:      &Session{ID: "idp-session", NameID: "alice@example.com", Index: "idp-session-index"},
			participants: map[string][]SessionParticipant{},
		},
		cookies:  map[string]*http.Cookie{},
		received: map[string][]*LogoutRequest{},
		status:   map[string]string{},
		answer:   map[string]func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) *http.Request{},
	}
	pt.idp.LogoutURL = mustParseURL("https://idp.example.com/saml/slo")
	pt.idp.LogoutBindings = []string{HTTPRedirectBinding, HTTPPostBinding}
	pt.idp.SessionProvider = pt.sessions

	key := mustParsePrivateKey(golden.Get(t, "key_2017.pem")).(*rsa.PrivateKey)
	cert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
	for i, bindings := range [][]string{
		{HTTPRedirectBinding},
		{HTTPPostBinding},
		{HTTPRedirectBinding, HTTPPostBinding},
	} {
		host := fmt.Sprintf("https://sp%d.example.com", i+1)
		pt.sps = append(pt.sps, &ServiceProvider{
			Key:                     key,
			Certificate:             cert,
			MetadataURL:             mustParseURL(host + "/metadata"),
			AcsURL:                  mustParseURL(host + "/acs"),
			SloURL:                  mustParseURL(host + "/slo"),
			LogoutBindings:          bindings,
			SignatureMethod:         dsig.RSASHA256SignatureMethod,
			IgnoreCertificateExpiry: true, // the IdP test certificate expired in 2014
			IDPMetadata:             pt.idp.Metadata(),
		})
	}
	pt.idp.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, id string) (*EntityDescriptor, error) {
			if sp := pt.sp(id); sp != nil {
				return sp.Metadata(), nil
			}
			return nil, os.ErrNotExist
		},
	}
	return pt
}

func (pt *propagationTest) sp(entityID string) *ServiceProvider {
	for _, sp := range pt.sps {
		if sp.MetadataURL.String() == entityID {
			return sp
		}
	}
	return nil
}

// spForURL returns the SP that serves u, or nil.
func (pt *propagationTest) spForURL(u *url.URL) *ServiceProvider {
	for _, sp := range pt.sps {
		if sp.SloURL.Host == u.Host {
			return sp
		}
	}
	return nil
}

// login logs the IdP session in to each of sps with IdP-initiated SSO,
// which records them as participants.
func (pt *propagationTest) login(t *testing.T, sps ...*ServiceProvider) {
	for _, sp := range sps {
		w := httptest.NewRecorder()
		pt.idp.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/login", nil), sp.MetadataURL.String(), "")
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	}
}

// keepCookies stores the IdP cookies that w sets.
func (pt *propagationTest) keepCookies(w *httptest.ResponseRecorder) {
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(pt.cookies, c.Name)
			continue
		}
		pt.cookies[c.Name] = c
	}
}

// next returns the request the browser makes after receiving w: following
// a redirect or submitting an auto-submitting form.
func next(t *testing.T, w *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	switch w.Code {
	case http.StatusFound:
		return httptest.NewRequest(http.MethodGet, w.Header().Get("Location"), nil)
	case http.StatusOK:
		action, fields := formFields(t, w.Body.Bytes())
		return simpleSignPost(t, action, fields)
	default:
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		return nil
	}
}

// serveIDP sends r to the IdP's ServeSLO with the browser's IdP cookies.
func (pt *propagationTest) serveIDP(r *http.Request) *httptest.ResponseRecorder {
	for _, c := range pt.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	pt.idp.ServeSLO(w, r)
	pt.keepCookies(w)
	return w
}

// spAnswer has sp validate the LogoutRequest in r and returns the browser's
// request carrying its LogoutResponse to the IdP, with the IdP binding sp
// prefers (HTTP-Redirect for an SP whose own first binding is
// HTTP-Redirect, HTTP-POST otherwise).
func (pt *propagationTest) spAnswer(t *testing.T, sp *ServiceProvider, r *http.Request) *http.Request {
	t.Helper()
	req, err := sp.ValidateLogoutRequest(r)
	assert.NilError(t, err)
	id := sp.MetadataURL.String()
	pt.received[id] = append(pt.received[id], req)
	if answer := pt.answer[id]; answer != nil {
		return answer(t, sp, req)
	}
	status := pt.status[id]
	if status == "" {
		status = StatusSuccess
	}
	return spLogoutResponse(t, sp, req.ID, status, sp.LogoutBindings[0])
}

// spLogoutResponse returns the browser's request carrying a LogoutResponse
// from sp to the IdP, signed as the binding requires.
func spLogoutResponse(t *testing.T, sp *ServiceProvider, requestID, status, binding string) *http.Request {
	t.Helper()
	resp := sp.makeUnsignedLogoutResponse(sp.GetSLOBindingLocation(binding), requestID)
	resp.Status.StatusCode.Value = status
	return spSendLogoutResponse(t, sp, resp, binding)
}

func spSendLogoutResponse(t *testing.T, sp *ServiceProvider, resp *LogoutResponse, binding string) *http.Request {
	t.Helper()
	if binding == HTTPRedirectBinding {
		encoded, err := deflateAndEncode(resp.Element())
		assert.NilError(t, err)
		u, err := sp.redirectBindingURL(resp.Destination, redirectParamSAMLResponse, encoded, "", sp.logoutSignatureMethod())
		assert.NilError(t, err)
		return httptest.NewRequest(http.MethodGet, u.String(), nil)
	}
	assert.NilError(t, sp.SignLogoutResponse(resp))
	action, fields := formFields(t, resp.Post(""))
	return simpleSignPost(t, action, fields)
}

// run follows the logout from the IdP's response w through every SP until
// the browser leaves the SPs' SingleLogoutServices, and returns the last
// response of the IdP.
func (pt *propagationTest) run(t *testing.T, w *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	pt.keepCookies(w)
	for i := 0; i < 10; i++ {
		if w.Code == http.StatusOK && !strings.Contains(w.Body.String(), "<form") {
			return w
		}
		r := next(t, w)
		sp := pt.spForURL(r.URL)
		if sp == nil || r.URL.Path != sp.SloURL.Path || !hasSAMLRequest(r) {
			return w
		}
		w = pt.serveIDP(pt.spAnswer(t, sp, r))
	}
	t.Fatal("logout does not end")
	return nil
}

func hasSAMLRequest(r *http.Request) bool {
	if r.Method == http.MethodGet {
		return r.URL.Query().Get("SAMLRequest") != ""
	}
	return r.PostForm.Get("SAMLRequest") != ""
}

func (pt *propagationTest) startLogout(returnURL string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	pt.idp.StartLogout(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/logout", nil), pt.sessions.session, returnURL)
	return w
}

func TestIDPInitiatedLogoutRoundTrip(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps...)
	assert.Assert(t, is.Len(pt.sessions.participants["idp-session"], 3))

	w := pt.startLogout(propagationReturnURL)
	// The first SP is sent a LogoutRequest signed with SHA-256.
	assert.Equal(t, http.StatusFound, w.Code)
	first, err := url.Parse(w.Header().Get("Location"))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("sp1.example.com", first.Host))
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, first.Query().Get("SigAlg")))
	stateCookie := pt.cookieFrom(t, w)
	assert.Check(t, stateCookie.HttpOnly && stateCookie.Secure)
	assert.Check(t, is.Equal(http.SameSiteNoneMode, stateCookie.SameSite))
	assert.Check(t, is.Equal("/saml/slo", stateCookie.Path))

	w = pt.run(t, w)
	assert.Check(t, is.Equal(http.StatusFound, w.Code))
	assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
	assert.Check(t, is.Len(pt.cookies, 0), "the logout state cookie is cleared")

	// Each SP got one LogoutRequest, for the NameID and SessionIndex of the
	// assertion it was issued.
	for _, sp := range pt.sps {
		reqs := pt.received[sp.MetadataURL.String()]
		assert.Assert(t, is.Len(reqs, 1), sp.MetadataURL.String())
		assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value))
		assert.Check(t, is.Equal(sp.MetadataURL.String(), reqs[0].NameID.SPNameQualifier))
		assert.Check(t, is.Equal("idp-session-index", reqs[0].SessionIndex.Value))
		assert.Check(t, is.Equal(sp.SloURL.String(), reqs[0].Destination))
	}
}

func (pt *propagationTest) cookieFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == logoutStateCookieName {
			return c
		}
	}
	t.Fatalf("no logout state cookie in %v", w.Header().Values("Set-Cookie"))
	return nil
}

func TestIDPInitiatedLogoutPage(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps[0], pt.sps[1])
	pt.status[pt.sps[1].MetadataURL.String()] = StatusResponder

	w := pt.run(t, pt.startLogout(""))
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Contains(w.Body.String(), "You have been logged out"))
	// The SP that answered with an error is listed; the other is not.
	assert.Check(t, is.Contains(w.Body.String(), pt.sps[1].MetadataURL.String()))
	assert.Check(t, !strings.Contains(w.Body.String(), pt.sps[0].MetadataURL.String()))
}

func TestIDPInitiatedLogoutSkipsUnreachableSPs(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps...)
	// sp1 no longer lists a SingleLogoutService, and sp2 is unknown.
	pt.sps[0].LogoutBindings = nil
	unknown := pt.sps[1].MetadataURL.String()
	pt.sps[1].MetadataURL = mustParseURL("https://gone.example.com/metadata")

	w := pt.run(t, pt.startLogout(""))
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Len(pt.received[pt.sps[2].MetadataURL.String()], 1))
	assert.Check(t, is.Contains(w.Body.String(), pt.sps[0].MetadataURL.String()))
	assert.Check(t, is.Contains(w.Body.String(), unknown))
}

func TestIDPInitiatedLogoutWithoutTracking(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.SessionProvider = &mockSessionProvider{}

	w := pt.startLogout(propagationReturnURL)
	assert.Check(t, is.Equal(http.StatusFound, w.Code))
	assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
	assert.Check(t, is.Len(w.Result().Cookies(), 0))
}

// An SP-initiated LogoutRequest is propagated to the other participants
// before the initiating SP gets its LogoutResponse.
func TestSPInitiatedLogoutPropagation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failing     bool
		wantPartial bool
	}{
		{"all succeed", false, false},
		{"one fails", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pt := newPropagationTest(t)
			pt.login(t, pt.sps...)
			if tc.failing {
				pt.status[pt.sps[2].MetadataURL.String()] = StatusRequester
			}

			initiator := pt.sps[0]
			logoutRequest, err := initiator.MakeLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com", WithSessionIndex("idp-session-index"))
			assert.NilError(t, err)
			u, err := initiator.RedirectLogoutRequestURL(logoutRequest, "initiator-relay-state")
			assert.NilError(t, err)

			w := pt.run(t, pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil)))
			assert.Check(t, pt.sessions.ended)
			assert.Check(t, is.Len(pt.received[initiator.MetadataURL.String()], 0))
			assert.Check(t, is.Len(pt.received[pt.sps[1].MetadataURL.String()], 1))
			assert.Check(t, is.Len(pt.received[pt.sps[2].MetadataURL.String()], 1))
			assert.Check(t, is.Len(pt.cookies, 0))

			// The initiator accepts the LogoutResponse.
			r := next(t, w)
			assert.Check(t, is.Equal(initiator.SloURL.Host, r.URL.Host))
			resp, err := initiator.ParseLogoutResponse(r, []string{logoutRequest.ID})
			assert.NilError(t, err)
			assert.Check(t, is.Equal("initiator-relay-state", r.URL.Query().Get("RelayState")))
			assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
			if tc.wantPartial {
				assert.Assert(t, resp.Status.StatusCode.StatusCode != nil)
				assert.Check(t, is.Equal(StatusPartialLogout, resp.Status.StatusCode.StatusCode.Value))
			} else {
				assert.Check(t, is.Nil(resp.Status.StatusCode.StatusCode))
			}
		})
	}
}

func TestSPInitiatedLogoutOnlyParticipant(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps[0])
	logoutRequest := pt.sps[0].makeUnsignedLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com")
	u, err := pt.sps[0].RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)

	// With no other participant, the LogoutResponse is sent at once.
	w := pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil))
	resp, err := pt.sps[0].ParseLogoutResponse(next(t, w), []string{logoutRequest.ID})
	assert.NilError(t, err)
	assert.Check(t, is.Nil(resp.Status.StatusCode.StatusCode))
	assert.Check(t, is.Len(pt.cookies, 0))
}

func TestSPInitiatedLogoutParticipantLookupFails(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps...)
	pt.sessions.listErr = errors.New("store unavailable")
	logoutRequest := pt.sps[0].makeUnsignedLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com")
	u, err := pt.sps[0].RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)

	w := pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil))
	resp, err := pt.sps[0].ParseLogoutResponse(next(t, w), []string{logoutRequest.ID})
	assert.NilError(t, err)
	assert.Assert(t, resp.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(StatusPartialLogout, resp.Status.StatusCode.StatusCode.Value))
}

func TestRecordSessionParticipantFails(t *testing.T) {
	pt := newPropagationTest(t)
	pt.sessions.addErr = errors.New("store unavailable")
	w := httptest.NewRecorder()
	pt.idp.ServeIDPInitiated(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/login", nil), pt.sps[0].MetadataURL.String(), "")
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
}

// LogoutResponses that do not answer the outstanding LogoutRequest, or are
// not validly signed by the SP it was sent to, are rejected and leave the
// logout where it was.
func TestIDPRejectsBadLogoutResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		// response returns the browser's request to the IdP, given the
		// LogoutRequest the IdP sent to sp (sp1, which uses HTTP-Redirect).
		response func(t *testing.T, pt *propagationTest, sp *ServiceProvider, req *LogoutRequest) *http.Request
	}{
		{"wrong InResponseTo", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, _ *LogoutRequest) *http.Request {
			return spLogoutResponse(t, sp, "id-other", StatusSuccess, HTTPRedirectBinding)
		}},
		{"no InResponseTo", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, _ *LogoutRequest) *http.Request {
			return spLogoutResponse(t, sp, "", StatusSuccess, HTTPRedirectBinding)
		}},
		{"signed by another key", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, req *LogoutRequest) *http.Request {
			other := *sp
			other.Key = mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
			return spLogoutResponse(t, &other, req.ID, StatusSuccess, HTTPRedirectBinding)
		}},
		{"post signed by another key", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, req *LogoutRequest) *http.Request {
			other := *sp
			other.Key = mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
			return spLogoutResponse(t, &other, req.ID, StatusSuccess, HTTPPostBinding)
		}},
		{"unsigned", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, req *LogoutRequest) *http.Request {
			unsigned := *sp
			unsigned.SignatureMethod = ""
			return spLogoutResponse(t, &unsigned, req.ID, StatusSuccess, HTTPRedirectBinding)
		}},
		{"from another participant", func(t *testing.T, pt *propagationTest, _ *ServiceProvider, req *LogoutRequest) *http.Request {
			return spLogoutResponse(t, pt.sps[2], req.ID, StatusSuccess, HTTPRedirectBinding)
		}},
		{"wrong destination", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, req *LogoutRequest) *http.Request {
			resp := sp.makeUnsignedLogoutResponse("https://other-idp.example.com/slo", req.ID)
			return spSendLogoutResponse(t, sp, resp, HTTPRedirectBinding)
		}},
		{"expired", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, req *LogoutRequest) *http.Request {
			resp := sp.makeUnsignedLogoutResponse(sp.GetSLOBindingLocation(HTTPRedirectBinding), req.ID)
			resp.IssueInstant = TimeNow().Add(-MaxIssueDelay - time.Second)
			return spSendLogoutResponse(t, sp, resp, HTTPRedirectBinding)
		}},
		{"tampered", func(t *testing.T, _ *propagationTest, sp *ServiceProvider, req *LogoutRequest) *http.Request {
			r := spLogoutResponse(t, sp, req.ID, StatusRequester, HTTPRedirectBinding)
			ok := sp.makeUnsignedLogoutResponse(sp.GetSLOBindingLocation(HTTPRedirectBinding), req.ID)
			return withRawQueryParam(r, "SAMLResponse", ok.Redirect("").Query().Get("SAMLResponse"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pt := newPropagationTest(t)
			pt.login(t, pt.sps[0], pt.sps[1])
			w := pt.startLogout("")
			pt.keepCookies(w)
			state := pt.cookies[logoutStateCookieName]
			assert.Assert(t, state != nil)

			r := next(t, w)
			sp := pt.spForURL(r.URL)
			req, err := sp.ValidateLogoutRequest(r)
			assert.NilError(t, err)

			w = pt.serveIDP(tc.response(t, pt, sp, req))
			assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
			assert.Check(t, is.Len(w.Result().Cookies(), 0), "the logout state is unchanged")

			// The genuine answer is still accepted afterwards.
			w = pt.serveIDP(spLogoutResponse(t, sp, req.ID, StatusSuccess, HTTPRedirectBinding))
			r = next(t, w)
			assert.Check(t, is.Equal(pt.sps[1].SloURL.Host, r.URL.Host))
		})
	}
}

func TestIDPRejectsLogoutResponseWithoutValidState(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps[0])
	w := pt.startLogout("")
	pt.keepCookies(w)
	sp := pt.sps[0]
	req, err := sp.ValidateLogoutRequest(next(t, w))
	assert.NilError(t, err)
	state := pt.cookies[logoutStateCookieName]

	for name, cookie := range map[string]*http.Cookie{
		"unsolicited (no state)":  nil,
		"tampered state":          stateCookie("x" + state.Value),
		"state without signature": stateCookie(strings.SplitN(state.Value, ".", 2)[0]),
		"state signed by another key": stateCookie(func() string {
			other := *pt.idp
			other.Key = mustParsePrivateKey(golden.Get(t, "key_2017.pem"))
			st, err := pt.idp.decodeLogoutState(state.Value)
			assert.NilError(t, err)
			v, err := other.encodeLogoutState(st)
			assert.NilError(t, err)
			return v
		}()),
		"expired state": stateCookie(func() string {
			st, err := pt.idp.decodeLogoutState(state.Value)
			assert.NilError(t, err)
			st.Expires = TimeNow()
			v, err := pt.idp.encodeLogoutState(st)
			assert.NilError(t, err)
			return v
		}()),
	} {
		t.Run(name, func(t *testing.T) {
			r := spLogoutResponse(t, sp, req.ID, StatusSuccess, HTTPRedirectBinding)
			if cookie != nil {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			pt.idp.ServeSLO(w, r)
			assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
		})
	}
}

func stateCookie(value string) *http.Cookie {
	return &http.Cookie{Name: logoutStateCookieName, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode} //nolint:gosec // test copy of the IdP state cookie, which must be SameSite=None so HTTP-POST LogoutResponses carry it
}

// Without a SessionParticipantTracker, a LogoutResponse at the IdP is never
// expected.
func TestIDPServeSLOLogoutResponseWithoutLogoutInProgress(t *testing.T) {
	test := newSLOTest(t)
	resp := test.SP.makeUnsignedLogoutResponse(test.IDP.LogoutURL.String(), "id-x")
	w := test.serve(spSendLogoutResponse(t, &test.SP, resp, HTTPRedirectBinding))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, is.Equal(0, test.sessions.calls))
}

func TestIDPRejectSHA1LogoutResponses(t *testing.T) {
	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		for _, reject := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s reject=%v", binding, reject), func(t *testing.T) {
				pt := newPropagationTest(t)
				pt.idp.RejectSHA1Signatures = reject
				pt.login(t, pt.sps[0], pt.sps[1])
				w := pt.startLogout("")
				pt.keepCookies(w)

				r := next(t, w)
				sp := pt.spForURL(r.URL)
				req, err := sp.ValidateLogoutRequest(r)
				assert.NilError(t, err)

				sha1SP := *sp
				sha1SP.SignatureMethod = dsig.RSASHA1SignatureMethod
				w = pt.serveIDP(spLogoutResponse(t, &sha1SP, req.ID, StatusSuccess, binding))
				if !reject {
					r = next(t, w)
					assert.Check(t, is.Equal(pt.sps[1].SloURL.Host, r.URL.Host))
					return
				}
				assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
				assert.Check(t, is.Len(w.Result().Cookies(), 0), "the logout state is unchanged")

				// The same answer signed with SHA-256 is accepted.
				w = pt.serveIDP(spLogoutResponse(t, sp, req.ID, StatusSuccess, binding))
				r = next(t, w)
				assert.Check(t, is.Equal(pt.sps[1].SloURL.Host, r.URL.Host))
			})
		}
	}
}

// The IdP reads a propagated LogoutResponse from what its enveloped
// signature covers: a namespace declaration added after signing, which
// encoding/xml would read as the StatusCode's Value, must not turn a failed
// logout into a successful one.
func TestPropagatedLogoutResponseStatusIgnoresNamespaceDeclaration(t *testing.T) {
	pt := newPropagationTest(t)
	pt.login(t, pt.sps...)
	pt.answer[pt.sps[1].MetadataURL.String()] = func(t *testing.T, sp *ServiceProvider, req *LogoutRequest) *http.Request {
		resp := sp.makeUnsignedLogoutResponse(sp.GetSLOBindingLocation(HTTPPostBinding), req.ID)
		resp.Status.StatusCode.Value = StatusRequester
		assert.NilError(t, sp.SignLogoutResponse(resp))
		action, fields := formFields(t, resp.Post(""))

		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromString(string(mustBase64Decode(t, fields.Get("SAMLResponse")))))
		statusCode := doc.FindElement("//StatusCode")
		assert.Assert(t, statusCode != nil)
		statusCode.CreateAttr("xmlns:Value", StatusSuccess)
		buf, err := doc.WriteToBytes()
		assert.NilError(t, err)
		fields.Set("SAMLResponse", base64.StdEncoding.EncodeToString(buf))
		return simpleSignPost(t, action, fields)
	}

	initiator := pt.sps[0]
	logoutRequest, err := initiator.MakeLogoutRequest(pt.idp.LogoutURL.String(), "alice@example.com", WithSessionIndex("idp-session-index"))
	assert.NilError(t, err)
	u, err := initiator.RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)

	w := pt.run(t, pt.serveIDP(httptest.NewRequest(http.MethodGet, u.String(), nil)))
	resp, err := initiator.ParseLogoutResponse(next(t, w), []string{logoutRequest.ID})
	assert.NilError(t, err)
	assert.Assert(t, resp.Status.StatusCode.StatusCode != nil, "sp2's failure must be reported")
	assert.Check(t, is.Equal(StatusPartialLogout, resp.Status.StatusCode.StatusCode.Value))
}

func mustBase64Decode(t *testing.T, s string) []byte {
	t.Helper()
	buf, err := base64.StdEncoding.DecodeString(s)
	assert.NilError(t, err)
	return buf
}
