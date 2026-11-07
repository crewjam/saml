package samlidp

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// propagationServerTest is a samlidp server with two service providers that
// support single logout, and a browser holding the IdP's cookies.
type propagationServerTest struct {
	*ServerTest
	sp2     saml.ServiceProvider
	cookies map[string]*http.Cookie
	// received are the LogoutRequests each SP accepted, by SLO host.
	received map[string]int
}

func newPropagationServerTest(t *testing.T) *propagationServerTest {
	test := newSLOServerTest(t)
	sp2 := test.SP
	sp2.MetadataURL = mustParseURL("https://sp2.example.com/saml2/metadata")
	sp2.AcsURL = mustParseURL("https://sp2.example.com/saml2/acs")
	sp2.SloURL = mustParseURL("https://sp2.example.com/saml2/slo")
	sp2.LogoutBindings = []string{saml.HTTPPostBinding}
	test.Server.serviceProviders[sp2.MetadataURL.String()] = sp2.Metadata()
	return &propagationServerTest{ServerTest: test, sp2: sp2, cookies: map[string]*http.Cookie{}, received: map[string]int{}}
}

func (pt *propagationServerTest) serve(r *http.Request) *httptest.ResponseRecorder {
	for _, c := range pt.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	pt.Server.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(pt.cookies, c.Name)
		} else {
			pt.cookies[c.Name] = c
		}
	}
	return w
}

// sso logs the browser's session in to sp with SP-initiated SSO.
func (pt *propagationServerTest) sso(t *testing.T, sp *saml.ServiceProvider) {
	u, err := sp.MakeRedirectAuthenticationRequest("")
	assert.NilError(t, err)
	w := pt.serve(httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Check(t, is.Contains(w.Body.String(), `name="SAMLResponse"`))
}

var (
	formActionRe = regexp.MustCompile(`<form method="post" action="([^"]*)"`)
	formInputRe  = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
)

// next returns the request the browser makes after w.
func next(t *testing.T, w *httptest.ResponseRecorder) *http.Request {
	t.Helper()
	if w.Code == http.StatusFound {
		return httptest.NewRequest(http.MethodGet, w.Header().Get("Location"), nil)
	}
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	action := formActionRe.FindStringSubmatch(w.Body.String())
	assert.Assert(t, action != nil, w.Body.String())
	form := url.Values{}
	for _, m := range formInputRe.FindAllStringSubmatch(w.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	r := httptest.NewRequest(http.MethodPost, html.UnescapeString(action[1]), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func (pt *propagationServerTest) spFor(r *http.Request) *saml.ServiceProvider {
	switch r.URL.Host {
	case pt.SP.SloURL.Host:
		return &pt.SP
	case pt.sp2.SloURL.Host:
		return &pt.sp2
	}
	return nil
}

// run answers each LogoutRequest the IdP sends to an SP until the IdP
// sends something else, and returns that last IdP response.
func (pt *propagationServerTest) run(t *testing.T, w *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	for i := 0; i < 10; i++ {
		if w.Code == http.StatusOK && !strings.Contains(w.Body.String(), "<form") {
			return w
		}
		r := next(t, w)
		sp := pt.spFor(r)
		if sp == nil {
			return w
		}
		assert.NilError(t, r.ParseForm())
		if r.Form.Get("SAMLRequest") == "" {
			return w
		}
		req, err := sp.ValidateLogoutRequest(r)
		assert.NilError(t, err)
		pt.received[sp.SloURL.Host]++
		u, err := sp.MakeRedirectLogoutResponse(req.ID, r.Form.Get("RelayState"))
		assert.NilError(t, err)
		w = pt.serve(httptest.NewRequest(http.MethodGet, u.String(), nil))
	}
	t.Fatal("logout does not end")
	return nil
}

func TestLogoutPropagatesToEveryServiceProvider(t *testing.T) {
	pt := newPropagationServerTest(t)
	session, cookie := pt.login(t, "alice", "alice@example.com")
	pt.cookies[cookie.Name] = cookie
	pt.sso(t, &pt.SP)
	pt.sso(t, &pt.sp2)

	participants, err := pt.Server.storedSessionParticipants(session.ID)
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, 2))

	w := pt.run(t, pt.serve(httptest.NewRequest(http.MethodGet, "https://idp.example.com/logout", nil)))
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Contains(w.Body.String(), "You have been logged out"))
	assert.Check(t, is.DeepEqual(map[string]int{"sp.example.com": 1, "sp2.example.com": 1}, pt.received))
	assert.Check(t, !pt.sessionExists(t, session.ID))
	participants, err = pt.Server.storedSessionParticipants(session.ID)
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, 0))
	assert.Check(t, is.Len(pt.cookies, 0), "the session and logout state cookies are expired")
}

func TestLogoutWithoutSession(t *testing.T) {
	pt := newPropagationServerTest(t)
	w := pt.serve(httptest.NewRequest(http.MethodPost, "https://idp.example.com/logout", nil))
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Contains(w.Body.String(), "not logged in"))
}

func TestSPInitiatedLogoutPropagates(t *testing.T) {
	pt := newPropagationServerTest(t)
	session, cookie := pt.login(t, "alice", "alice@example.com")
	pt.cookies[cookie.Name] = cookie
	pt.sso(t, &pt.SP)
	pt.sso(t, &pt.sp2)

	logoutRequest, err := pt.SP.MakeLogoutRequest(pt.Server.IDP.LogoutURL.String(), session.NameID, saml.WithSessionIndex(session.Index))
	assert.NilError(t, err)
	u, err := pt.SP.RedirectLogoutRequestURL(logoutRequest, "relay")
	assert.NilError(t, err)

	w := pt.run(t, pt.serve(httptest.NewRequest(http.MethodGet, u.String(), nil)))
	assert.Check(t, is.DeepEqual(map[string]int{"sp2.example.com": 1}, pt.received))
	assert.Check(t, !pt.sessionExists(t, session.ID))

	r := next(t, w)
	resp, err := pt.SP.ParseLogoutResponse(r, []string{logoutRequest.ID})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(saml.StatusSuccess, resp.Status.StatusCode.Value))
	assert.Check(t, is.Nil(resp.Status.StatusCode.StatusCode))
}

func TestDeleteSessionDeletesParticipants(t *testing.T) {
	pt := newPropagationServerTest(t)
	session, cookie := pt.login(t, "alice", "alice@example.com")
	pt.cookies[cookie.Name] = cookie
	pt.sso(t, &pt.SP)
	participants, err := pt.Server.storedSessionParticipants(session.ID)
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, 1))

	w := httptest.NewRecorder()
	pt.Server.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "https://idp.example.com/sessions/"+url.PathEscape(session.ID), nil))
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	participants, err = pt.Server.storedSessionParticipants(session.ID)
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, 0))
}
