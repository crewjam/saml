package samlsp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// HandleStartLogout ends the session on the server as well as deleting the
// cookie, so a copy of the session token is refused afterwards. Sessions of
// the same user from other IdP sessions (other devices) are kept. Logging
// out of a session without a SessionIndex revokes nothing.
func TestHandleStartLogoutRevokesSession(t *testing.T) {
	for _, bindings := range [][]string{{saml.HTTPRedirectBinding}, nil} {
		lt := newLogoutTest(t, bindings...)
		loggedOut := lt.sessionCookie(t, "idx-1")
		otherDevice := lt.sessionCookie(t, "idx-2")

		req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
		req.AddCookie(loggedOut)
		resp := httptest.NewRecorder()
		lt.m.HandleStartLogout(resp, req)
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))

		getSession := func(c *http.Cookie) error {
			r := httptest.NewRequest(http.MethodGet, "https://sp.example.com/app", nil)
			r.AddCookie(c)
			_, err := lt.m.Session.GetSession(r)
			return err
		}
		err := getSession(loggedOut)
		assert.Check(t, errors.Is(err, ErrSessionRevoked), "bindings %v: %v", bindings, err)
		assert.Check(t, getSession(otherDevice), "bindings %v", bindings)
	}

	lt := newLogoutTest(t)
	noIndex := lt.sessionCookie(t)
	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(noIndex)
	lt.m.HandleStartLogout(httptest.NewRecorder(), req)
	r := httptest.NewRequest(http.MethodGet, "https://sp.example.com/app", nil)
	r.AddCookie(noIndex)
	_, err := lt.m.Session.GetSession(r)
	assert.Check(t, err)
}

// With RequirePOSTToStartLogout, a GET (such as a cross-site link or image)
// does not log the user out; a POST does.
func TestHandleStartLogoutRequirePOST(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	lt.m.RequirePOSTToStartLogout = true
	cookie := lt.sessionCookie(t, "idx-1")

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)
	assert.Check(t, is.Equal(http.StatusMethodNotAllowed, resp.Code))
	assert.Check(t, is.Equal(http.MethodPost, resp.Header().Get("Allow")))
	assert.Check(t, is.Len(resp.Result().Cookies(), 0))

	req = httptest.NewRequest(http.MethodPost, "https://sp.example.com/logout", nil)
	req.AddCookie(cookie)
	resp = httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
}
