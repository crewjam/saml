package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// assertSessionKept checks that resp does not touch the session cookie.
func assertSessionKept(t *testing.T, lt *logoutTest, resp *httptest.ResponseRecorder) {
	t.Helper()
	name := lt.m.Session.(CookieSessionProvider).Name
	for _, c := range resp.Result().Cookies() {
		assert.Check(t, c.Name != name, "response sets the %s cookie: %v", name, resp.Header().Values("Set-Cookie"))
	}
}

// A LogoutRequest the IdP sends through the browser names one principal.
// Anyone can capture one about themselves, by stopping their own logout
// before the IdP redirects back to the SP, and have another user's browser
// deliver it. That browser's session is ended only if the request names it;
// the IdP is still answered, and the named sessions are still ended.
func TestServeSLOFrontChannelKeepsSessionOfAnotherPrincipal(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		t.Run(binding, func(t *testing.T) {
			app := newSOAPLogoutApp(t)
			alice := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
			bob := app.cookie(t, "bob@example.com", logoutTestNow, "index-1")

			// alice's LogoutRequest, delivered by bob's browser.
			resp := app.frontChannelLogout(t, binding, bob, "index-1")
			assert.Check(t, is.Len(app.errors, 0))
			assertSessionKept(t, app.lt, resp)
			assert.Check(t, is.Equal(app.get(t, bob), http.StatusOK))
			assert.Check(t, is.Equal(app.get(t, alice), http.StatusFound))
		})
	}

	t.Run("same NameID, another SessionIndex", func(t *testing.T) {
		app := newSOAPLogoutApp(t)
		aliceOther := app.cookie(t, "alice@example.com", logoutTestNow, "index-2")
		resp := app.frontChannelLogout(t, saml.HTTPPostBinding, aliceOther, "index-1")
		assert.Check(t, is.Len(app.errors, 0))
		assertSessionKept(t, app.lt, resp)
		assert.Check(t, is.Equal(app.get(t, aliceOther), http.StatusOK))
	})

	t.Run("named session without SessionIndex", func(t *testing.T) {
		app := newSOAPLogoutApp(t)
		aliceNoIndex := app.cookie(t, "alice@example.com", logoutTestNow)
		resp := app.frontChannelLogout(t, saml.HTTPPostBinding, aliceNoIndex, "index-1")
		checkLogoutSuccess(t, app.lt, resp)
	})

	t.Run("invalid session", func(t *testing.T) {
		app := newSOAPLogoutApp(t)
		name := app.lt.m.Session.(CookieSessionProvider).Name
		resp := app.frontChannelLogout(t, saml.HTTPPostBinding, &http.Cookie{Name: name, Value: "not-a-token", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}, "index-1")
		checkLogoutSuccess(t, app.lt, resp)
	})
}
