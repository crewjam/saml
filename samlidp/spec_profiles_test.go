package samlidp

// Tests pinning behavior of the samlidp server required by the SAML V2.0
// Profiles specification (saml-profiles-2.0-os).

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// specProfServerTest returns NewServerTest(t), restoring the package globals
// it replaces when the test ends.
func specProfServerTest(t *testing.T) *ServerTest {
	t.Helper()
	oldTimeNow, oldRandReader := saml.TimeNow, saml.RandReader
	t.Cleanup(func() { saml.TimeNow, saml.RandReader = oldTimeNow, oldRandReader })
	return NewServerTest(t)
}

// specProfAuthnRequest returns a validated IdpAuthnRequest for an
// HTTP-Redirect AuthnRequest from test.SP.
func specProfAuthnRequest(t *testing.T, test *ServerTest) *saml.IdpAuthnRequest {
	t.Helper()
	u, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	req, err := saml.NewIdpAuthnRequest(&test.Server.IDP, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	return req
}

// saml-profiles §4.1.4.2: "If the identity provider supports the Single
// Logout profile, defined in Section 4.4, any such authentication statements
// MUST include a SessionIndex attribute to enable per-session logout requests
// by the service provider." The samlidp server supports Single Logout, and a
// session it establishes at login has an Index that the assertion's
// AuthnStatement carries as its SessionIndex.
func TestSpecProfile_4_1_4_2_SessionIndexForSingleLogout(t *testing.T) {
	test := specProfServerTest(t)
	md := test.Server.IDP.Metadata()
	assert.Assert(t, len(md.IDPSSODescriptors[0].SingleLogoutServices) > 0, "the IdP advertises Single Logout")

	session, cookie := test.login(t, "alice", "alice@example.com")
	assert.Assert(t, session.Index != "")

	req := specProfAuthnRequest(t, test)
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/sso", nil)
	r.AddCookie(cookie)
	got := test.Server.GetSession(httptest.NewRecorder(), r, req)
	assert.Assert(t, got != nil)

	assert.NilError(t, saml.DefaultAssertionMaker{}.MakeAssertion(req, got))
	assert.Assert(t, is.Len(req.Assertion.AuthnStatements, 1))
	assert.Check(t, is.Equal(session.Index, req.Assertion.AuthnStatements[0].SessionIndex))
}

// saml-profiles §4.1.3.4: "the identity provider MUST establish the identity
// of the principal (unless it returns an error to the service provider)". An
// expired or unknown IdP session is not used; the user is asked to log in
// instead.
func TestSpecProfile_4_1_3_4_NoAssertionWithoutValidSession(t *testing.T) {
	test := specProfServerTest(t)
	req := specProfAuthnRequest(t, test)

	expired := &saml.Session{
		ID: "expired", NameID: "alice", Index: "idx",
		CreateTime: saml.TimeNow().Add(-2 * time.Hour),
		ExpireTime: saml.TimeNow().Add(-time.Minute),
	}
	assert.NilError(t, test.Store.Put(sessionKey(expired.ID), expired))

	for name, cookie := range map[string]string{"expired session": "expired", "unknown session": "unknown", "no session": ""} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/sso", nil)
			if cookie != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			}
			w := httptest.NewRecorder()
			assert.Check(t, test.Server.GetSession(w, r, req) == nil)
			assert.Check(t, is.Contains(w.Body.String(), `name="password"`))
		})
	}
}
