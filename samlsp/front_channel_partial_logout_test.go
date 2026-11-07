package samlsp

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/testsaml"
)

// newFrontChannelLogoutTest returns a logoutTest whose IDP answers logout
// only with responseBinding, and whose OnError records the errors it is
// passed in errs.
func newFrontChannelLogoutTest(t *testing.T, responseBinding string, errs *[]error) *logoutTest {
	t.Helper()
	var lt *logoutTest
	if responseBinding == saml.HTTPPostSimpleSignBinding {
		lt = newSimpleSignLogoutTest(t, responseBinding)
	} else {
		lt = newLogoutTest(t, responseBinding)
	}
	lt.m.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
		*errs = append(*errs, err)
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return lt
}

// sentLogoutResponse returns the LogoutResponse that resp sends the IDP
// with binding. A SimpleSign response is checked to be signed by the SP.
func sentLogoutResponse(t *testing.T, lt *logoutTest, binding string, resp *httptest.ResponseRecorder) *saml.LogoutResponse {
	t.Helper()
	var message []byte
	switch binding {
	case saml.HTTPRedirectBinding:
		assert.Assert(t, is.Equal(resp.Code, http.StatusFound))
		location, err := url.Parse(resp.Header().Get("Location"))
		assert.NilError(t, err)
		message, err = testsaml.ParseRedirectResponse(location)
		assert.NilError(t, err)
	case saml.HTTPPostSimpleSignBinding:
		message, _ = checkSimpleSignForm(t, resp, "SAMLResponse", "SAMLResponseForm", lt.m.ServiceProvider.Certificate)
	default:
		assert.Assert(t, is.Equal(resp.Code, http.StatusOK), resp.Body.String())
		var err error
		message, err = base64.StdEncoding.DecodeString(simpleSignFormFields(resp.Body.String())["SAMLResponse"])
		assert.NilError(t, err)
	}
	var logoutResponse saml.LogoutResponse
	assert.NilError(t, xml.Unmarshal(message, &logoutResponse))
	assert.Check(t, is.Equal(logoutResponse.InResponseTo, "id-idp-logout-request"))
	return &logoutResponse
}

// frontChannelLogoutBindings are the bindings ServeSLO answers a
// front-channel LogoutRequest with.
var frontChannelLogoutBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding}

// When the other copies of the session cannot be ended because the
// revocation store is full, the browser's session is still deleted, the
// failure is reported, and the IdP is answered over the same binding with
// Success and the second-level status PartialLogout (saml-core-2.0-os
// §3.7.3.2).
func TestServeSLOFrontChannelPartialLogout(t *testing.T) {
	for _, binding := range frontChannelLogoutBindings {
		t.Run(binding, func(t *testing.T) {
			var errs []error
			lt := newFrontChannelLogoutTest(t, binding, &errs)
			provider := lt.m.Session.(CookieSessionProvider)
			store := NewMemorySessionRevocationStore(1)
			assert.NilError(t, store.Revoke(t.Context(), "other", logoutTestNow, logoutTestNow.Add(time.Hour)))
			provider.Revocations = store
			lt.m.Session = provider

			resp := lt.postToSLO(url.Values{
				"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
				"RelayState":  {"idp-state"},
			}, lt.sessionCookie(t, "index-1"))

			assertSessionDeleted(t, lt, resp)
			logoutResponse := sentLogoutResponse(t, lt, binding, resp)
			assert.Check(t, is.Equal(logoutResponse.Status.StatusCode.Value, saml.StatusSuccess))
			assert.Assert(t, logoutResponse.Status.StatusCode.StatusCode != nil)
			assert.Check(t, is.Equal(logoutResponse.Status.StatusCode.StatusCode.Value, saml.StatusPartialLogout))
			assert.Assert(t, is.Len(errs, 1))
			assert.Check(t, is.ErrorIs(errs[0], errFrontChannelLogoutNotTerminated))
			assert.Check(t, is.ErrorIs(errs[0], ErrSessionRevocationStoreFull))
		})
	}
}

// When the other copies were ended, or the session provider cannot end
// sessions on the server at all, the IdP is answered with a plain Success:
// the browser's session has ended, and nothing more was promised.
func TestServeSLOFrontChannelPlainSuccess(t *testing.T) {
	providers := []struct {
		name  string
		setup func(provider CookieSessionProvider) SessionProvider
	}{
		{"revocation store", func(provider CookieSessionProvider) SessionProvider { return provider }},
		{"cookie provider without a store", func(provider CookieSessionProvider) SessionProvider {
			provider.Revocations = nil
			return provider
		}},
		{"provider without TerminateSessions", func(CookieSessionProvider) SessionProvider { return staticSessionProvider{} }},
	}
	for _, binding := range frontChannelLogoutBindings {
		for _, tc := range providers {
			t.Run(binding+"/"+tc.name, func(t *testing.T) {
				var errs []error
				lt := newFrontChannelLogoutTest(t, binding, &errs)
				cookie := lt.sessionCookie(t, "index-1")
				lt.m.Session = tc.setup(lt.m.Session.(CookieSessionProvider))

				resp := lt.postToSLO(url.Values{
					"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
					"RelayState":  {"idp-state"},
				}, cookie)

				logoutResponse := sentLogoutResponse(t, lt, binding, resp)
				assert.Check(t, is.Equal(logoutResponse.Status.StatusCode.Value, saml.StatusSuccess))
				assert.Check(t, is.Nil(logoutResponse.Status.StatusCode.StatusCode))
				assert.Check(t, is.Len(errs, 0))
			})
		}
	}
}
