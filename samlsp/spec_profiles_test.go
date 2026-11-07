package samlsp

// Tests pinning behavior of the samlsp middleware required by the SAML V2.0
// Profiles specification (saml-profiles-2.0-os).

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/testsaml"
)

// saml-profiles §4.1.4.5: "The service provider MUST ensure that bearer
// assertions are not replayed, by maintaining the set of used ID values for
// the length of time for which the assertion would be considered valid".
// Options.ReplayCache is passed to the ServiceProvider, and MemoryReplayCache
// refuses an ID it has already recorded until the expiry it was given.
func TestSpecProfile_4_1_4_5_ReplayCacheOption(t *testing.T) {
	cache := NewMemoryReplayCache(10)
	m, err := New(Options{
		URL:         mustParseURL("https://sp.example.com/"),
		IDPMetadata: &saml.EntityDescriptor{EntityID: "https://idp.example.com/"},
		ReplayCache: cache,
	})
	assert.NilError(t, err)
	assert.Check(t, m.ServiceProvider.ReplayCache == saml.AssertionReplayCache(cache))

	expires := saml.TimeNow().Add(time.Hour)
	assert.NilError(t, cache.Consume("id-assertion", expires))
	assert.Check(t, errors.Is(cache.Consume("id-assertion", expires), saml.ErrAssertionReplayed))
	assert.NilError(t, cache.Consume("id-other-assertion", expires))
}

// saml-profiles §4.1.4.3: the SP MUST "Verify that the InResponseTo attribute
// in the bearer <SubjectConfirmationData> equals the ID of its original
// <AuthnRequest> message, unless the response is unsolicited". The ACS
// refuses a response to a request this browser has no tracked request for,
// when unsolicited responses are not allowed, and grants no session.
func TestSpecProfile_4_1_4_3_ACSRejectsUntrackedResponse(t *testing.T) {
	oldTimeNow, oldClock, oldRandReader := saml.TimeNow, saml.Clock, saml.RandReader
	t.Cleanup(func() { saml.TimeNow, saml.Clock, saml.RandReader = oldTimeNow, oldClock, oldRandReader })
	test := NewMiddlewareTest(t)
	v := url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")

	for name, cookie := range map[string]string{
		"no tracked request":    "",
		"other tracked request": "saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6=" + test.makeTrackedRequest("id-other-request"),
	} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if cookie != "" {
				req.Header.Set("Cookie", cookie)
			}
			resp := httptest.NewRecorder()
			test.Middleware.ServeHTTP(resp, req)
			assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
			assert.Check(t, is.Equal("", resp.Header().Get("Set-Cookie")))
		})
	}
}

// saml-profiles §4.4.3.1: "The <LogoutRequest> message MUST be signed if the
// HTTP POST or Redirect binding is used", and the session participant issues
// it "containing one or more applicable <SessionIndex> elements". §4.4.4.1:
// the Issuer "MUST be present". With request signing enabled,
// HandleStartLogout sends a signed LogoutRequest carrying the SessionIndex
// of the session.
func TestSpecProfile_4_4_3_1_SignedLogoutRequestWithSessionIndex(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	lt.m.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/logout", nil)
	req.AddCookie(lt.sessionCookie(t, "session-index-1"))
	resp := httptest.NewRecorder()
	lt.m.HandleStartLogout(resp, req)
	assert.Assert(t, is.Equal(http.StatusFound, resp.Code))

	location, err := url.Parse(resp.Header().Get("Location"))
	assert.NilError(t, err)
	assert.Check(t, location.Query().Get("Signature") != "")
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, location.Query().Get("SigAlg")))

	buf, err := testsaml.ParseRedirectRequest(location)
	assert.NilError(t, err)
	var logoutRequest saml.LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &logoutRequest))
	assert.Assert(t, logoutRequest.Issuer != nil)
	assert.Check(t, is.Equal(lt.m.ServiceProvider.Metadata().EntityID, logoutRequest.Issuer.Value))
	assert.Assert(t, logoutRequest.SessionIndex != nil)
	assert.Check(t, is.Equal("session-index-1", logoutRequest.SessionIndex.Value))
}

// saml-profiles §4.4.3.4: the session participant "MUST issue a
// <LogoutResponse> message ... to the requesting identity provider", which
// "MUST be signed if the HTTP POST or Redirect binding is used". With request
// signing enabled, a valid IdP LogoutRequest is answered with a signed
// LogoutResponse InResponseTo it.
func TestSpecProfile_4_4_3_4_SignedLogoutResponseToIdP(t *testing.T) {
	lt := newLogoutTest(t, saml.HTTPRedirectBinding)
	lt.m.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	logoutRequest := lt.logoutRequest()
	form := url.Values{"SAMLRequest": {lt.signedIDPMessage(t, logoutRequest.Element())}, "RelayState": {"rs"}}
	resp := lt.postToSLO(form, lt.sessionCookie(t, "session-index-1"))
	assert.Assert(t, is.Equal(http.StatusFound, resp.Code), resp.Body.String())

	location, err := url.Parse(resp.Header().Get("Location"))
	assert.NilError(t, err)
	assert.Check(t, location.Query().Get("Signature") != "")
	assert.Check(t, is.Equal("rs", location.Query().Get("RelayState")))
	buf, err := testsaml.ParseRedirectResponse(location)
	assert.NilError(t, err)
	var logoutResponse saml.LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &logoutResponse))
	assert.Check(t, is.Equal(logoutRequest.ID, logoutResponse.InResponseTo))
	assert.Assert(t, logoutResponse.Issuer != nil)
	assert.Check(t, is.Equal(lt.m.ServiceProvider.Metadata().EntityID, logoutResponse.Issuer.Value))
}
