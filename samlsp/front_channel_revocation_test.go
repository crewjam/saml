package samlsp

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// redirectToSLO sends el, a message from the IDP, to the SLO endpoint as a
// SAMLRequest with the HTTP-Redirect binding, signed by the IDP, with the
// RelayState "idp-state".
func (lt *logoutTest) redirectToSLO(t *testing.T, el *etree.Element, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	message, err := doc.WriteToBytes()
	assert.NilError(t, err)
	var deflated bytes.Buffer
	fw, err := flate.NewWriter(&deflated, flate.DefaultCompression)
	assert.NilError(t, err)
	_, err = fw.Write(message)
	assert.NilError(t, err)
	assert.NilError(t, fw.Close())

	query := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(deflated.Bytes())) +
		"&RelayState=" + url.QueryEscape("idp-state") +
		"&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	digest := sha256.Sum256([]byte(query))
	signature, err := rsa.SignPKCS1v15(rand.Reader, lt.idpKey, crypto.SHA256, digest[:])
	assert.NilError(t, err)
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))

	req := httptest.NewRequest(http.MethodGet, lt.m.ServiceProvider.SloURL.String()+"?"+query, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	lt.m.ServeHTTP(resp, req)
	return resp
}

// frontChannelLogout sends the IdP's LogoutRequest for alice, with the
// given SessionIndexes, to the SLO endpoint through the browser that holds
// cookie, with binding.
func (app *soapLogoutApp) frontChannelLogout(t *testing.T, binding string, cookie *http.Cookie, sessionIndexes ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := app.lt.logoutRequest()
	saml.WithSessionIndexes(sessionIndexes...)(req)
	switch binding {
	case saml.HTTPRedirectBinding:
		return app.lt.redirectToSLO(t, req.Element(), cookie)
	case saml.HTTPPostSimpleSignBinding:
		return app.lt.postToSLO(app.lt.simpleSignIDPForm(t, "SAMLRequest", req.Element(), "idp-state"), cookie)
	default:
		return app.lt.postToSLO(url.Values{
			"SAMLRequest": {app.lt.signedIDPMessage(t, req.Element())},
			"RelayState":  {"idp-state"},
		}, cookie)
	}
}

// checkLogoutSuccess checks that resp deletes the session cookie and posts
// the IdP a LogoutResponse with the status Success.
func checkLogoutSuccess(t *testing.T, lt *logoutTest, resp *httptest.ResponseRecorder) {
	t.Helper()
	assertSessionDeleted(t, lt, resp)
	assert.Assert(t, is.Equal(resp.Code, http.StatusOK), resp.Body.String())
	fields := simpleSignFormFields(resp.Body.String())
	buf, err := base64.StdEncoding.DecodeString(fields["SAMLResponse"])
	assert.NilError(t, err)
	var logoutResponse saml.LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &logoutResponse))
	assert.Check(t, is.Equal(logoutResponse.InResponseTo, "id-idp-logout-request"))
	assert.Check(t, is.Equal(logoutResponse.Status.StatusCode.Value, saml.StatusSuccess))
}

// A LogoutRequest the IdP sends through the browser ends the named session
// in other browsers too: a copy of the session with the same SessionIndex
// is refused. The user's other sessions, and other users', are not
// affected.
func TestServeSLOFrontChannelRevokesOtherCopies(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		t.Run(binding, func(t *testing.T) {
			app := newSOAPLogoutApp(t)
			alice := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
			aliceElsewhere := app.cookie(t, "alice@example.com", logoutTestNow.Add(-time.Minute), "index-1")
			aliceOther := app.cookie(t, "alice@example.com", logoutTestNow, "index-2")
			bob := app.cookie(t, "bob@example.com", logoutTestNow, "index-1")
			for _, c := range []*http.Cookie{alice, aliceElsewhere, aliceOther, bob} {
				assert.Check(t, is.Equal(app.get(t, c), http.StatusOK))
			}

			resp := app.frontChannelLogout(t, binding, alice, "index-1")
			assert.Check(t, is.Len(app.errors, 0))
			assertSessionDeleted(t, app.lt, resp)

			assert.Check(t, is.Equal(app.get(t, aliceElsewhere), http.StatusFound))
			assert.Check(t, is.Equal(app.get(t, alice), http.StatusFound))
			assert.Check(t, is.Equal(app.get(t, aliceOther), http.StatusOK))
			assert.Check(t, is.Equal(app.get(t, bob), http.StatusOK))
			_, err := app.lt.m.Session.GetSession(requestWithCookie(aliceElsewhere))
			assert.Check(t, is.ErrorIs(err, ErrSessionRevoked))
		})
	}
}

// A front-channel LogoutRequest without a SessionIndex ends every session
// of its NameID issued before it, but not a later login or other users'
// sessions.
func TestServeSLOFrontChannelWithoutSessionIndex(t *testing.T) {
	app := newSOAPLogoutApp(t)
	alice1 := app.cookie(t, "alice@example.com", logoutTestNow.Add(-10*time.Minute), "index-1")
	alice2 := app.cookie(t, "alice@example.com", logoutTestNow, "index-2")
	aliceNoIndex := app.cookie(t, "alice@example.com", logoutTestNow)
	bob := app.cookie(t, "bob@example.com", logoutTestNow, "index-1")

	resp := app.frontChannelLogout(t, saml.HTTPPostBinding, alice1)
	checkLogoutSuccess(t, app.lt, resp)
	assert.Check(t, is.Len(app.errors, 0))

	for _, c := range []*http.Cookie{alice1, alice2, aliceNoIndex} {
		assert.Check(t, is.Equal(app.get(t, c), http.StatusFound))
	}
	assert.Check(t, is.Equal(app.get(t, bob), http.StatusOK))

	later := logoutTestNow.Add(time.Second)
	saml.TimeNow = func() time.Time { return later }
	assert.Check(t, is.Equal(app.get(t, app.cookie(t, "alice@example.com", later, "index-3")), http.StatusOK))
}

// When the session provider cannot end sessions on the server, a
// front-channel LogoutRequest still deletes the browser's session and is
// answered with Success, as before: that session, the one the IdP sent,
// has ended.
func TestServeSLOFrontChannelProviderCannotTerminate(t *testing.T) {
	t.Run("provider without TerminateSessions", func(t *testing.T) {
		app := newSOAPLogoutApp(t)
		alice := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
		app.lt.m.Session = staticSessionProvider{}
		resp := app.frontChannelLogout(t, saml.HTTPPostBinding, alice, "index-1")
		assert.Check(t, is.Len(app.errors, 0))
		assert.Check(t, is.Equal(resp.Code, http.StatusOK))
		assert.Check(t, is.Contains(resp.Body.String(), `name="SAMLResponse"`))
	})
	t.Run("cookie provider without a store", func(t *testing.T) {
		app := newSOAPLogoutApp(t)
		alice := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
		aliceElsewhere := app.cookie(t, "alice@example.com", logoutTestNow.Add(-time.Minute), "index-1")
		provider := app.lt.m.Session.(CookieSessionProvider)
		provider.Revocations = nil
		app.lt.m.Session = provider

		checkLogoutSuccess(t, app.lt, app.frontChannelLogout(t, saml.HTTPPostBinding, alice, "index-1"))
		assert.Check(t, is.Len(app.errors, 0))
		// Only the browser's own cookie was deleted.
		assert.Check(t, is.Equal(app.get(t, aliceElsewhere), http.StatusOK))
	})
	t.Run("store failure", func(t *testing.T) {
		app := newSOAPLogoutApp(t)
		alice := app.cookie(t, "alice@example.com", logoutTestNow, "index-1")
		provider := app.lt.m.Session.(CookieSessionProvider)
		store := NewMemorySessionRevocationStore(1)
		assert.NilError(t, store.Revoke(t.Context(), "other", logoutTestNow, logoutTestNow.Add(time.Hour)))
		provider.Revocations = store
		app.lt.m.Session = provider

		// The failure is reported, and the IdP still told Success: the
		// session it sent has ended.
		checkLogoutSuccess(t, app.lt, app.frontChannelLogout(t, saml.HTTPPostBinding, alice, "index-1"))
		assert.Assert(t, is.Len(app.errors, 1))
		assert.Check(t, is.ErrorIs(app.errors[0], errFrontChannelLogoutNotTerminated))
		assert.Check(t, is.ErrorIs(app.errors[0], ErrSessionRevocationStoreFull))
	})
}
