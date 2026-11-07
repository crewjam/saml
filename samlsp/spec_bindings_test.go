package samlsp

import (
	"errors"
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

// Tests pinning behavior required by the OASIS SAML V2.0 Bindings
// specification (saml-bindings-2.0-os) at the HTTP level of the middleware.

var specRelayStateInputRe = regexp.MustCompile(`<input type="hidden" name="RelayState" value="([^"]*)" />`)

// specMiddlewareTest is NewMiddlewareTest, restoring the package globals it
// changes when the test ends.
func specMiddlewareTest(t *testing.T) *MiddlewareTest {
	t.Helper()
	oldTimeNow, oldClock, oldRandReader := saml.TimeNow, saml.Clock, saml.RandReader
	t.Cleanup(func() {
		saml.TimeNow, saml.Clock, saml.RandReader = oldTimeNow, oldClock, oldRandReader
	})
	return NewMiddlewareTest(t)
}

// saml-bindings-2.0-os §3.4.3 and §3.5.3: RelayState "MUST NOT exceed 80
// bytes in length and SHOULD be integrity protected". The default request
// tracker uses a random index (integrity protected by the signed tracking
// cookie) that fits the limit, for both the HTTP-Redirect and the HTTP-POST
// bindings. §3.4.5 step 2: the HTTP-Redirect request is sent with status 302
// or 303.
func TestSpecBinding_3_4_3_DefaultRelayStateWithin80Bytes(t *testing.T) {
	t.Run("HTTP-Redirect", func(t *testing.T) {
		test := specMiddlewareTest(t)
		w := httptest.NewRecorder()
		test.Middleware.HandleStartAuthFlow(w, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, w.Code == http.StatusFound || w.Code == http.StatusSeeOther, "status %d", w.Code)
		loc, err := url.Parse(w.Header().Get("Location"))
		assert.NilError(t, err)
		relayState := loc.Query().Get("RelayState")
		assert.Check(t, relayState != "")
		assert.Check(t, len(relayState) <= 80, "RelayState is %d bytes", len(relayState))
		assert.Check(t, loc.Query().Get("SAMLRequest") != "")
	})

	t.Run("HTTP-POST", func(t *testing.T) {
		test := specMiddlewareTest(t)
		test.Middleware.Binding = saml.HTTPPostBinding
		w := httptest.NewRecorder()
		test.Middleware.HandleStartAuthFlow(w, httptest.NewRequest(http.MethodGet, "/frob", nil))
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
		m := specRelayStateInputRe.FindStringSubmatch(w.Body.String())
		assert.Assert(t, m != nil, w.Body.String())
		relayState := html.UnescapeString(m[1])
		assert.Check(t, relayState != "")
		assert.Check(t, len(relayState) <= 80, "RelayState is %d bytes", len(relayState))
	})
}

// saml-bindings-2.0-os §3.4.3 and §3.5.3: the SAML responder "MUST place the
// exact data it received with the request into the corresponding RelayState
// parameter in the response". Checked for the LogoutResponse the middleware
// returns to an IdP-initiated LogoutRequest, with a RelayState that needs URL
// and HTML escaping, for both response bindings. §3.4.5: the HTTP-Redirect
// response uses status 302 or 303; §3.5.4: the HTTP-POST form posts to the
// IdP's endpoint.
func TestSpecBinding_3_4_3_SLOResponseEchoesExactRelayState(t *testing.T) {
	relayState := `a b+c&d=e"f'g<h>%2F/` + strings.Repeat("z", 20)

	t.Run("HTTP-Redirect", func(t *testing.T) {
		lt := newLogoutTest(t, saml.HTTPRedirectBinding)
		resp := lt.postToSLO(url.Values{
			"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
			"RelayState":  {relayState},
		}, lt.sessionCookie(t, "x"))
		assert.Check(t, resp.Code == http.StatusFound || resp.Code == http.StatusSeeOther, "status %d", resp.Code)
		loc, err := url.Parse(resp.Header().Get("Location"))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(logoutTestIDPRedirect, loc.Scheme+"://"+loc.Host+loc.Path))
		assert.Check(t, is.DeepEqual([]string{relayState}, loc.Query()["RelayState"]))
	})

	t.Run("HTTP-POST", func(t *testing.T) {
		lt := newLogoutTest(t, saml.HTTPPostBinding)
		resp := lt.postToSLO(url.Values{
			"SAMLRequest": {lt.signedIDPMessage(t, lt.logoutRequest().Element())},
			"RelayState":  {relayState},
		}, lt.sessionCookie(t, "x"))
		assert.Check(t, is.Equal(http.StatusOK, resp.Code))
		body := resp.Body.String()
		assert.Check(t, is.Contains(body, `method="post" action="`+logoutTestIDPPost+`"`))
		assert.Check(t, !strings.Contains(body, `"f'g<h>`), "RelayState must be HTML-escaped")
		m := specRelayStateInputRe.FindStringSubmatch(body)
		assert.Assert(t, m != nil, body)
		assert.Check(t, is.Equal(relayState, html.UnescapeString(m[1])))
	})
}

// saml-bindings-2.0-os §3.4.3 and §3.5.3: RelayState "MUST NOT exceed 80
// bytes in length". A RelayStateFunc result longer than that is refused
// before a tracking cookie is set or a request is sent; 80 bytes are used
// as is.
func TestSpecBinding_3_4_3_RelayStateFuncAtMost80Bytes(t *testing.T) {
	tracker := covCookieRequestTracker(t)
	relayState := strings.Repeat("r", saml.MaxRelayStateLength)
	tracker.RelayStateFunc = func(http.ResponseWriter, *http.Request) string { return relayState }

	rec := httptest.NewRecorder()
	index, err := tracker.TrackRequest(rec, httptest.NewRequest(http.MethodGet, "/frob", nil), "id-1")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(relayState, index))

	relayState += "r"
	rec = httptest.NewRecorder()
	_, err = tracker.TrackRequest(rec, httptest.NewRequest(http.MethodGet, "/frob", nil), "id-1")
	assert.Check(t, errors.Is(err, saml.ErrRelayStateTooLong), "%v", err)
	assert.Check(t, is.Equal("", rec.Header().Get("Set-Cookie")))
}
