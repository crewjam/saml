package samlsp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A RelayStateFunc may return a value that is not a valid cookie name, such
// as a path with a query. The request is still tracked: the cookie name
// encodes the value, while the RelayState sent to the IdP stays as returned.
func TestCookieRequestTrackerRelayStateFunc(t *testing.T) {
	for _, relayState := range []string{
		"/dashboard?x=1",
		"https://sp.example.com/a b",
		"~already-marked",
		"plain-token.ok",
	} {
		t.Run(relayState, func(t *testing.T) {
			opts := Options{
				URL:            url.URL{Scheme: "https", Host: "sp.example.com"},
				Key:            covRSAKey(t),
				RelayStateFunc: func(http.ResponseWriter, *http.Request) string { return relayState },
			}
			sp := DefaultServiceProvider(opts)
			tracker := DefaultRequestTracker(opts, &sp)

			w := httptest.NewRecorder()
			index, err := tracker.TrackRequest(w, httptest.NewRequest(http.MethodGet, "https://sp.example.com/app", nil), "id-1")
			assert.Assert(t, err)
			assert.Check(t, is.Equal(relayState, index))

			cookies := w.Result().Cookies()
			assert.Assert(t, is.Len(cookies, 1))
			assert.Check(t, cookies[0].Valid())

			r := httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/acs", nil)
			r.AddCookie(cookies[0])
			tr, err := tracker.GetTrackedRequest(r, index)
			assert.Assert(t, err)
			assert.Check(t, is.Equal("id-1", tr.SAMLRequestID))
			assert.Check(t, is.Equal(relayState, tr.Index))

			all := tracker.GetTrackedRequests(r)
			assert.Assert(t, is.Len(all, 1))
			assert.Check(t, is.Equal(relayState, all[0].Index))

			w = httptest.NewRecorder()
			assert.NilError(t, tracker.StopTrackingRequest(w, r, index))
			expired := w.Result().Cookies()
			assert.Assert(t, is.Len(expired, 1))
			assert.Check(t, is.Equal(cookies[0].Name, expired[0].Name))
		})
	}
}

// The default index is used in the cookie name as-is, so cookies set before
// the encoding was introduced are still found.
func TestCookieRequestTrackerDefaultIndexName(t *testing.T) {
	tracker := CookieRequestTracker{NamePrefix: "saml_"}
	assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5Q", tracker.cookieName("KCosLjAyNDY4Ojw-QEJERkhKTE5Q")))
	assert.Check(t, tracker.cookieName("~x") != tracker.cookieName("x"))
}
