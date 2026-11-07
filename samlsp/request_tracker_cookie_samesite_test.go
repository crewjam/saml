package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// The IDP returns the SAML response with a cross-site POST to the ACS URL.
// Browsers treat a cookie without a SameSite attribute as SameSite=Lax and do
// not send it on that POST, so the tracked request is lost (issue #392). An
// unset SameSite must therefore become SameSite=None on a secure cookie.
func TestCookieRequestTrackerSameSite(t *testing.T) {
	for _, tc := range []struct {
		name     string
		scheme   string
		sameSite http.SameSite
		want     http.SameSite
	}{
		{"unset https", "https", 0, http.SameSiteNoneMode},
		{"default mode https", "https", http.SameSiteDefaultMode, http.SameSiteNoneMode},
		{"explicit lax https", "https", http.SameSiteLaxMode, http.SameSiteLaxMode},
		{"explicit strict https", "https", http.SameSiteStrictMode, http.SameSiteStrictMode},
		{"unset http", "http", 0, 0},
		{"explicit lax http", "http", http.SameSiteLaxMode, http.SameSiteLaxMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracker := covCookieRequestTracker(t)
			tracker.ServiceProvider = &saml.ServiceProvider{AcsURL: mustParseURL(tc.scheme + "://sp.example.com/saml/acs")}
			tracker.SameSite = tc.sameSite

			rec := httptest.NewRecorder()
			index, err := tracker.TrackRequest(rec, httptest.NewRequest(http.MethodGet, "/frob", nil), "id-1")
			assert.Assert(t, err)
			c := rec.Result().Cookies()[0]
			assert.Check(t, is.Equal(tc.want, c.SameSite))
			assert.Check(t, is.Equal(tc.scheme == "https", c.Secure))

			// The cookie that deletes the tracked request carries the same attributes.
			req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
			rec = httptest.NewRecorder()
			assert.Assert(t, tracker.StopTrackingRequest(rec, req, index))
			c = rec.Result().Cookies()[0]
			assert.Check(t, is.Equal(tc.want, c.SameSite))
			assert.Check(t, is.Equal(tc.scheme == "https", c.Secure))
		})
	}
}

// The default options, which leave CookieSameSite unset, issue a tracking
// cookie that the browser will send with the IDP's cross-site POST.
func TestDefaultRequestTrackerSameSite(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/")}
	sp := saml.ServiceProvider{AcsURL: mustParseURL("https://sp.example.com/saml/acs")}
	tracker := DefaultRequestTracker(opts, &sp)
	tracker.Codec = covTrackedRequestCodec(t)

	rec := httptest.NewRecorder()
	_, err := tracker.TrackRequest(rec, httptest.NewRequest(http.MethodGet, "/frob", nil), "id-1")
	assert.Assert(t, err)
	c := rec.Result().Cookies()[0]
	assert.Check(t, is.Equal(http.SameSiteNoneMode, c.SameSite))
	assert.Check(t, c.Secure)
}
