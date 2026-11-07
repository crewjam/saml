package samlsp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// A tracked request outlives saml.MaxIssueDelay: a user who spends several
// minutes at the IdP (MFA, password reset) still comes back to a request the
// ACS can find.
func TestTrackedRequestOutlivesMaxIssueDelay(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	defer func(old func() time.Time) { saml.TimeNow = old }(saml.TimeNow)
	saml.TimeNow = func() time.Time { return now }

	for _, tc := range []struct {
		name   string
		maxAge time.Duration
		wait   time.Duration
		found  bool
	}{
		{"default after five minutes", 0, 5 * time.Minute, true},
		{"default after the default", 0, DefaultTrackedRequestMaxAge + time.Second, false},
		{"configured", time.Minute, 2 * time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				URL:                  url.URL{Scheme: "https", Host: "sp.example.com"},
				Key:                  covRSAKey(t),
				TrackedRequestMaxAge: tc.maxAge,
			}
			sp := DefaultServiceProvider(opts)
			tracker := DefaultRequestTracker(opts, &sp)
			want := trackedRequestMaxAge(opts)

			saml.TimeNow = func() time.Time { return now }
			w := httptest.NewRecorder()
			index, err := tracker.TrackRequest(w, httptest.NewRequest(http.MethodGet, "https://sp.example.com/app", nil), "id-1")
			assert.Assert(t, err)
			cookies := w.Result().Cookies()
			assert.Assert(t, is.Len(cookies, 1))
			assert.Check(t, is.Equal(int(want.Seconds()), cookies[0].MaxAge))

			saml.TimeNow = func() time.Time { return now.Add(tc.wait) }
			r := httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/acs", nil)
			r.AddCookie(cookies[0])
			_, err = tracker.GetTrackedRequest(r, index)
			assert.Check(t, is.Equal(tc.found, err == nil), "err=%v", err)
		})
	}
}
