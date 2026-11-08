package samlsp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// The URI of a tracked request is the request-target of the request that
// started the login, which the client chooses. After the login the user is
// sent back there only if it is a path on this site: a request for
// "//evil.example/x" (which reaches RequireAccount when nothing in front of
// it cleans the path) must not make the ACS redirect the newly logged-in
// user to evil.example.
func TestMiddlewareTrackedRequestRedirectIsLocal(t *testing.T) {
	for path, want := range map[string]string{
		"/landing?x=1":      "/landing?x=1",
		"//evil.example/x":  "/default",
		"///evil.example/x": "/default",
		"/\\evil.example/x": "/%5Cevil.example/x", // URL.String escapes the backslash
	} {
		t.Run(path, func(t *testing.T) {
			test := NewMiddlewareTest(t)

			start := httptest.NewRequest(http.MethodGet, "/", nil)
			start.URL = &url.URL{Path: path}
			if before, after, ok := strings.Cut(path, "?"); ok {
				start.URL = &url.URL{Path: before, RawQuery: after}
			}
			startRec := httptest.NewRecorder()
			index, err := test.Middleware.RequestTracker.TrackRequest(startRec, start, "id-abc")
			assert.NilError(t, err)

			form := url.Values{"RelayState": {index}}
			req := httptest.NewRequest(http.MethodPost, "/saml2/acs", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, c := range startRec.Result().Cookies() {
				req.AddCookie(c)
			}
			assert.NilError(t, req.ParseForm())

			rec := httptest.NewRecorder()
			test.Middleware.CreateSessionFromAssertion(rec, req, &saml.Assertion{}, "/default")
			assert.Check(t, is.Equal(http.StatusFound, rec.Code))
			assert.Check(t, is.Equal(want, rec.Header().Get("Location")))
		})
	}
}
