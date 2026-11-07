package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// DeleteSession expires the session cookie with the same Secure, HttpOnly
// and SameSite attributes as the cookie CreateSession sets, not with the
// attribute-less cookie read from the request.
func TestDeleteSessionCookieAttributes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		provider   CookieSessionProvider
		url        string
		wantSecure bool
	}{
		{
			name:       "configured",
			provider:   CookieSessionProvider{Name: "token", Domain: "example.com:8080", HTTPOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, Path: "/app"},
			url:        "http://example.com/app",
			wantSecure: true,
		},
		{
			name:       "secure over https",
			provider:   CookieSessionProvider{Name: "token", HTTPOnly: true, SameSite: http.SameSiteLaxMode},
			url:        "https://example.com/",
			wantSecure: true,
		},
		{
			name:     "plain http",
			provider: CookieSessionProvider{Name: "token", SameSite: http.SameSiteLaxMode},
			url:      "http://example.com/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.AddCookie(&http.Cookie{Name: "token", Value: "session"}) //nolint:gosec // a request cookie: only its name and value are sent
			rec := httptest.NewRecorder()
			assert.NilError(t, tc.provider.DeleteSession(rec, req))

			cookies := rec.Result().Cookies()
			assert.Assert(t, is.Len(cookies, 1))
			got := cookies[0]
			assert.Check(t, is.Equal("token", got.Name))
			assert.Check(t, is.Equal("", got.Value))
			assert.Check(t, got.Expires.Before(time.Unix(2, 0)), "expires %v", got.Expires)
			assert.Check(t, is.Equal(tc.provider.HTTPOnly, got.HttpOnly))
			assert.Check(t, is.Equal(tc.wantSecure, got.Secure))
			assert.Check(t, is.Equal(tc.provider.SameSite, got.SameSite))

			wantPath := tc.provider.Path
			if wantPath == "" {
				wantPath = "/"
			}
			assert.Check(t, is.Equal(wantPath, got.Path))
			if tc.provider.Domain != "" {
				assert.Check(t, is.Equal("example.com", got.Domain))
			}
		})
	}
}
