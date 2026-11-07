package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

func TestCookieSameSite(t *testing.T) {
	t.Parallel()

	csp := CookieSessionProvider{
		Name:   "token",
		Domain: "localhost",
		Codec: DefaultSessionCodec(Options{
			Key: NewMiddlewareTest(t).Key,
		}),
	}

	getSessionCookie := func(tb testing.TB) *http.Cookie {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := csp.CreateSession(resp, req, &saml.Assertion{})
		assert.Check(tb, err)

		result := resp.Result()
		cookies := result.Cookies()
		assert.Check(tb, is.Len(cookies, 1), "Expected to have a cookie set")
		assert.Check(tb, result.Body.Close())

		return cookies[0]
	}

	t.Run("no same site", func(t *testing.T) {
		cookie := getSessionCookie(t)
		assert.Check(t, is.Equal(http.SameSite(0), cookie.SameSite))
	})

	t.Run("with same site", func(t *testing.T) {
		csp.SameSite = http.SameSiteStrictMode
		cookie := getSessionCookie(t)
		assert.Check(t, is.Equal(http.SameSiteStrictMode, cookie.SameSite))
	})
}

func TestDefaultSessionProviderCookieDomain(t *testing.T) {
	key := NewMiddlewareTest(t).Key

	type wantCookie struct {
		domain  string
		expired bool
	}
	testCases := []struct {
		name         string
		cookieDomain string
		wantCreate   []wantCookie
		wantDelete   []wantCookie
	}{
		{
			name: "default is host-only and expires the legacy cookie",
			wantCreate: []wantCookie{
				{domain: "app.example.com", expired: true},
				{domain: ""},
			},
			wantDelete: []wantCookie{
				{domain: "", expired: true},
				{domain: "app.example.com", expired: true},
			},
		},
		{
			name:         "explicit parent domain",
			cookieDomain: "example.com",
			wantCreate: []wantCookie{
				{domain: "app.example.com", expired: true},
				{domain: "example.com"},
			},
			wantDelete: []wantCookie{
				{domain: "example.com", expired: true},
				{domain: "app.example.com", expired: true},
			},
		},
		{
			name:         "explicit host keeps the previous behaviour",
			cookieDomain: "app.example.com",
			wantCreate:   []wantCookie{{domain: "app.example.com"}},
			wantDelete:   []wantCookie{{domain: "app.example.com", expired: true}},
		},
	}

	check := func(t *testing.T, got []*http.Cookie, want []wantCookie) {
		t.Helper()
		assert.Assert(t, is.Len(got, len(want)))
		for i, w := range want {
			assert.Check(t, is.Equal("token", got[i].Name))
			assert.Check(t, is.Equal("/", got[i].Path))
			assert.Check(t, is.Equal(w.domain, got[i].Domain), "cookie %d", i)
			assert.Check(t, is.Equal(w.expired, got[i].Value == ""), "cookie %d", i)
			assert.Check(t, is.Equal(w.expired, !got[i].Expires.IsZero() && got[i].Expires.Before(time.Unix(2, 0))), "cookie %d", i)
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sp := DefaultSessionProvider(Options{
				URL:          mustParseURL("https://app.example.com:8443/"),
				Key:          key,
				CookieDomain: tc.cookieDomain,
			})

			resp := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			assert.Assert(t, sp.CreateSession(resp, req, &saml.Assertion{}))
			check(t, resp.Result().Cookies(), tc.wantCreate)

			resp = httptest.NewRecorder()
			req = httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: "token", Value: "abc"})
			assert.Assert(t, sp.DeleteSession(resp, req))
			check(t, resp.Result().Cookies(), tc.wantDelete)
		})
	}
}
