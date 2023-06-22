package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

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
