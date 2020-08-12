package samlsp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/crewjam/saml"
)

func TestCookieSameSite(t *testing.T) {
	t.Parallel()

	csp := CookieSessionProvider{
		Name:   "token",
		Domain: "localhost",
		Codec: DefaultSessionCodec(Options{
			Key: NewMiddlewareTest().Key,
		}),
	}

	getSessionCookie := func(tb testing.TB) *http.Cookie {
		resp := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := csp.CreateSession(resp, req, &saml.Assertion{})
		assert.NoError(t, err)

		cookies := resp.Result().Cookies()
		assert.Len(t, cookies, 1, "Expected to have a cookie set")

		return cookies[0]
	}

	t.Run("no same site", func(t *testing.T) {
		cookie := getSessionCookie(t)
		assert.EqualValues(t, http.SameSite(0), cookie.SameSite)
	})

	t.Run("with same site", func(t *testing.T) {
		csp.SameSite = http.SameSiteStrictMode
		cookie := getSessionCookie(t)
		assert.EqualValues(t, http.SameSiteStrictMode, cookie.SameSite)
	})
}
