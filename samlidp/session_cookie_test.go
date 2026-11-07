package samlidp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The cookie that deletes the session cookie has the session cookie's
// attributes, so that browsers replace it.
func TestExpireSessionCookieMatchesSessionCookie(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	r := httptest.NewRequest(http.MethodGet, "http://idp.example.com/logout", nil)

	w := httptest.NewRecorder()
	s.expireSessionCookie(w, r)
	cookies := w.Result().Cookies()
	assert.Assert(t, is.Len(cookies, 1))
	expired := cookies[0]
	set := s.sessionCookie(r, "abc", 3600)

	assert.Check(t, is.Equal(set.Name, expired.Name))
	assert.Check(t, is.Equal(set.Path, expired.Path))
	assert.Check(t, is.Equal(set.Secure, expired.Secure))
	assert.Check(t, is.Equal(set.SameSite, expired.SameSite))
	assert.Check(t, is.Equal(set.HttpOnly, expired.HttpOnly))
	assert.Check(t, expired.MaxAge < 0)
	assert.Check(t, expired.Secure, "the IdP URL is https")
	assert.Check(t, is.Equal(http.SameSiteNoneMode, expired.SameSite))
}
