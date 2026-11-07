package samlsp

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/v3/assert"

	"github.com/crewjam/saml"
)

// A server-side request carries no scheme in r.URL, only r.TLS. The session
// cookie is Secure whenever the request arrived over TLS, both when it is set
// and when it is expired.
func TestSessionCookieSecureFromTLS(t *testing.T) {
	provider := CookieSessionProvider{
		Name:     "token",
		MaxAge:   time.Hour,
		Codec:    stubSessionCodec{},
		SameSite: http.SameSiteLaxMode,
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.URL.Scheme = "" // as on a real server
	r.TLS = &tls.ConnectionState{}

	w := httptest.NewRecorder()
	assert.NilError(t, provider.CreateSession(w, r, &saml.Assertion{}))
	cookies := w.Result().Cookies()
	assert.Equal(t, len(cookies), 1)
	assert.Check(t, cookies[0].Secure)

	r.AddCookie(&http.Cookie{Name: "token", Value: "x"}) //nolint:gosec // G124: a request cookie carries no attributes
	w = httptest.NewRecorder()
	assert.NilError(t, provider.DeleteSession(w, r))
	cookies = w.Result().Cookies()
	assert.Equal(t, len(cookies), 1)
	assert.Check(t, cookies[0].Secure)

	// Plain http stays non-Secure unless configured.
	r = httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w = httptest.NewRecorder()
	assert.NilError(t, provider.CreateSession(w, r, &saml.Assertion{}))
	assert.Check(t, !w.Result().Cookies()[0].Secure)
}

// stubSessionCodec makes an empty session and encodes it as a fixed value.
type stubSessionCodec struct{}

func (stubSessionCodec) New(*saml.Assertion) (Session, error) { return struct{}{}, nil }
func (stubSessionCodec) Encode(Session) (string, error)       { return "v", nil }
func (stubSessionCodec) Decode(string) (Session, error)       { return struct{}{}, nil }
