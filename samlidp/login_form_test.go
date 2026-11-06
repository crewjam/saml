package samlidp

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

var (
	loginFormActionRe = regexp.MustCompile(`<form method="post" action="([^"]*)">`)
	loginFormInputRe  = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)" />`)
)

// TestHTTPLoginFormCompletesSSO drives an SP-initiated flow through the login
// form: the form shown by /sso must post back to /sso along with the original
// SAMLRequest, and submitting valid credentials must yield a SAML response for
// the service provider rather than stopping at the IdP.
func TestHTTPLoginFormCompletesSSO(t *testing.T) {
	test := NewServerTest(t)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	assert.NilError(t, err)
	assert.NilError(t, test.Store.Put("/users/alice", User{
		Name:           "alice",
		HashedPassword: hashedPassword,
		Email:          "alice@example.com",
	}))

	u, err := test.SP.MakeRedirectAuthenticationRequest("frob")
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", u.String(), nil)
	test.Server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code))

	action := loginFormActionRe.FindStringSubmatch(w.Body.String())
	assert.Assert(t, action != nil, w.Body.String())
	assert.Check(t, is.Equal("https://idp.example.com/sso", html.UnescapeString(action[1])))

	form := url.Values{"user": {"alice"}, "password": {"hunter2"}}
	for _, m := range loginFormInputRe.FindAllStringSubmatch(w.Body.String(), -1) {
		form.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	assert.Assert(t, form.Get("SAMLRequest") != "", w.Body.String())
	assert.Check(t, is.Equal("frob", form.Get("RelayState")))

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", html.UnescapeString(action[1]), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	assert.Check(t, strings.Contains(w.Header().Get("Set-Cookie"), "session="))
	assert.Check(t, strings.Contains(w.Body.String(), `action="https://sp.example.com/saml2/acs"`), w.Body.String())
	assert.Check(t, strings.Contains(w.Body.String(), `name="SAMLResponse"`), w.Body.String())
}
