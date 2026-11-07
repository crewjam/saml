package samlidp

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// saml-bindings-2.0-os §3.4.3 and §3.5.3: "If a SAML request message is
// accompanied by RelayState data, then the SAML responder MUST return its
// SAML protocol response using a binding that also supports a RelayState
// mechanism, and it MUST place the exact data it received with the request
// into the corresponding RelayState parameter in the response." The RelayState
// of an HTTP-Redirect AuthnRequest must survive the login form exactly, even
// when it needs URL and HTML escaping, and come back in the HTTP-POST
// response form (§3.5.4) posted to the ACS.
func TestSpecBinding_3_4_3_LoginFormKeepsExactRelayState(t *testing.T) {
	test := NewServerTest(t)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	assert.NilError(t, err)
	assert.NilError(t, test.Store.Put("/users/alice", User{
		Name:           "alice",
		HashedPassword: hashedPassword,
		Email:          "alice@example.com",
	}))

	relayState := `a b+c&d=e"f'g<h>%2F/` + strings.Repeat("z", 40)
	u, err := test.SP.MakeRedirectAuthenticationRequest(relayState)
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Assert(t, is.Equal(http.StatusOK, w.Code))
	action := loginFormActionRe.FindStringSubmatch(w.Body.String())
	assert.Assert(t, action != nil, w.Body.String())

	form := url.Values{"user": {"alice"}, "password": {"hunter2"}}
	for _, m := range loginFormInputRe.FindAllStringSubmatch(w.Body.String(), -1) {
		form.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	assert.Check(t, is.Equal(relayState, form.Get("RelayState")))

	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, html.UnescapeString(action[1]), strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())

	body := w.Body.String()
	assert.Check(t, is.Contains(body, `method="post" action="https://sp.example.com/saml2/acs"`))
	assert.Check(t, !strings.Contains(body, `"f'g<h>`), "RelayState must be HTML-escaped")
	got := url.Values{}
	for _, m := range loginFormInputRe.FindAllStringSubmatch(body, -1) {
		got.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	assert.Check(t, got.Get("SAMLResponse") != "", body)
	assert.Check(t, is.DeepEqual([]string{relayState}, got["RelayState"]))
}
