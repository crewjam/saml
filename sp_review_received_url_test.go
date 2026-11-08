package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// postResponseTo posts the IdP-signed Response r to the SP's ACS with the
// request-target target, as a client sends it, and parses it.
func (e *spcovEnv) postResponseTo(t *testing.T, target string, r *Response) (*Assertion, error) {
	t.Helper()
	r.Assertion = e.assertion()
	form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(spcovSerialize(t, e.idpSign(t, r.Element())))}}
	req := httptest.NewRequest(http.MethodPost, e.sp.AcsURL.String(), strings.NewReader(form.Encode()))
	// httptest.NewRequest parses an absolute URL as given; set the URL as
	// Go's server does from the request line.
	u, err := url.ParseRequestURI(target)
	assert.NilError(t, err)
	req.URL = u
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.NilError(t, req.ParseForm())
	return e.sp.ParseResponse(req, []string{spcovRequestID})
}

// The Destination of a Response is checked against the URL it was received
// at, but the scheme and host of that URL are the SP's, not those of the
// request-target: a client that sends "POST https://other-sp.example/acs"
// must not make a Response addressed to another SP pass the check.
func TestParseResponseDestinationIgnoresClientHost(t *testing.T) {
	e := spcovSetup(t)
	other := e.sp.AcsURL
	other.Host = "other-sp.example.com"

	t.Run("absolute-form request-target naming another SP", func(t *testing.T) {
		r := e.response()
		r.Destination = other.String()
		_, err := e.postResponseTo(t, other.String(), r)
		assert.Check(t, errors.Is(err, ErrDestinationMismatch), "%v", err)
	})

	t.Run("origin-form request-target", func(t *testing.T) {
		assertion, err := e.postResponseTo(t, e.sp.AcsURL.RequestURI(), e.response())
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("Destination with the query it was received with", func(t *testing.T) {
		received := e.sp.AcsURL
		received.RawQuery = "tenant=a"
		r := e.response()
		r.Destination = received.String()
		assertion, err := e.postResponseTo(t, received.RequestURI(), r)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})
}
