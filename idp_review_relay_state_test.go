package saml

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// rawSignedRedirectURL returns destination with an HTTP-Redirect binding
// query for message whose RelayState is rawRelayState exactly as given (not
// escaped), signed by sp over the parameters as they appear.
func rawSignedRedirectURL(t *testing.T, sp *ServiceProvider, destination, messageParam string, message *LogoutRequest, authn *AuthnRequest, rawRelayState string) string {
	t.Helper()
	var encoded string
	var err error
	if message != nil {
		encoded, err = deflateAndEncode(message.Element())
	} else {
		unsigned := *authn
		unsigned.Signature = nil
		encoded, err = deflateAndEncode(unsigned.Element())
	}
	assert.NilError(t, err)
	signingContext, err := sp.signingContext(sp.SignatureMethod)
	assert.NilError(t, err)
	query := messageParam + "=" + url.QueryEscape(encoded) +
		"&RelayState=" + rawRelayState +
		"&SigAlg=" + url.QueryEscape(sp.SignatureMethod)
	sig, err := signDetached(signingContext, query)
	assert.NilError(t, err)
	return destination + "?" + query + "&Signature=" + url.QueryEscape(sig)
}

// The RelayState of an HTTP-Redirect message is read from the same parse of
// the query as the content its signature covers. url.Values drops a pair
// that contains a semicolon, which would echo back an empty RelayState for
// a correctly signed request.
func TestIDPRedirectRelayStateFromSignedQuery(t *testing.T) {
	const relayState = "a;b"

	// url.Values loses it.
	q, _ := url.ParseQuery("RelayState=" + relayState)
	assert.Check(t, is.Equal("", q.Get("RelayState")))

	t.Run("LogoutRequest", func(t *testing.T) {
		test := newSLOTest(t)
		u := rawSignedRedirectURL(t, &test.SP, test.IDP.LogoutURL.String(), "SAMLRequest", test.logoutRequest(), nil, relayState)
		req, err := NewIdpLogoutRequest(&test.IDP, httptest.NewRequest(http.MethodGet, u, nil))
		assert.NilError(t, err)
		assert.NilError(t, req.Validate())
		assert.Check(t, is.Equal(relayState, req.RelayState))
	})

	t.Run("AuthnRequest", func(t *testing.T) {
		test := newSignedAuthnRequestTest(t)
		authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		u := rawSignedRedirectURL(t, &test.SP, test.IDP.SSOURL.String(), "SAMLRequest", nil, authReq, relayState)
		req, err := validateAuthnRequest(t, test, httptest.NewRequest(http.MethodGet, u, nil))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(relayState, req.RelayState))
	})
}
