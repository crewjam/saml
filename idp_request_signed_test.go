package saml

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Validate sets RequestSigned for a request whose signature it verified,
// whichever binding carried it.
func TestIdpAuthnRequestRequestSigned(t *testing.T) {
	t.Run("redirect", func(t *testing.T) {
		test := newSignedAuthnRequestTest(t)
		redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
		assert.NilError(t, err)
		r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
		req, err := validateAuthnRequest(t, test, r)
		assert.NilError(t, err)
		assert.Check(t, req.RequestSigned)
	})

	t.Run("post enveloped", func(t *testing.T) {
		test := newSignedAuthnRequestTest(t)
		authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		assert.Assert(t, authReq.Signature != nil)
		req, err := validateAuthnRequest(t, test, postForm(t, authReq.Post("relay")))
		assert.NilError(t, err)
		assert.Check(t, req.RequestSigned)
	})

	t.Run("simplesign", func(t *testing.T) {
		test := newSimpleSignIDPTest(t)
		authReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPPostSimpleSignBinding), HTTPPostSimpleSignBinding, HTTPPostSimpleSignBinding)
		assert.NilError(t, err)
		form, err := authReq.SimpleSign("relay", &test.SP)
		assert.NilError(t, err)
		req, err := validateAuthnRequest(t, test, postForm(t, form))
		assert.NilError(t, err)
		assert.Check(t, req.RequestSigned)
	})

	t.Run("unsigned", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		test.SP.SignatureMethod = ""
		redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
		assert.NilError(t, err)
		assert.Check(t, is.Equal("", redirectURL.Query().Get("Signature")))
		r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
		req, err := validateAuthnRequest(t, test, r)
		assert.NilError(t, err)
		assert.Check(t, !req.RequestSigned)

		authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		assert.Assert(t, authReq.Signature == nil)
		req, err = validateAuthnRequest(t, test, postForm(t, authReq.Post("relay")))
		assert.NilError(t, err)
		assert.Check(t, !req.RequestSigned)
	})

	t.Run("bad signature", func(t *testing.T) {
		test := newSignedAuthnRequestTest(t)
		redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
		assert.NilError(t, err)
		tampered := strings.Replace(redirectURL.String(), "RelayState=relay", "RelayState=other", 1)
		r, _ := http.NewRequest(http.MethodGet, tampered, nil)
		req, err := NewIdpAuthnRequest(&test.IDP, r)
		assert.NilError(t, err)
		err = req.Validate()
		assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
		assert.Check(t, !req.RequestSigned)
	})
}
