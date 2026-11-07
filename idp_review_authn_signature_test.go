package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// newSignedAuthnRequestTest returns an IdP test whose SP signs its
// AuthnRequests with RSA-SHA256, so that its metadata says
// AuthnRequestsSigned="true" and lists its signing certificate.
func newSignedAuthnRequestTest(t *testing.T) *IdentityProviderTest {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	return test
}

// validateAuthnRequest parses and validates r as an AuthnRequest to test's IdP.
func validateAuthnRequest(t *testing.T, test *IdentityProviderTest, r *http.Request) (*IdpAuthnRequest, error) {
	t.Helper()
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	if err != nil {
		return nil, err
	}
	return req, req.Validate()
}

func TestIDPVerifiesRedirectAuthnRequestSignature(t *testing.T) {
	test := newSignedAuthnRequestTest(t)
	redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	assert.Check(t, redirectURL.Query().Get("Signature") != "")

	r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	req, err := validateAuthnRequest(t, test, r)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("relay", req.RelayState))

	// The signature covers the RelayState.
	tampered := strings.Replace(redirectURL.String(), "RelayState=relay", "RelayState=other", 1)
	r, _ = http.NewRequest(http.MethodGet, tampered, nil)
	_, err = validateAuthnRequest(t, test, r)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
}

func TestIDPVerifiesPostAuthnRequestSignature(t *testing.T) {
	test := newSignedAuthnRequestTest(t)
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Assert(t, authReq.Signature != nil)

	req, err := validateAuthnRequest(t, test, postForm(t, authReq.Post("relay")))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(authReq.ID, req.Request.ID))

	// Changing the signed request breaks the signature.
	requestXML := string(spcovSerialize(t, authReq.Element()))
	tampered := strings.Replace(requestXML, "<samlp:AuthnRequest ", `<samlp:AuthnRequest ForceAuthn="true" `, 1)
	assert.Assert(t, tampered != requestXML)
	_, err = validateAuthnRequest(t, test, postRequestXML(t, test, tampered))
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
}

func TestIDPRequiresSignatureWhenSPMetadataSaysSigned(t *testing.T) {
	test := newSignedAuthnRequestTest(t)

	unsignedSP := test.SP
	unsignedSP.SignatureMethod = ""

	redirectURL, err := unsignedSP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	_, err = validateAuthnRequest(t, test, r)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
	assert.Check(t, is.ErrorContains(err, "says it signs them"))

	authReq, err := unsignedSP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	_, err = validateAuthnRequest(t, test, postForm(t, authReq.Post("relay")))
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)

	// An SP that does not say it signs may send unsigned requests.
	plain := NewIdentityProviderTest(t, applyKey)
	redirectURL, err = plain.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	r, _ = http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	_, err = validateAuthnRequest(t, plain, r)
	assert.NilError(t, err)
}

func TestIDPWantAuthnRequestsSigned(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.WantAuthnRequestsSigned = true
	want := test.IDP.Metadata().IDPSSODescriptors[0].WantAuthnRequestsSigned
	assert.Assert(t, want != nil && *want)
	test.SP.IDPMetadata = test.IDP.Metadata()

	redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	_, err = validateAuthnRequest(t, test, r)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)

	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	redirectURL, err = test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	r, _ = http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	_, err = validateAuthnRequest(t, test, r)
	assert.NilError(t, err)
}

func TestIDPRejectsSignedAuthnRequestWithoutSPSigningCert(t *testing.T) {
	test := newSignedAuthnRequestTest(t)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, _ string) (*EntityDescriptor, error) {
			md := test.SP.Metadata()
			md.SPSSODescriptors[0].KeyDescriptors = nil
			md.SPSSODescriptors[0].AuthnRequestsSigned = nil
			return md, nil
		},
	}
	redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	_, err = validateAuthnRequest(t, test, r)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
}

func TestIDPRejectsSHA1RedirectAuthnRequestSignature(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.SP.SignatureMethod = dsig.RSASHA1SignatureMethod
	test.IDP.RejectSHA1Signatures = true
	redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	_, err = validateAuthnRequest(t, test, r)
	assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
}

// postRequestXML returns an HTTP-POST binding request to test's IdP that
// carries requestXML.
func postRequestXML(t *testing.T, test *IdentityProviderTest, requestXML string) *http.Request {
	t.Helper()
	v := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(requestXML))}}
	return simpleSignPost(t, test.IDP.SSOURL.String(), v)
}
