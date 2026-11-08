package saml

import (
	"encoding/base64"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// specEncIDResponse has an IdentityProvider issue a Response for e's SP to
// a request with the given NameIDPolicy, encrypting to the SP's
// certificate when encrypt is set, and returns the request.
func (e *spcovEnv) specEncIDResponse(t *testing.T, policy *NameIDPolicy, encrypt bool) *IdpAuthnRequest {
	t.Helper()
	spsso := &SPSSODescriptor{}
	if encrypt {
		spsso.KeyDescriptors = []KeyDescriptor{{
			Use: "encryption",
			KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{
				{Data: base64.StdEncoding.EncodeToString(e.sp.Certificate.Raw)},
			}}},
		}}
	}
	req := &IdpAuthnRequest{
		IDP: &IdentityProvider{
			Key:         e.idpKey,
			Certificate: e.idpCert,
			MetadataURL: mustParseURL(spcovIDPEntityID),
			SSOURL:      mustParseURL("https://idp.example.com/sso/post"),
		},
		Now:             spcovNow,
		Request:         AuthnRequest{ID: spcovRequestID, NameIDPolicy: policy},
		ACSEndpoint:     &IndexedEndpoint{Binding: HTTPPostBinding, Location: e.sp.AcsURL.String()},
		SPSSODescriptor: spsso,
		Assertion:       e.assertion(),
	}
	assert.NilError(t, req.MakeResponse())
	return req
}

// saml-core-2.0-os §3.4.1.1: a request whose NameIDPolicy Format is
// encrypted is answered with the Subject's identifier as an EncryptedID
// (§2.2.4, §8.3.9), which the SP decrypts back to the NameID, of the
// format the IdP issues.
func TestIdPIssuesEncryptedID(t *testing.T) {
	e := spcovSetup(t)
	issued := *e.assertion().Subject.NameID
	req := e.specEncIDResponse(t, nameidPolicy(encryptedNameIDFormat, ""), true)
	assert.Check(t, req.Assertion.Subject.NameID == nil)
	assert.Assert(t, req.Assertion.Subject.EncryptedID != nil)

	responseEl := spcovParse(t, string(spcovSerialize(t, req.ResponseEl)))
	assertionEl, err := e.sp.decryptElement(responseEl.FindElement("./EncryptedAssertion"))
	assert.NilError(t, err)
	assert.Check(t, assertionEl.FindElement("./Subject/NameID") == nil)
	assert.Assert(t, assertionEl.FindElement("./Subject/EncryptedID/EncryptedData") != nil)

	assertion, err := e.specSigParse(t, responseEl)
	assert.NilError(t, err)
	assert.Check(t, assertion.Subject.EncryptedID == nil)
	assert.Assert(t, assertion.Subject.NameID != nil)
	assert.Check(t, is.Equal(issued.Value, assertion.Subject.NameID.Value))
	assert.Check(t, is.Equal(issued.Format, assertion.Subject.NameID.Format))
}

// Without an encryption certificate, or without a request for the
// encrypted format, the NameID is issued as it is.
func TestIdPEncryptedIDNeedsPolicyAndKey(t *testing.T) {
	e := spcovSetup(t)
	for name, test := range map[string]struct {
		policy  *NameIDPolicy
		encrypt bool
	}{
		"no key":       {policy: nameidPolicy(encryptedNameIDFormat, ""), encrypt: false},
		"no policy":    {encrypt: true},
		"other format": {policy: nameidPolicy(string(EmailAddressNameIDFormat), ""), encrypt: true},
	} {
		t.Run(name, func(t *testing.T) {
			req := e.specEncIDResponse(t, test.policy, test.encrypt)
			assert.Check(t, req.Assertion.Subject.NameID != nil)
			assert.Check(t, req.Assertion.Subject.EncryptedID == nil)
			assertion, err := e.specSigParse(t, spcovParse(t, string(spcovSerialize(t, req.ResponseEl))))
			assert.NilError(t, err)
			assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
		})
	}
}
