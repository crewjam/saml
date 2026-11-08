package saml

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The assertion's Issuer and the NameID's NameQualifier are the IdP's
// entity ID, as its metadata publishes it, though making an assertion no
// longer builds the metadata.
func TestIDPAssertionUsesMetadataEntityID(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, authReq.Post("")))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", NameID: "alice"}))

	entityID := test.IDP.Metadata().EntityID
	assert.Check(t, is.Equal(entityID, req.Assertion.Issuer.Value))
	assert.Check(t, is.Equal(entityID, req.Assertion.Subject.NameID.NameQualifier))
}
