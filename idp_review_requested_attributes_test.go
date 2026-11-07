package saml

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Requested attribute names in the basic or unspecified format, or with no
// NameFormat, are matched without regard to case or punctuation.
func TestDefaultAssertionMakerRequestedAttributeNames(t *testing.T) {
	const basic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	test := NewIdentityProviderTest(t, applyKey)
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	validated, err := NewIdpAuthnRequest(&test.IDP, postForm(t, authReq.Post("")))
	assert.NilError(t, err)
	assert.NilError(t, validated.Validate())
	validated.SPSSODescriptor.AttributeConsumingServices = []AttributeConsumingService{{
		RequestedAttributes: []RequestedAttribute{
			{Attribute: Attribute{Name: "Email", NameFormat: basic}},
			{Attribute: Attribute{Name: "FirstName"}},
			{Attribute: Attribute{Name: "last_name", NameFormat: basic}},
			{Attribute: Attribute{Name: "Email", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"}},
		},
	}}

	session := &Session{ID: "s", UserEmail: "alice@example.com", UserGivenName: "Alice", UserSurname: "Smith"}
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(validated, session))

	got := map[string]string{}
	for _, statement := range validated.Assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			if len(attr.Values) == 1 {
				got[attr.Name+"|"+attr.NameFormat] = attr.Values[0].Value
			}
		}
	}
	assert.Check(t, is.Equal("alice@example.com", got["Email|"+basic]))
	assert.Check(t, is.Equal("Alice", got["FirstName|"]))
	assert.Check(t, is.Equal("Smith", got["last_name|"+basic]))
	_, uriEmail := got["Email|urn:oasis:names:tc:SAML:2.0:attrname-format:uri"]
	assert.Check(t, !uriEmail, "a uri-format name is not guessed at")
}
