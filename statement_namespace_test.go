package saml

import (
	"encoding/xml"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// Statements, attributes and their children outside the SAML assertion
// namespace are not part of the assertion. A consumer that reads the
// subject-id attribute to identify the user must not see one carried in a
// foreign namespace.
func TestStatementsRequireAssertionNamespace(t *testing.T) {
	const foreign = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:x="urn:example:foreign">
  <x:AttributeStatement>
    <x:Attribute Name="urn:oasis:names:tc:SAML:attribute:subject-id"><x:AttributeValue>victim</x:AttributeValue></x:Attribute>
  </x:AttributeStatement>
  <saml:AttributeStatement>
    <x:Attribute Name="mail"><saml:AttributeValue>victim@example.com</saml:AttributeValue></x:Attribute>
    <saml:Attribute Name="uid"><x:AttributeValue>victim</x:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
  <x:AuthnStatement SessionIndex="foreign"/>
  <saml:AuthnStatement SessionIndex="native">
    <x:SubjectLocality Address="10.0.0.1"/>
    <x:AuthnContext><x:AuthnContextClassRef>foreign</x:AuthnContextClassRef></x:AuthnContext>
  </saml:AuthnStatement>
  <saml:Conditions><x:OneTimeUse/><x:ProxyRestriction><x:Audience>foreign</x:Audience></x:ProxyRestriction></saml:Conditions>
</saml:Assertion>`
	var a Assertion
	assert.Check(t, xml.Unmarshal([]byte(foreign), &a))

	assert.Assert(t, is.Len(a.AttributeStatements, 1))
	assert.Assert(t, is.Len(a.AttributeStatements[0].Attributes, 1))
	assert.Check(t, is.Equal(a.AttributeStatements[0].Attributes[0].Name, "uid"))
	assert.Check(t, is.Len(a.AttributeStatements[0].Attributes[0].Values, 0))

	assert.Assert(t, is.Len(a.AuthnStatements, 1))
	assert.Check(t, is.Equal(a.AuthnStatements[0].SessionIndex, "native"))
	assert.Check(t, is.Nil(a.AuthnStatements[0].SubjectLocality))
	assert.Check(t, is.Nil(a.AuthnStatements[0].AuthnContext.AuthnContextClassRef))

	assert.Assert(t, a.Conditions != nil)
	assert.Check(t, is.Nil(a.Conditions.OneTimeUse))
	assert.Check(t, is.Nil(a.Conditions.ProxyRestriction))
}

// The same elements in the SAML assertion namespace are still read, whatever
// prefix the document binds to it.
func TestStatementsInAssertionNamespace(t *testing.T) {
	const native = `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <AttributeStatement>
    <Attribute Name="urn:oasis:names:tc:SAML:attribute:subject-id"><AttributeValue>user</AttributeValue></Attribute>
  </AttributeStatement>
  <AuthnStatement SessionIndex="native">
    <SubjectLocality Address="10.0.0.1"/>
    <AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext>
  </AuthnStatement>
  <Conditions><OneTimeUse/><ProxyRestriction Count="1"><Audience>https://sp.example.com/</Audience></ProxyRestriction></Conditions>
</Assertion>`
	var a Assertion
	assert.Check(t, xml.Unmarshal([]byte(native), &a))

	assert.Assert(t, is.Len(a.AttributeStatements, 1))
	assert.Assert(t, is.Len(a.AttributeStatements[0].Attributes, 1))
	assert.Assert(t, is.Len(a.AttributeStatements[0].Attributes[0].Values, 1))
	assert.Check(t, is.Equal(a.AttributeStatements[0].Attributes[0].Values[0].Value, "user"))

	assert.Assert(t, is.Len(a.AuthnStatements, 1))
	assert.Assert(t, a.AuthnStatements[0].SubjectLocality != nil)
	assert.Check(t, is.Equal(a.AuthnStatements[0].SubjectLocality.Address, "10.0.0.1"))
	assert.Assert(t, a.AuthnStatements[0].AuthnContext.AuthnContextClassRef != nil)

	assert.Assert(t, a.Conditions != nil)
	assert.Check(t, a.Conditions.OneTimeUse != nil)
	assert.Assert(t, a.Conditions.ProxyRestriction != nil)
	assert.Assert(t, a.Conditions.ProxyRestriction.Count != nil)
	assert.Check(t, is.Equal(*a.Conditions.ProxyRestriction.Count, 1))
	assert.Assert(t, is.Len(a.Conditions.ProxyRestriction.Audiences, 1))
	assert.Check(t, is.Equal(a.Conditions.ProxyRestriction.Audiences[0].Value, "https://sp.example.com/"))
}
