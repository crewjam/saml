package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A NameID outside the SAML assertion namespace is not the subject's NameID.
func TestSubjectNameIDRequiresAssertionNamespace(t *testing.T) {
	const foreign = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject><x:NameID xmlns:x="urn:example:foreign">attacker@example.com</x:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <x:NameID xmlns:x="urn:example:foreign">attacker@example.com</x:NameID>
    </saml:SubjectConfirmation>
  </saml:Subject>
</saml:Assertion>`
	var a Assertion
	assert.Check(t, xml.Unmarshal([]byte(foreign), &a))
	assert.Assert(t, a.Subject != nil)
	assert.Check(t, is.Nil(a.Subject.NameID))
	assert.Assert(t, is.Len(a.Subject.SubjectConfirmations, 1))
	assert.Check(t, is.Nil(a.Subject.SubjectConfirmations[0].NameID))

	const native = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
</saml:Assertion>`
	a = Assertion{}
	assert.Check(t, xml.Unmarshal([]byte(native), &a))
	assert.Assert(t, a.Subject != nil && a.Subject.NameID != nil)
	assert.Check(t, is.Equal(a.Subject.NameID.Value, "user@example.com"))
}

// Conditions in a foreign namespace are not the assertion's Conditions.
func TestAssertionConditionsRequireAssertionNamespace(t *testing.T) {
	const foreign = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <x:Conditions xmlns:x="urn:example:foreign" NotOnOrAfter="2999-01-01T00:00:00Z"/>
</saml:Assertion>`
	var a Assertion
	assert.Check(t, xml.Unmarshal([]byte(foreign), &a))
	assert.Check(t, is.Nil(a.Conditions))
}

// An assertion missing its optional elements fails validation with an error
// instead of a nil-pointer panic.
func TestValidateAssertionMissingElements(t *testing.T) {
	now := TimeNow()
	sp := ServiceProvider{
		EntityID:    "https://sp.example.com/metadata",
		AcsURL:      mustParseURL("https://sp.example.com/acs"),
		IDPMetadata: &EntityDescriptor{EntityID: "https://idp.example.com/"},
	}
	full := func() *Assertion {
		return &Assertion{
			Version:      "2.0",
			IssueInstant: now,
			Issuer:       Issuer{Value: "https://idp.example.com/"},
			Subject: &Subject{NameID: &NameID{Value: "alice"}, SubjectConfirmations: []SubjectConfirmation{{
				Method: bearerSubjectConfirmationMethod,
				SubjectConfirmationData: &SubjectConfirmationData{
					InResponseTo: "id-1", Recipient: "https://sp.example.com/acs", NotOnOrAfter: now.Add(time.Minute),
				},
			}}},
			Conditions: &Conditions{
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute),
				AudienceRestrictions: []AudienceRestriction{{Audience: Audience{Value: "https://sp.example.com/metadata"}}},
			},
			AuthnStatements: []AuthnStatement{{AuthnInstant: now}},
		}
	}
	assert.Check(t, sp.validateAssertion(full(), []string{"id-1"}, now))

	a := full()
	a.Subject = nil
	assert.Check(t, is.Error(sp.validateAssertion(a, []string{"id-1"}, now), "assertion has no Subject"))

	a = full()
	a.Conditions = nil
	assert.Check(t, is.Error(sp.validateAssertion(a, []string{"id-1"}, now), "assertion has no Conditions"))

	a = full()
	a.Subject.SubjectConfirmations[0].SubjectConfirmationData = nil
	assert.Check(t, is.Error(sp.validateAssertion(a, []string{"id-1"}, now),
		"assertion SubjectConfirmation has no SubjectConfirmationData"))

	a = full()
	a.Issuer = Issuer{}
	assert.Check(t, is.Error(sp.validateAssertion(a, []string{"id-1"}, now), `issuer is not "https://idp.example.com/"`))
}

// A LogoutResponse without an Issuer is refused instead of panicking.
func TestValidateLogoutResponseWithoutIssuer(t *testing.T) {
	sp := ServiceProvider{
		SloURL:      mustParseURL("https://sp.example.com/slo"),
		IDPMetadata: &EntityDescriptor{EntityID: "https://idp.example.com/"},
	}
	resp := &LogoutResponse{Version: "2.0", Destination: "https://sp.example.com/slo", IssueInstant: TimeNow()}
	assert.Check(t, is.ErrorContains(sp.validateLogoutResponse(resp), "issuer does not match"))
}

// Advice and AuthzDecisionStatement in a foreign namespace are not the
// assertion's.
func TestAssertionAdviceAndAuthzDecisionRequireAssertionNamespace(t *testing.T) {
	const foreign = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <x:Advice xmlns:x="urn:example:foreign"><saml:AssertionIDRef>id-1</saml:AssertionIDRef></x:Advice>
  <x:AuthzDecisionStatement xmlns:x="urn:example:foreign" Resource="urn:r" Decision="Permit"/>
  <saml:AuthnStatement AuthnInstant="2030-01-01T00:00:00Z"><saml:AuthnContext>
    <x:AuthnContextDecl xmlns:x="urn:example:foreign"/><x:AuthnContextDeclRef xmlns:x="urn:example:foreign">urn:d</x:AuthnContextDeclRef>
  </saml:AuthnContext></saml:AuthnStatement>
</saml:Assertion>`
	var a Assertion
	assert.Check(t, xml.Unmarshal([]byte(foreign), &a))
	assert.Check(t, is.Nil(a.Advice))
	assert.Check(t, is.Len(a.AuthzDecisionStatements, 0))
	assert.Assert(t, is.Len(a.AuthnStatements, 1))
	assert.Check(t, is.Nil(a.AuthnStatements[0].AuthnContext.AuthnContextDecl))
	assert.Check(t, is.Nil(a.AuthnStatements[0].AuthnContext.AuthnContextDeclRef))
}
