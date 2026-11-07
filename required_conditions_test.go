package saml

import (
	"errors"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// validAssertion is an assertion that validateAssertion accepts for
// requiredConditionsSP, so each test removes exactly one part of it.
func validAssertion(now time.Time) *Assertion {
	return &Assertion{
		Version:      "2.0",
		IssueInstant: now,
		Issuer:       Issuer{Value: "https://idp.example.com/"},
		Subject: &Subject{SubjectConfirmations: []SubjectConfirmation{{
			Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
			SubjectConfirmationData: &SubjectConfirmationData{
				InResponseTo: "id-1", Recipient: "https://sp.example.com/acs", NotOnOrAfter: now.Add(time.Minute),
			},
		}}},
		Conditions: &Conditions{
			NotBefore:            now.Add(-time.Minute),
			NotOnOrAfter:         now.Add(time.Minute),
			AudienceRestrictions: []AudienceRestriction{{Audience: Audience{Value: "https://sp.example.com/metadata"}}},
		},
	}
}

func requiredConditionsSP() ServiceProvider {
	return ServiceProvider{
		AcsURL:      mustParseURL("https://sp.example.com/acs"),
		MetadataURL: mustParseURL("https://sp.example.com/metadata"),
		IDPMetadata: &EntityDescriptor{EntityID: "https://idp.example.com/"},
	}
}

func TestValidateAssertionAcceptsCompleteAssertion(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()
	assert.Check(t, sp.validateAssertion(validAssertion(now), []string{"id-1"}, now))
}

// Without a SubjectConfirmation the Recipient, InResponseTo and expiry checks
// never run, so the SAML web browser SSO profile (saml-profiles §4.1.4.2)
// requires a bearer one.
func TestValidateAssertionRequiresBearerSubjectConfirmation(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()

	a := validAssertion(now)
	a.Subject.SubjectConfirmations = nil
	assert.Check(t, is.Error(sp.validateAssertion(a, []string{"id-1"}, now),
		"assertion has no bearer SubjectConfirmation"))

	a = validAssertion(now)
	a.Subject.SubjectConfirmations[0].Method = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
	assert.Check(t, is.Error(sp.validateAssertion(a, []string{"id-1"}, now),
		"assertion has no bearer SubjectConfirmation"))
}

// Without an AudienceRestriction an assertion issued to any service provider
// trusting the same IdP would be accepted here.
func TestValidateAssertionRequiresAudienceRestriction(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()

	a := validAssertion(now)
	a.Conditions.AudienceRestrictions = nil
	assert.Check(t, is.Error(sp.validateAssertion(a, []string{"id-1"}, now),
		`assertion Conditions has no AudienceRestriction for "https://sp.example.com/metadata"`))
}

// A ValidateAudienceRestriction hook still replaces the default check.
func TestValidateAudienceRestrictionHookStillDecides(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()
	sp.ValidateAudienceRestriction = func(*Assertion) error { return nil }

	a := validAssertion(now)
	a.Conditions.AudienceRestrictions = nil
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))

	sp.ValidateAudienceRestriction = func(*Assertion) error { return errors.New("no") }
	assert.Check(t, is.Error(sp.validateAssertion(validAssertion(now), []string{"id-1"}, now),
		"audience restriction validation failed: no"))
}
