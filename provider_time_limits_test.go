package saml

import (
	"errors"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A ServiceProvider's MaxClockSkew replaces the package-level one for its
// IssueInstant and NotBefore checks, in either direction.
func TestServiceProviderMaxClockSkew(t *testing.T) {
	now := TimeNow()
	future := func(d time.Duration) *Assertion {
		a := validAssertion(now)
		a.IssueInstant = now.Add(d)
		a.Conditions.NotBefore = now.Add(d)
		return a
	}

	sp := requiredConditionsSP()
	a := future(MaxClockSkew + time.Minute)
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrNotYetValid))
	sp.MaxClockSkew = MaxClockSkew + 2*time.Minute
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))

	sp = requiredConditionsSP()
	a = future(30 * time.Second)
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))
	sp.MaxClockSkew = 10 * time.Second
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrNotYetValid))
}

// A ServiceProvider's MaxIssueDelay replaces the package-level one, and the
// replay cache keeps the assertion for that long.
func TestServiceProviderMaxIssueDelay(t *testing.T) {
	now := TimeNow()
	sp := requiredConditionsSP()
	a := validAssertion(now.Add(-MaxIssueDelay - time.Second))
	a.Conditions.NotOnOrAfter = time.Time{}
	a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = now.Add(time.Hour)
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrExpired))
	sp.MaxIssueDelay = MaxIssueDelay + time.Minute
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))
	assert.Check(t, is.DeepEqual(a.IssueInstant.Add(sp.MaxIssueDelay), sp.limits().acceptableUntil(a)))

	sp = requiredConditionsSP()
	a = validAssertion(now.Add(-30 * time.Second))
	assert.Check(t, sp.validateAssertion(a, []string{"id-1"}, now))
	sp.MaxIssueDelay = 10 * time.Second
	assert.Check(t, errors.Is(sp.validateAssertion(a, []string{"id-1"}, now), ErrExpired))
}

// An IdentityProvider's MaxClockSkew and MaxIssueDelay replace the
// package-level ones for the AuthnRequest IssueInstant.
func TestIdentityProviderTimeLimits(t *testing.T) {
	req := newIssueInstantRequest(t, MaxClockSkew+time.Minute)
	assert.Check(t, errors.Is(req.Validate(), ErrNotYetValid))
	req = newIssueInstantRequest(t, MaxClockSkew+time.Minute)
	req.IDP.MaxClockSkew = MaxClockSkew + 2*time.Minute
	assert.Check(t, req.Validate())

	req = newIssueInstantRequest(t, 30*time.Second)
	req.IDP.MaxClockSkew = 10 * time.Second
	assert.Check(t, errors.Is(req.Validate(), ErrNotYetValid))

	req = newIssueInstantRequest(t, -MaxIssueDelay-time.Minute)
	assert.Check(t, errors.Is(req.Validate(), ErrExpired))
	req = newIssueInstantRequest(t, -MaxIssueDelay-time.Minute)
	req.IDP.MaxIssueDelay = MaxIssueDelay + 2*time.Minute
	assert.Check(t, req.Validate())

	req = newIssueInstantRequest(t, -30*time.Second)
	req.IDP.MaxIssueDelay = 10 * time.Second
	assert.Check(t, errors.Is(req.Validate(), ErrExpired))

	// The issued assertion is valid for the IdP's MaxIssueDelay.
	req = newIssueInstantRequest(t, 0)
	req.IDP.MaxIssueDelay = 10 * time.Minute
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", UserName: "alice"}))
	assert.Check(t, is.DeepEqual(req.Assertion.Conditions.NotOnOrAfter, req.Request.IssueInstant.Add(10*time.Minute)))
}
