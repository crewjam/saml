package saml

import (
	"errors"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// newIssueInstantRequest returns a validated-looking request whose
// IssueInstant is offset from now.
func newIssueInstantRequest(t *testing.T, offset time.Duration) *IdpAuthnRequest {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	authReq.IssueInstant = TimeNow().Add(offset)
	req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, authReq.Post("")))
	assert.NilError(t, err)
	return req
}

func TestIDPRejectsFutureAuthnRequestIssueInstant(t *testing.T) {
	req := newIssueInstantRequest(t, 365*24*time.Hour)
	err := req.Validate()
	assert.Check(t, errors.Is(err, ErrNotYetValid), "%v", err)
	assert.Check(t, is.ErrorContains(err, "in the future"))

	// Within the clock skew it is accepted.
	req = newIssueInstantRequest(t, MaxClockSkew-time.Second)
	assert.NilError(t, req.Validate())
}

func TestIDPAssertionNotBeforeIsNeverPostdated(t *testing.T) {
	req := newIssueInstantRequest(t, MaxClockSkew-time.Second)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", UserName: "alice"}))

	conditions := req.Assertion.Conditions
	assert.Check(t, !conditions.NotBefore.After(req.Now), "NotBefore %s is after now %s", conditions.NotBefore, req.Now)
	confirmation := req.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData
	assert.Check(t, conditions.NotBefore.Before(confirmation.NotOnOrAfter))
	assert.Check(t, !confirmation.NotOnOrAfter.After(conditions.NotOnOrAfter))
}
