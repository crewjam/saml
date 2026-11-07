package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
)

// An empty string among possibleRequestIDs does not accept an unsolicited
// response or assertion unless AllowIDPInitiated is set.
func TestSPEmptyPossibleRequestIDNeedsAllowIDPInitiated(t *testing.T) {
	e := spcovSetup(t)
	r := e.response()
	r.InResponseTo = ""
	r.Assertion = e.assertion()
	r.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = ""
	buf := spcovSerialize(t, e.idpSign(t, r.Element()))

	_, err := e.sp.ParseXMLResponse(buf, []string{"", spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "%v", err)

	err = e.sp.validateAssertionInResponseTo("", []string{"", spcovRequestID})
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "%v", err)

	e.sp.AllowIDPInitiated = true
	_, err = e.sp.ParseXMLResponse(buf, []string{""}, e.sp.AcsURL)
	assert.NilError(t, err)
}
