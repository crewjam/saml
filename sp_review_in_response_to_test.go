package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
)

// An assertion issued for one pending request cannot be accepted inside a
// Response that answers another.
func TestSPResponseAndAssertionInResponseToMustAgree(t *testing.T) {
	const otherRequestID = "id-other-request"
	e := spcovSetup(t)
	signedAssertion := e.idpSign(t, e.assertion().Element()) // InResponseTo spcovRequestID

	r := e.response()
	r.InResponseTo = otherRequestID
	responseEl := r.Element()
	responseEl.AddChild(signedAssertion)

	_, err := e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID, otherRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "%v", err)

	r.InResponseTo = spcovRequestID
	responseEl = r.Element()
	responseEl.AddChild(e.idpSign(t, e.assertion().Element()))
	_, err = e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID, otherRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
}
