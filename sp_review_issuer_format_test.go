package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// saml-profiles §4.1.4.2: the Issuer of a Response and of an Assertion of
// the Web Browser SSO profile "MUST" have no Format or the entity Format.
// One with another Format, even with the IdP's entity ID as its value, is
// refused with ErrIssuerMismatch.
func TestSPIssuerFormat(t *testing.T) {
	const persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	parse := func(t *testing.T, responseFormat, assertionFormat string) error {
		t.Helper()
		e := spcovSetup(t)
		r := e.response()
		r.Issuer.Format = responseFormat
		a := e.assertion()
		a.Issuer.Format = assertionFormat
		r.Assertion = a
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
		return err
	}

	for _, format := range []string{"", entityNameIDFormat} {
		assert.Check(t, parse(t, format, format), "Format %q", format)
	}

	err := parse(t, persistent, "")
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "%v", err)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), `response Issuer Format "`+persistent+`"`))

	err = parse(t, entityNameIDFormat, persistent)
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "%v", err)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), `assertion Issuer Format "`+persistent+`"`))
}

// The Response delivered by artifact is checked the same way.
func TestSPIssuerFormatArtifactResponse(t *testing.T) {
	e := spcovSetup(t)
	const artifactReqID = "id-artifact-request"
	parse := func(mutate func(ar *ArtifactResponse)) error {
		el := e.artifactResponseEl(t, artifactReqID, true, mutate)
		_, err := e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), []string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
		return err
	}
	assert.NilError(t, parse(nil))
	err := parse(func(ar *ArtifactResponse) {
		ar.Response.Issuer.Format = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	})
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "%v", err)
}
