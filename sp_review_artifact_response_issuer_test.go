package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// saml-profiles §5.4.2: the Issuer of an ArtifactResponse "MUST be present
// and MUST contain the unique identifier of the artifact issuer; the Format
// attribute MUST be omitted or have a value of
// urn:oasis:names:tc:SAML:2.0:nameid-format:entity".
func TestSPArtifactResponseIssuer(t *testing.T) {
	e := spcovSetup(t)
	const artifactReqID = "id-artifact-request"
	parse := func(t *testing.T, mutate func(*ArtifactResponse)) error {
		t.Helper()
		el := e.artifactResponseEl(t, artifactReqID, true, mutate)
		_, err := e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), []string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
		return err
	}

	assert.Check(t, parse(t, nil))
	assert.Check(t, parse(t, func(ar *ArtifactResponse) { ar.Issuer.Format = entityNameIDFormat }))

	err := parse(t, func(ar *ArtifactResponse) { ar.Issuer = nil })
	assert.Check(t, errors.Is(err, ErrMissingElement), "%v", err)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "ArtifactResponse has no Issuer"))

	err = parse(t, func(ar *ArtifactResponse) { ar.Issuer.Format = string(EmailAddressNameIDFormat) })
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "%v", err)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "saml-profiles §5.4.2"))

	err = parse(t, func(ar *ArtifactResponse) { ar.Issuer.Value = "https://other.example.com/" })
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "%v", err)
}
