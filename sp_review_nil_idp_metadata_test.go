package saml

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A misconfigured SP without IDPMetadata returns an error for an artifact
// instead of panicking.
func TestSPArtifactWithoutIDPMetadata(t *testing.T) {
	e := spcovSetup(t)
	e.sp.IDPMetadata = nil
	assert.Check(t, is.Equal("", e.sp.GetArtifactBindingLocation(SOAPBinding)))
	assert.Check(t, is.Equal("", e.sp.GetSSOBindingLocation(HTTPRedirectBinding)))
	assert.Check(t, is.Equal("", e.sp.GetSLOBindingLocation(HTTPRedirectBinding)))

	req := httptest.NewRequest("POST", "https://sp.example.com/saml/acs",
		strings.NewReader(url.Values{"SAMLart": {"AAQAAA"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.NilError(t, req.ParseForm())
	_, err := e.sp.ParseResponse(req, []string{spcovRequestID})
	assert.Check(t, errors.Is(err, ErrArtifactResolution), "%v", err)
}

// Without IDPMetadata, the Issuer of a Response, an ArtifactResponse or an
// Assertion names no known IdP: each is refused with an error rather than a
// nil pointer dereference.
func TestSPIssuerWithoutIDPMetadata(t *testing.T) {
	const wantErr = "cannot check the Issuer: IDPMetadata is not set"

	t.Run("unsigned Response with an Issuer", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.IDPMetadata = nil
		r := e.response()
		r.Assertion = e.assertion()
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, r.Element()), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), wantErr))
	})

	t.Run("ArtifactResponse with an Issuer", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.IDPMetadata = nil
		el := e.artifactResponseEl(t, "id-artifact-request", false, nil)
		_, err := e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(el)),
			[]string{spcovRequestID}, "id-artifact-request", e.sp.AcsURL)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), wantErr))
	})

	// Signature verification needs IDPMetadata today, so an assertion does
	// not get this far without it; validateAssertion does not rely on that.
	t.Run("Assertion", func(t *testing.T) {
		e := spcovSetup(t)
		e.sp.IDPMetadata = nil
		err := e.sp.validateAssertion(e.assertion(), []string{spcovRequestID}, spcovNow)
		assert.Check(t, is.ErrorContains(err, wantErr))
	})
}
