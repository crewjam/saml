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
