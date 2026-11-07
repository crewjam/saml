package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
)

// The Response inside an ArtifactResponse is checked against the ACS URL,
// not against the IdP's ArtifactResolutionService the SP posted to.
func TestSPArtifactResponseDestinationIsTheACS(t *testing.T) {
	var destination string
	e := spcovSetup(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := etree.NewDocument()
		if _, err := doc.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resolveEl := doc.FindElement("//ArtifactResolve")
		el := e.artifactResponseEl(t, resolveEl.SelectAttrValue("ID", ""), true, func(ar *ArtifactResponse) {
			ar.Response.Destination = destination
		})
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(spcovSerialize(t, spcovSOAPEnvelope(el)))
	}))
	t.Cleanup(srv.Close)
	resolutionURL := srv.URL + "/artifact"
	e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = resolutionURL
	e.sp.HTTPClient = srv.Client()

	destination = resolutionURL
	_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
	assert.Check(t, errors.Is(err, ErrDestinationMismatch), "%v", err)

	destination = e.sp.AcsURL.String()
	_, err = e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
	assert.NilError(t, err)
}
