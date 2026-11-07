package saml

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The SOAP ArtifactResponse body read from the IDP is limited to
// MaxArtifactResponseSize bytes.
func TestArtifactResponseSizeLimit(t *testing.T) {
	const limit = 64 << 10

	oldLimit := MaxArtifactResponseSize
	MaxArtifactResponseSize = limit
	t.Cleanup(func() { MaxArtifactResponseSize = oldLimit })

	e := spcovSetup(t)

	// bodySize is the exact size of the response the IDP sends: a valid
	// signed ArtifactResponse, padded with trailing whitespace.
	var bodySize int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := etree.NewDocument()
		if _, err := doc.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resolveEl := doc.FindElement("//ArtifactResolve")
		el := e.artifactResponseEl(t, resolveEl.SelectAttrValue("ID", ""), true, nil)
		body := spcovSerialize(t, spcovSOAPEnvelope(el))
		if len(body) > bodySize {
			http.Error(w, "response too large for the test", http.StatusInternalServerError)
			return
		}
		body = append(body, bytes.Repeat([]byte(" "), bodySize-len(body))...)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = srv.URL + "/artifact"
	e.sp.HTTPClient = srv.Client()

	t.Run("exactly at the limit", func(t *testing.T) {
		bodySize = limit
		assertion, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("one byte over the limit", func(t *testing.T) {
		bodySize = limit + 1
		_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.Check(t, errors.Is(err, ErrArtifactResolution))
		assert.Check(t, is.Error(spcovPrivateErr(t, err),
			"Error during artifact resolution: response body is larger than 65536 bytes"))
	})

	t.Run("far over the limit", func(t *testing.T) {
		bodySize = 4 * limit
		_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.Check(t, is.Error(spcovPrivateErr(t, err),
			"Error during artifact resolution: response body is larger than 65536 bytes"))
	})
}
