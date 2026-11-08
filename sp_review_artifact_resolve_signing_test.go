package saml

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// spArtifactResolveVerify checks that el carries a valid signature by the
// SP's certificate.
func spArtifactResolveVerify(t *testing.T, e *spcovEnv, el *etree.Element) {
	t.Helper()
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{e.sp.Certificate},
	})
	ctx.Clock = dsig.NewFakeClockAt(spcovNow)
	_, err := ctx.Validate(el)
	assert.NilError(t, err)
}

// saml-bindings §3.6.5.2: the IdP must authenticate the requester of an
// artifact before it returns the message. Like an attribute query or a SOAP
// LogoutRequest, the ArtifactResolve is signed whenever Key is set, with
// SHA-256 when SignatureMethod is empty, and names the resolution service it
// is sent to as its Destination.
func TestSPArtifactResolveSignedWithoutSignatureMethod(t *testing.T) {
	e := spcovSetup(t)
	assert.Equal(t, "", e.sp.SignatureMethod)

	req, err := e.sp.MakeArtifactResolveRequest("the-artifact")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(spcovArtifactLocation, req.Destination))
	assert.Assert(t, req.Signature != nil)
	method := req.Signature.FindElement("./SignedInfo/SignatureMethod")
	assert.Assert(t, method != nil)
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, method.SelectAttrValue("Algorithm", "")))
	spArtifactResolveVerify(t, e, req.Element())

	// Signing again replaces the signature rather than adding one.
	assert.NilError(t, e.sp.SignArtifactResolve(req))
	sigs, err := findChildren(req.Element(), dsig.Namespace, "Signature")
	assert.NilError(t, err)
	assert.Check(t, is.Len(sigs, 1))
	spArtifactResolveVerify(t, e, req.Element())

	// Without a key, the request is unsigned.
	e.sp.Key = nil
	req, err = e.sp.MakeArtifactResolveRequest("the-artifact")
	assert.NilError(t, err)
	assert.Check(t, req.Signature == nil)
}

// The ArtifactResolve that ParseResponse sends is signed and names, as its
// Destination, the URL it is posted to.
func TestSPArtifactResolveSentSignedToItsDestination(t *testing.T) {
	e := spcovSetup(t)
	var received *etree.Element
	var receivedURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := etree.NewDocument()
		if _, err := doc.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received = doc.FindElement("//ArtifactResolve").Copy()
		receivedURL = "https://" + r.Host + r.URL.Path
		el := e.artifactResponseEl(t, received.SelectAttrValue("ID", ""), true, nil)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(spcovSerialize(t, spcovSOAPEnvelope(el)))
	}))
	t.Cleanup(srv.Close)
	resolutionURL := srv.URL + "/artifact"
	e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = resolutionURL
	e.sp.HTTPClient = srv.Client()

	_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
	assert.NilError(t, err)
	assert.Assert(t, received != nil)
	assert.Check(t, is.Equal(resolutionURL, receivedURL))
	assert.Check(t, is.Equal(resolutionURL, received.SelectAttrValue("Destination", "")))
	spArtifactResolveVerify(t, e, received)
}
