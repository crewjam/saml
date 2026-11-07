package samlidp

import (
	"crypto/x509"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// fakeSignature is a ds:Signature element. Without SPMetadataCertificates a
// signature is not checked, so it need not be valid.
const fakeSignature = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
	`<ds:SignedInfo><ds:Reference URI=""><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>` +
	`<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>`

// getService sends GET /services/sp and returns the response.
func getService(t *testing.T, test *ServerTest) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp", nil)
	test.Server.ServeHTTP(w, r)
	return w
}

// assertStoredAsReceived checks that the service PUT with metadata was
// stored as it was received: the store holds the exact bytes, GET
// /services/sp returns them unchanged, and the parsed metadata, from the
// store and as registered by initializeServices, still has its signatures.
func assertStoredAsReceived(t *testing.T, test *ServerTest, metadata string) {
	t.Helper()

	var service Service
	assert.NilError(t, test.Store.Get("/services/sp", &service))
	assert.Check(t, is.Equal(metadata, string(service.RawMetadata)))
	assert.Check(t, is.Equal(signedSPEntityID, service.Metadata.EntityID))
	assert.Check(t, hasSignature(&service.Metadata), "parsed metadata lost its signatures")

	w := getService(t, test)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal(metadata, w.Body.String()))
	assert.Check(t, is.Equal("application/samlmetadata+xml", w.Header().Get("Content-Type")))

	assertRegisteredAfterRestart(t, test)
	assert.Check(t, hasSignature(test.Server.serviceProviders[signedSPEntityID]))
}

// assertRegisteredAfterRestart checks that initializeServices registers the
// stored service.
func assertRegisteredAfterRestart(t *testing.T, test *ServerTest) {
	t.Helper()
	delete(test.Server.serviceProviders, signedSPEntityID)
	assert.NilError(t, test.Server.initializeServices())
	registered, ok := test.Server.serviceProviders[signedSPEntityID]
	assert.Assert(t, ok)
	assert.Check(t, is.Contains(acsLocations(registered), "https://sp.example.com/saml2/acs"))
}

// hasSignature reports whether md, or one of its SPSSODescriptors, holds
// an XML signature.
func hasSignature(md *saml.EntityDescriptor) bool {
	if md.Signature != nil {
		return true
	}
	for _, d := range md.SPSSODescriptors {
		if d.Signature != nil {
			return true
		}
	}
	return false
}

func TestPutServiceStoresSignedMetadataReadably(t *testing.T) {
	test := NewServerTest(t)
	metadata := signedSPMetadata(t, test.SP)
	assert.Assert(t, strings.Contains(metadata, "Signature"))

	assert.Check(t, is.Equal(http.StatusNoContent, putService(t, test, metadata)))
	registered, ok := test.Server.serviceProviders[signedSPEntityID]
	assert.Assert(t, ok)
	assert.Check(t, registered.Signature != nil)
	assertStoredAsReceived(t, test, metadata)
}

func TestPutServiceStoresNestedSignaturesReadably(t *testing.T) {
	unsigned := func(t *testing.T, test *ServerTest) string {
		// Drop the XML declaration, if any, so the metadata can be nested.
		md := unsignedSPMetadata(t, test.SP)
		if i := strings.Index(md, "?>"); strings.HasPrefix(md, "<?xml") && i >= 0 {
			md = md[i+2:]
		}
		return md
	}
	// signDescriptor puts a ds:Signature as the first child of the
	// SPSSODescriptor, where the schema puts it.
	signDescriptor := func(t *testing.T, md string) string {
		t.Helper()
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromString(md))
		spsso := doc.FindElement("//SPSSODescriptor")
		assert.Assert(t, spsso != nil)
		sig := etree.NewDocument()
		assert.NilError(t, sig.ReadFromString(fakeSignature))
		spsso.InsertChildAt(0, sig.Root())
		rv, err := doc.WriteToString()
		assert.NilError(t, err)
		return rv
	}

	t.Run("SPSSODescriptor signature", func(t *testing.T) {
		test := NewServerTest(t)
		metadata := signDescriptor(t, unsigned(t, test))
		assert.Check(t, is.Equal(http.StatusNoContent, putService(t, test, metadata)))
		assertStoredAsReceived(t, test, metadata)
	})

	t.Run("signed EntityDescriptor in signed EntitiesDescriptor", func(t *testing.T) {
		test := NewServerTest(t)
		entity := signDescriptor(t, unsigned(t, test))
		entity = strings.Replace(entity, "<SPSSODescriptor", fakeSignature+"<SPSSODescriptor", 1)
		metadata := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
			fakeSignature + entity + `</EntitiesDescriptor>`
		assert.Check(t, is.Equal(http.StatusNoContent, putService(t, test, metadata)))
		assertStoredAsReceived(t, test, metadata)
	})
}

func TestStoredServiceWithSignatureLoads(t *testing.T) {
	// A service stored by an earlier version, without RawMetadata, has its
	// Signature JSON-encoded in the store. It must load, without the
	// signature, which cannot be decoded from JSON.
	test := NewServerTest(t)
	el, err := test.SP.SignedMetadata()
	assert.NilError(t, err)
	var md saml.EntityDescriptor
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	assert.NilError(t, xml.Unmarshal(buf, &md))
	assert.Assert(t, md.Signature != nil)
	sig := etree.NewDocument()
	assert.NilError(t, sig.ReadFromString(fakeSignature))
	md.SPSSODescriptors[0].Signature = sig.Root()

	assert.NilError(t, test.Store.Put("/services/sp", &Service{Name: "sp", Metadata: md}))

	var service Service
	assert.NilError(t, test.Store.Get("/services/sp", &service))
	assert.Check(t, is.Equal(signedSPEntityID, service.Metadata.EntityID))
	assert.Check(t, is.Len(service.RawMetadata, 0))
	assert.Check(t, !hasSignature(&service.Metadata))

	w := getService(t, test)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code))
	var got saml.EntityDescriptor
	assert.NilError(t, xml.Unmarshal(w.Body.Bytes(), &got))
	assert.Check(t, is.Equal(signedSPEntityID, got.EntityID))

	assertRegisteredAfterRestart(t, test)
}

func TestStoredLegacyServiceWithoutSignatureUnchanged(t *testing.T) {
	// A service stored by an earlier version without signatures decodes as
	// it always did.
	test := NewServerTest(t)
	md, err := getSPMetadata(strings.NewReader(unsignedSPMetadata(t, test.SP)))
	assert.NilError(t, err)
	assert.NilError(t, test.Store.Put("/services/sp", &Service{Name: "sp", Metadata: *md}))

	var service Service
	assert.NilError(t, test.Store.Get("/services/sp", &service))
	assert.Check(t, is.DeepEqual(md.SPSSODescriptors[0].AssertionConsumerServices, service.Metadata.SPSSODescriptors[0].AssertionConsumerServices))
	assertRegisteredAfterRestart(t, test)
}

func TestPutServiceWithSPMetadataCertificatesStoresReadably(t *testing.T) {
	test := NewServerTest(t)
	test.Server.SPMetadataCertificates = []*x509.Certificate{test.SPCertificate}

	metadata := signedSPMetadata(t, test.SP)
	assert.Check(t, is.Equal(http.StatusNoContent, putService(t, test, metadata)))
	assertStoredAsReceived(t, test, metadata)
}
