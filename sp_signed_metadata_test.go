package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// validateSignedMetadata serializes el, parses it again, as a consumer
// would, and validates its signature against cert. It returns the parsed
// root element.
func validateSignedMetadata(t *testing.T, el *etree.Element, cert *x509.Certificate) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	parsed := etree.NewDocument()
	assert.NilError(t, parsed.ReadFromBytes(buf))
	root := parsed.Root()

	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	validationContext.Clock = dsig.NewFakeClockAt(cert.NotBefore)
	_, err = validationContext.Validate(root)
	assert.NilError(t, err)
	return root
}

func signatureMethodOf(t *testing.T, root *etree.Element) string {
	t.Helper()
	sigMethod := root.FindElement("./Signature/SignedInfo/SignatureMethod")
	assert.Assert(t, sigMethod != nil)
	return sigMethod.SelectAttrValue("Algorithm", "")
}

func TestSPSignedMetadata(t *testing.T) {
	test := NewServiceProviderTest(t)
	newSP := func() *ServiceProvider {
		return &ServiceProvider{
			Key:         test.Key,
			Certificate: test.Certificate,
			MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
			AcsURL:      mustParseURL("https://example.com/saml2/acs"),
			IDPMetadata: &EntityDescriptor{},
		}
	}

	t.Run("without request signing", func(t *testing.T) {
		// Signing metadata does not depend on SignatureMethod, which also
		// turns on request signing.
		sp := newSP()
		el, err := sp.SignedMetadata()
		assert.NilError(t, err)
		root := validateSignedMetadata(t, el, test.Certificate)

		assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, signatureMethodOf(t, root)))
		first := root.ChildElements()[0]
		assert.Check(t, is.Equal("Signature", first.Tag))
		assert.Check(t, root.SelectAttrValue("ID", "") != "")
		// AuthnRequestsSigned still reflects SignatureMethod
		assert.Check(t, is.Equal("false", root.FindElement("./SPSSODescriptor").SelectAttrValue("AuthnRequestsSigned", "")))
	})

	t.Run("uses SignatureMethod when set", func(t *testing.T) {
		sp := newSP()
		sp.SignatureMethod = dsig.RSASHA512SignatureMethod
		el, err := sp.SignedMetadata()
		assert.NilError(t, err)
		root := validateSignedMetadata(t, el, test.Certificate)
		assert.Check(t, is.Equal(dsig.RSASHA512SignatureMethod, signatureMethodOf(t, root)))
	})

	t.Run("ECDSA key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.NilError(t, err)
		cert := selfSignedCert(t, key)
		sp := newSP()
		sp.Key = key
		sp.Certificate = cert
		el, err := sp.SignedMetadata()
		assert.NilError(t, err)
		root := validateSignedMetadata(t, el, cert)
		assert.Check(t, is.Equal(dsig.ECDSASHA256SignatureMethod, signatureMethodOf(t, root)))
	})

	t.Run("nil key is an error", func(t *testing.T) {
		sp := newSP()
		sp.Key = nil
		_, err := sp.SignedMetadata()
		assert.Check(t, err != nil)
	})

	t.Run("nil certificate is an error", func(t *testing.T) {
		sp := newSP()
		sp.Certificate = nil
		_, err := sp.SignedMetadata()
		assert.Check(t, err != nil)
	})
}
