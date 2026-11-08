package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

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

// issueCert creates a certificate for key, signed by parentKey as parent, or
// self-signed when parent is nil.
func issueCert(t *testing.T, serial int64, name string, isCA bool, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return cert
}

func TestSPSignaturesIncludeIntermediates(t *testing.T) {
	NewServiceProviderTest(t)
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		assert.NilError(t, err)
		return key
	}
	rootKey, intermediateKey, leafKey := newKey(), newKey(), newKey()
	root := issueCert(t, 1, "root", true, rootKey, nil, nil)
	intermediate := issueCert(t, 2, "intermediate", true, intermediateKey, root, rootKey)
	leaf := issueCert(t, 3, "sp.example.com", false, leafKey, intermediate, intermediateKey)

	sp := &ServiceProvider{
		Key:             leafKey,
		Certificate:     leaf,
		Intermediates:   []*x509.Certificate{intermediate},
		SignatureMethod: dsig.ECDSASHA256SignatureMethod,
		MetadataURL:     mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://sp.example.com/saml2/acs"),
		IDPMetadata:     &EntityDescriptor{},
	}

	// assertChain checks that sig's KeyInfo carries the leaf, then the
	// intermediate.
	assertChain := func(t *testing.T, sig *etree.Element) {
		t.Helper()
		assert.Assert(t, sig != nil)
		certEls := sig.FindElements("./KeyInfo/X509Data/X509Certificate")
		assert.Assert(t, is.Len(certEls, 2))
		for i, want := range []*x509.Certificate{leaf, intermediate} {
			got, err := base64.StdEncoding.DecodeString(certEls[i].Text())
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(want.Raw, got), "certificate %d", i)
		}
	}

	t.Run("AuthnRequest", func(t *testing.T) {
		req, err := sp.MakeAuthenticationRequest("https://idp.example.com/sso", HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		assertChain(t, req.Signature)
	})

	t.Run("LogoutRequest", func(t *testing.T) {
		req, err := sp.MakeLogoutRequest("https://idp.example.com/slo", "alice")
		assert.NilError(t, err)
		assertChain(t, req.Signature)
	})

	t.Run("metadata", func(t *testing.T) {
		el, err := sp.SignedMetadata()
		assert.NilError(t, err)
		// validates against the leaf, which comes first in KeyInfo
		root := validateSignedMetadata(t, el, leaf)
		assertChain(t, root.FindElement("./Signature"))
	})

	t.Run("no intermediates", func(t *testing.T) {
		noChain := *sp
		noChain.Intermediates = nil
		req, err := noChain.MakeAuthenticationRequest("https://idp.example.com/sso", HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		assert.Check(t, is.Len(req.Signature.FindElements("./KeyInfo/X509Data/X509Certificate"), 1))
	})
}

func TestSPSignEntityDescriptor(t *testing.T) {
	test := NewServiceProviderTest(t)
	sp := &ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	md := sp.Metadata()
	md.Organization = &Organization{
		OrganizationNames: []LocalizedName{{Lang: "en", Value: "Example"}},
	}
	el, err := sp.SignEntityDescriptor(md)
	assert.NilError(t, err)
	root := validateSignedMetadata(t, el, test.Certificate)
	assert.Check(t, is.Equal("Example", root.FindElement("./Organization/OrganizationName").Text()))
	assert.Check(t, md.Signature == nil, "the descriptor was modified")
}
