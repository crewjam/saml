package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func newTestECDSAKeyAndCert(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, cert
}

func spKeyDescriptorCerts(t *testing.T, md *EntityDescriptor) map[string]string {
	t.Helper()
	certs := map[string]string{}
	for _, kd := range md.SPSSODescriptors[0].KeyDescriptors {
		assert.Assert(t, is.Len(kd.KeyInfo.X509Data.X509Certificates, 1))
		certs[kd.Use] = kd.KeyInfo.X509Data.X509Certificates[0].Data
	}
	return certs
}

// An ECDSA key cannot be used for XML encryption, so the metadata must not
// advertise it for encryption.
func TestSPMetadataOmitsEncryptionKeyForECDSACertificate(t *testing.T) {
	ecKey, ecCert := newTestECDSAKeyAndCert(t)
	s := ServiceProvider{
		Key:             ecKey,
		Certificate:     ecCert,
		SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
		MetadataURL:     mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://example.com/saml2/acs"),
	}

	certs := spKeyDescriptorCerts(t, s.Metadata())
	assert.Check(t, is.DeepEqual(map[string]string{
		"signing": base64.StdEncoding.EncodeToString(ecCert.Raw),
	}, certs))
}

func TestSPMetadataAdvertisesSeparateEncryptionCertificate(t *testing.T) {
	test := NewServiceProviderTest(t)
	ecKey, ecCert := newTestECDSAKeyAndCert(t)
	s := ServiceProvider{
		Key:                   ecKey,
		Certificate:           ecCert,
		EncryptionKey:         test.Key,
		EncryptionCertificate: test.Certificate,
		SignatureMethod:       "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
		MetadataURL:           mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:                mustParseURL("https://example.com/saml2/acs"),
	}

	certs := spKeyDescriptorCerts(t, s.Metadata())
	assert.Check(t, is.DeepEqual(map[string]string{
		"signing":    base64.StdEncoding.EncodeToString(ecCert.Raw),
		"encryption": base64.StdEncoding.EncodeToString(test.Certificate.Raw),
	}, certs))

	// Without a signature method only the encryption key is advertised.
	s.SignatureMethod = ""
	certs = spKeyDescriptorCerts(t, s.Metadata())
	assert.Check(t, is.DeepEqual(map[string]string{
		"encryption": base64.StdEncoding.EncodeToString(test.Certificate.Raw),
	}, certs))
}

// The SP decrypts assertions with EncryptionKey, even when Key is an ECDSA
// key that could not decrypt them.
func TestSPDecryptsWithSeparateEncryptionKey(t *testing.T) {
	test := NewServiceProviderTest(t)
	ecKey, ecCert := newTestECDSAKeyAndCert(t)
	newSP := func() *ServiceProvider {
		s := &ServiceProvider{
			Key:         ecKey,
			Certificate: ecCert,
			MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
			AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
			IDPMetadata: &EntityDescriptor{},
		}
		assert.NilError(t, xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata))
		return s
	}
	parse := func(s *ServiceProvider) (*Assertion, error) {
		req := http.Request{PostForm: url.Values{}, URL: &s.AcsURL}
		req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
		return s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	}

	// With only the ECDSA key, the encrypted assertion cannot be decrypted.
	_, err := parse(newSP())
	assert.Check(t, err != nil)

	s := newSP()
	s.EncryptionKey = test.Key
	s.EncryptionCertificate = test.Certificate
	assertion, err := parse(s)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("_41bd295976dadd70e1480f318e772841", assertion.Subject.NameID.Value))
}
