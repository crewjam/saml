package xmlenc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// newKeyAndCert returns an RSA key and a self-signed certificate for it, as
// Encrypt takes the recipient's certificate and Decrypt its key.
func newKeyAndCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, cert
}

// RSA PKCS#1 v1.5 key transport is open to Bleichenbacher padding-oracle
// attacks, so a document that names it is refused.
func TestPKCS1v15KeyTransportIsNotDecrypted(t *testing.T) {
	key, cert := newKeyAndCert(t)
	el, err := PKCS1v15().Encrypt(cert, []byte("hello"), nil)
	assert.NilError(t, err)

	_, err = Decrypt(key, el)
	assert.Check(t, is.Error(err, ErrAlgorithmNotImplemented("http://www.w3.org/2001/04/xmlenc#rsa-1_5").Error()))
}

// RSA-OAEP key transport, which service provider metadata advertises, still
// decrypts.
func TestOAEPKeyTransportIsDecrypted(t *testing.T) {
	key, cert := newKeyAndCert(t)
	el, err := OAEP().Encrypt(cert, []byte("hello"), nil)
	assert.NilError(t, err)

	plaintext, err := Decrypt(key, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual([]byte("hello"), plaintext))
}
