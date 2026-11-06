package xmlenc

import (
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestCovErrorStrings(t *testing.T) {
	assert.Check(t, is.Equal("algorithm is not implemented: x", ErrAlgorithmNotImplemented("x").Error()))
	assert.Check(t, is.Equal("cannot find required element: x", ErrCannotFindRequiredElement("x").Error()))
	assert.Check(t, is.Equal("expected key to be 16 bytes", ErrIncorrectKeyLength(16).Error()))
	assert.Check(t, is.Equal("expected key to be []byte", ErrIncorrectKeyType("[]byte").Error()))
}

func TestCovDecryptWithoutEncryptionMethod(t *testing.T) {
	el := etree.NewElement("EncryptedData")
	_, err := Decrypt([]byte{}, el)
	assert.Check(t, is.Error(err, ErrCannotFindRequiredElement("EncryptionMethod").Error()))
}

func TestCovGetCiphertext(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		_, err := getCiphertext(etree.NewElement("EncryptedData"))
		assert.Check(t, is.ErrorContains(err, "cannot find CipherData"))
	})
	t.Run("bad base64", func(t *testing.T) {
		el := etree.NewElement("EncryptedData")
		el.CreateElement("CipherData").CreateElement("CipherValue").SetText("!!not base64!!")
		_, err := getCiphertext(el)
		assert.Check(t, is.ErrorContains(err, "illegal base64"))
	})
	t.Run("surrounding whitespace", func(t *testing.T) {
		el := etree.NewElement("EncryptedData")
		el.CreateElement("CipherData").CreateElement("CipherValue").SetText("\n  aGVsbG8=\n ")
		buf, err := getCiphertext(el)
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual([]byte("hello"), buf))
	})
}

// covEncryptedKeyWithCert returns an EncryptedKey element whose KeyInfo holds
// certText as its X509Certificate.
func covEncryptedKeyWithCert(certText string) *etree.Element {
	el := etree.NewElement("EncryptedKey")
	el.CreateElement("KeyInfo").CreateElement("X509Data").CreateElement("X509Certificate").SetText(certText)
	return el
}

func TestCovValidateRSAKeyIfPresent(t *testing.T) {
	key, cert := newKeyAndCert(t)
	otherKey, _ := newKeyAndCert(t)

	t.Run("not an RSA key", func(t *testing.T) {
		_, err := validateRSAKeyIfPresent([]byte("k"), etree.NewElement("EncryptedKey"))
		assert.Check(t, is.Error(err, "expected key to be a *rsa.PrivateKey"))
	})
	t.Run("no key info", func(t *testing.T) {
		got, err := validateRSAKeyIfPresent(key, etree.NewElement("EncryptedKey"))
		assert.NilError(t, err)
		assert.Check(t, got == key)
	})
	t.Run("matching certificate", func(t *testing.T) {
		got, err := validateRSAKeyIfPresent(key, covEncryptedKeyWithCert(base64.StdEncoding.EncodeToString(cert.Raw)))
		assert.NilError(t, err)
		assert.Check(t, got == key)
	})
	t.Run("certificate for another key", func(t *testing.T) {
		_, err := validateRSAKeyIfPresent(otherKey, covEncryptedKeyWithCert(base64.StdEncoding.EncodeToString(cert.Raw)))
		assert.Check(t, is.Error(err, "certificate does not match provided key"))
	})
	t.Run("not base64", func(t *testing.T) {
		_, err := validateRSAKeyIfPresent(key, covEncryptedKeyWithCert("@@@"))
		assert.Check(t, is.Error(err, "invalid certificate"))
	})
	t.Run("not a certificate", func(t *testing.T) {
		_, err := validateRSAKeyIfPresent(key, covEncryptedKeyWithCert("AAAA"))
		assert.Check(t, is.ErrorContains(err, "x509"))
	})
	t.Run("ECDSA certificate", func(t *testing.T) {
		ecCert := covECDSACert(t)
		_, err := validateRSAKeyIfPresent(key, covEncryptedKeyWithCert(base64.StdEncoding.EncodeToString(ecCert.Raw)))
		assert.Check(t, is.Error(err, "expected certificate to be an *rsa.PublicKey"))
	})
	t.Run("issuer serial is accepted unverified", func(t *testing.T) {
		el := etree.NewElement("EncryptedKey")
		el.CreateElement("KeyInfo").CreateElement("X509Data").CreateElement("X509IssuerSerial")
		got, err := validateRSAKeyIfPresent(key, el)
		assert.NilError(t, err)
		assert.Check(t, got == key)
	})
}
