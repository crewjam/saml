package xmlenc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// covKeyTransportRoundTrip encrypts plaintext with e, unwraps the session key
// with e directly (so it works for key transports that are not registered as
// decrypters), and then decrypts the data with e.BlockCipher.
func covKeyTransportRoundTrip(t *testing.T, e RSA, key *rsa.PrivateKey, cert *x509.Certificate, plaintext []byte) {
	t.Helper()
	el, err := e.Encrypt(cert, plaintext, nil)
	assert.NilError(t, err)

	keyInfo := el.FindElement("./KeyInfo")
	ek := keyInfo.FindElement("./EncryptedKey")
	sessionKey, err := e.Decrypt(key, ek)
	assert.NilError(t, err)
	assert.Check(t, is.Len(sessionKey, e.BlockCipher.KeySize()))

	el.RemoveChild(keyInfo)
	got, err := e.BlockCipher.Decrypt(sessionKey, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(plaintext, got))
}

func TestCovKeyTransports(t *testing.T) {
	key, cert := newKeyAndCert(t)
	plaintext := []byte("<Assertion>hi</Assertion>")

	for name, e := range map[string]RSA{
		"OAEP":        OAEP(),
		"OAEP_SHA256": OAEP_SHA256(),
		"OAEP_SHA384": OAEP_SHA384(),
		"OAEP_SHA512": OAEP_SHA512(),
		"PKCS1v15":    PKCS1v15(),
	} {
		t.Run(name, func(t *testing.T) {
			covKeyTransportRoundTrip(t, e, key, cert, plaintext)
		})
	}
	t.Run("OAEP_SHA256 with GCM", func(t *testing.T) {
		e := OAEP_SHA256()
		e.BlockCipher = AES256GCM
		covKeyTransportRoundTrip(t, e, key, cert, plaintext)
	})

	assert.Check(t, is.Equal("http://www.w3.org/2009/xmlenc11#rsa-oaep", OAEP_SHA256().Algorithm()))
	assert.Check(t, is.Equal(SHA256.Algorithm(), OAEP_SHA256().DigestMethod.Algorithm()))
	assert.Check(t, is.Equal(SHA384.Algorithm(), OAEP_SHA384().DigestMethod.Algorithm()))
	assert.Check(t, is.Equal(SHA512.Algorithm(), OAEP_SHA512().DigestMethod.Algorithm()))
	assert.Check(t, PKCS1v15().DigestMethod == nil)
}

// Without a DigestMethod element, RSA-OAEP-MGF1P defaults to SHA-1.
func TestCovOAEPDefaultsToSHA1(t *testing.T) {
	key, cert := newKeyAndCert(t)
	e := OAEP()
	e.DigestMethod = SHA1
	el, err := e.Encrypt(cert, []byte("x"), nil)
	assert.NilError(t, err)
	dm := el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod/DigestMethod")
	dm.Parent().RemoveChild(dm)

	got, err := Decrypt(key, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual([]byte("x"), got))
}

func TestCovRSAEncryptErrors(t *testing.T) {
	_, cert := newKeyAndCert(t)

	t.Run("not a certificate", func(t *testing.T) {
		_, err := OAEP().Encrypt(cert.Raw, []byte("x"), nil)
		assert.Check(t, is.Error(err, ErrIncorrectKeyType("*x.509 certificate").Error()))
	})
	t.Run("not an RSA certificate", func(t *testing.T) {
		_, err := OAEP().Encrypt(covECDSACert(t), []byte("x"), nil)
		assert.Check(t, is.Error(err, ErrIncorrectKeyType("x.509 certificate with an RSA public key").Error()))
	})
	t.Run("rand for session key", func(t *testing.T) {
		covSetRandReader(t, &covFailingReader{ok: 0})
		_, err := OAEP().Encrypt(cert, []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovRand))
	})
	t.Run("rand for Id", func(t *testing.T) {
		covSetRandReader(t, &covFailingReader{ok: 1})
		_, err := OAEP().Encrypt(cert, []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovRand))
	})
	t.Run("key encryption", func(t *testing.T) {
		// OAEP with SHA-512 needs 2*64+2 bytes of overhead, more than a 1024
		// bit modulus leaves room for.
		smallKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately too small
		assert.NilError(t, err)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "small.example.com"},
			NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &smallKey.PublicKey, smallKey)
		assert.NilError(t, err)
		smallCert, err := x509.ParseCertificate(der)
		assert.NilError(t, err)

		_, err = OAEP_SHA512().Encrypt(smallCert, []byte("x"), nil)
		assert.Check(t, errors.Is(err, rsa.ErrMessageTooLong))
	})
	t.Run("block cipher", func(t *testing.T) {
		e := OAEP()
		e.BlockCipher = CBC{keySize: 32, algorithm: "cov", cipher: covFailingCipher}
		_, err := e.Encrypt(cert, []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovCipher))
	})
}

func TestCovRSADecryptErrors(t *testing.T) {
	key, cert := newKeyAndCert(t)
	el, err := OAEP().Encrypt(cert, []byte("x"), nil)
	assert.NilError(t, err)
	ek := el.FindElement("./KeyInfo/EncryptedKey")

	t.Run("not an RSA key", func(t *testing.T) {
		_, err := OAEP().Decrypt([]byte("k"), ek)
		assert.Check(t, is.Error(err, "expected key to be a *rsa.PrivateKey"))
	})
	t.Run("no cipher value", func(t *testing.T) {
		_, err := OAEP().Decrypt(key, etree.NewElement("EncryptedKey"))
		assert.Check(t, is.ErrorContains(err, "cannot find CipherData"))
	})
	t.Run("unknown digest method", func(t *testing.T) {
		ek := ek.Copy()
		ek.FindElement("./EncryptionMethod/DigestMethod").CreateAttr("Algorithm", "cov:digest")
		_, err := OAEP().Decrypt(key, ek)
		assert.Check(t, is.Error(err, ErrAlgorithmNotImplemented("cov:digest").Error()))
	})
	t.Run("wrong digest method", func(t *testing.T) {
		ek := ek.Copy()
		ek.FindElement("./EncryptionMethod/DigestMethod").CreateAttr("Algorithm", SHA512.Algorithm())
		_, err := OAEP().Decrypt(key, ek)
		assert.Check(t, errors.Is(err, rsa.ErrDecryption))
	})
	t.Run("PKCS1v15 malformed", func(t *testing.T) {
		ek := ek.Copy()
		ek.FindElement("./CipherData/CipherValue").SetText("AAAA")
		_, err := PKCS1v15().Decrypt(key, ek)
		assert.Check(t, err != nil)
	})
}
