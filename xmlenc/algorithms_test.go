package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
)

// TestRegisteredDigestMethodURIs asserts that the digest methods are registered
// under the URIs assigned by RFC 4051, which is what other implementations send,
// as well as under the URIs earlier releases of this package emitted.
func TestRegisteredDigestMethodURIs(t *testing.T) {
	for _, uri := range []string{
		"http://www.w3.org/2000/09/xmldsig#sha1",
		"http://www.w3.org/2001/04/xmlenc#sha256",
		"http://www.w3.org/2001/04/xmlenc#sha512",
		"http://www.w3.org/2001/04/xmlenc#ripemd160",
		"http://www.w3.org/2000/09/xmldsig#sha256",
		"http://www.w3.org/2000/09/xmldsig#sha512",
		"http://www.w3.org/2000/09/xmldsig#ripemd160",
	} {
		_, ok := digestMethods[uri]
		assert.Check(t, ok, "digest method not registered: %s", uri)
	}
}

// TestRegisteredGCMDecrypters asserts that every AES-GCM key size is available,
// mirroring what cbc.go already provides for AES-CBC.
func TestRegisteredGCMDecrypters(t *testing.T) {
	for _, uri := range []string{
		"http://www.w3.org/2009/xmlenc11#aes128-gcm",
		"http://www.w3.org/2009/xmlenc11#aes192-gcm",
		"http://www.w3.org/2009/xmlenc11#aes256-gcm",
	} {
		_, ok := decrypters[uri]
		assert.Check(t, ok, "decrypter not registered: %s", uri)
	}
}

// TestDecryptAES256GCMWithOAEPSHA256 decrypts a document shaped the way
// interoperating identity providers emit it by default: the data encrypted with
// AES-256-GCM and the session key wrapped with RSA-OAEP using a SHA-256 digest
// identified by its RFC 4051 URI.
func TestDecryptAES256GCMWithOAEPSHA256(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)

	plaintext := []byte("<Assertion>hello</Assertion>")

	sessionKey := make([]byte, 32)
	_, err = rand.Read(sessionKey)
	assert.NilError(t, err)

	block, err := aes.NewCipher(sessionKey)
	assert.NilError(t, err)
	aesgcm, err := cipher.NewGCM(block)
	assert.NilError(t, err)
	nonce := make([]byte, aesgcm.NonceSize())
	_, err = rand.Read(nonce)
	assert.NilError(t, err)
	cipherValue := append(nonce, aesgcm.Seal(nil, nonce, plaintext, nil)...) //nolint:gocritic

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &privKey.PublicKey, sessionKey, nil)
	assert.NilError(t, err)

	doc := etree.NewDocument()
	el := doc.CreateElement("EncryptedData")
	em := el.CreateElement("EncryptionMethod")
	em.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#aes256-gcm")

	ek := el.CreateElement("KeyInfo").CreateElement("EncryptedKey")
	kem := ek.CreateElement("EncryptionMethod")
	kem.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
	dm := kem.CreateElement("DigestMethod")
	dm.CreateAttr("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	ek.CreateElement("CipherData").CreateElement("CipherValue").
		SetText(base64.StdEncoding.EncodeToString(wrappedKey))

	el.CreateElement("CipherData").CreateElement("CipherValue").
		SetText(base64.StdEncoding.EncodeToString(cipherValue))

	got, err := Decrypt(privKey, el)
	assert.NilError(t, err)
	assert.Equal(t, string(plaintext), string(got))
}
