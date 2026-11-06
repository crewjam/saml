package xmlenc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
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

// XML Encryption 1.1 RSA-OAEP key transport, which OAEP_SHA256 and OAEP_SHA512
// produce, decrypts.
func TestOAEP11KeyTransportIsDecrypted(t *testing.T) {
	key, cert := newKeyAndCert(t)
	for name, e := range map[string]RSA{
		"OAEP_SHA256": OAEP_SHA256(),
		"OAEP_SHA512": OAEP_SHA512(),
	} {
		t.Run(name, func(t *testing.T) {
			el, err := e.Encrypt(cert, []byte("hello"), nil)
			assert.NilError(t, err)
			mgf := el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod/MGF")
			assert.Assert(t, mgf != nil, "MGF element missing")
			assert.Check(t, is.Equal(e.DigestMethod.Hash().Size()*8,
				map[string]int{
					"http://www.w3.org/2009/xmlenc11#mgf1sha256": 256,
					"http://www.w3.org/2009/xmlenc11#mgf1sha512": 512,
				}[mgf.SelectAttrValue("Algorithm", "")]))

			plaintext, err := Decrypt(key, el)
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual([]byte("hello"), plaintext))
		})
	}
}

// oaep11Document returns an EncryptedData element whose AES-256-CBC key is
// wrapped with XML Encryption 1.1 RSA-OAEP using the given digest and MGF1
// hashes. mgfURI is omitted from the document when empty.
func oaep11Document(t *testing.T, key *rsa.PrivateKey, digestURI string, hash crypto.Hash, mgfURI string, mgfHash crypto.Hash) *etree.Element {
	t.Helper()
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	assert.NilError(t, err)
	el, err := AES256CBC.Encrypt(sessionKey, []byte("hello"), nil)
	assert.NilError(t, err)

	wrapped, err := rsa.EncryptOAEPWithOptions(rand.Reader, &key.PublicKey, sessionKey,
		&rsa.OAEPOptions{Hash: hash, MGFHash: mgfHash})
	assert.NilError(t, err)

	ek := etree.NewElement("EncryptedKey")
	em := ek.CreateElement("EncryptionMethod")
	em.CreateAttr("Algorithm", "http://www.w3.org/2009/xmlenc11#rsa-oaep")
	em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestURI)
	if mgfURI != "" {
		em.CreateElement("xenc11:MGF").CreateAttr("Algorithm", mgfURI)
	}
	ek.CreateElement("CipherData").CreateElement("CipherValue").
		SetText(base64.StdEncoding.EncodeToString(wrapped))
	keyInfo := etree.NewElement("ds:KeyInfo")
	keyInfo.AddChild(ek)
	el.InsertChildAt(el.FindElement("./CipherData").Index(), keyInfo)
	return el
}

// Without an MGF element, XML Encryption 1.1 RSA-OAEP uses MGF1 with SHA-1
// regardless of the digest method.
func TestOAEP11DefaultsToMGF1SHA1(t *testing.T) {
	key, _ := newKeyAndCert(t)
	el := oaep11Document(t, key, "http://www.w3.org/2001/04/xmlenc#sha256", crypto.SHA256, "", crypto.SHA1)

	plaintext, err := Decrypt(key, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual([]byte("hello"), plaintext))
}

// An MGF element names the MGF1 hash, which may differ from the digest method.
func TestOAEP11HonoursMGFElement(t *testing.T) {
	key, _ := newKeyAndCert(t)
	el := oaep11Document(t, key, "http://www.w3.org/2000/09/xmldsig#sha1", crypto.SHA1,
		"http://www.w3.org/2009/xmlenc11#mgf1sha256", crypto.SHA256)

	plaintext, err := Decrypt(key, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual([]byte("hello"), plaintext))
}

func TestOAEP11UnknownMGF(t *testing.T) {
	key, _ := newKeyAndCert(t)
	el := oaep11Document(t, key, "http://www.w3.org/2001/04/xmlenc#sha256", crypto.SHA256,
		"http://example.com/mgf", crypto.SHA256)

	_, err := Decrypt(key, el)
	assert.Check(t, is.Error(err, ErrAlgorithmNotImplemented("http://example.com/mgf").Error()))
}
