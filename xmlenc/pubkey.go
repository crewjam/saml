package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// RSA implements Encrypter and Decrypter using RSA public key encryption.
//
// Use function like OAEP(), or PKCS1v15() to get an instance of this type ready
// to use.
type RSA struct {
	BlockCipher  BlockCipher
	DigestMethod DigestMethod // only for OAEP

	algorithm    string
	keyEncrypter func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error)
	keyDecrypter func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error)

	// The fields below are only set while decrypting, from the EncryptionMethod
	// element of the document.
	mgfHash   crypto.Hash // 0 when the document has no MGF element
	oaepLabel []byte
}

// Algorithm returns the name of the algorithm
func (e RSA) Algorithm() string {
	return e.algorithm
}

// Encrypt implements encrypter. certificate must be a []byte containing the ASN.1 bytes
// of certificate containing an RSA public key.
func (e RSA) Encrypt(certificate interface{}, plaintext []byte, nonce []byte) (*etree.Element, error) {
	cert, ok := certificate.(*x509.Certificate)
	if !ok {
		return nil, ErrIncorrectKeyType("*x.509 certificate")
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, ErrIncorrectKeyType("x.509 certificate with an RSA public key")
	}

	// generate a key
	key := make([]byte, e.BlockCipher.KeySize())
	if _, err := RandReader.Read(key); err != nil {
		return nil, err
	}

	keyInfoEl := etree.NewElement("ds:KeyInfo")
	keyInfoEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	encryptedKey := keyInfoEl.CreateElement("xenc:EncryptedKey")
	{
		randBuf := make([]byte, 16)
		if _, err := RandReader.Read(randBuf); err != nil {
			return nil, err
		}
		encryptedKey.CreateAttr("Id", fmt.Sprintf("_%x", randBuf))
	}
	encryptedKey.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")

	encryptionMethodEl := encryptedKey.CreateElement("xenc:EncryptionMethod")
	encryptionMethodEl.CreateAttr("Algorithm", e.algorithm)
	encryptionMethodEl.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	if e.DigestMethod != nil {
		dm := encryptionMethodEl.CreateElement("ds:DigestMethod")
		dm.CreateAttr("Algorithm", e.DigestMethod.Algorithm())
		dm.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	}
	if e.algorithm == algorithmRSAOAEP11 {
		mgfURI, err := mgfURIFor(e.DigestMethod)
		if err != nil {
			return nil, err
		}
		mgfEl := encryptionMethodEl.CreateElement("xenc11:MGF")
		mgfEl.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
		mgfEl.CreateAttr("Algorithm", mgfURI)
	}
	{
		innerKeyInfoEl := encryptedKey.CreateElement("ds:KeyInfo")
		x509data := innerKeyInfoEl.CreateElement("ds:X509Data")
		x509data.CreateElement("ds:X509Certificate").SetText(
			base64.StdEncoding.EncodeToString(cert.Raw),
		)
	}

	buf, err := e.keyEncrypter(e, pubKey, key)
	if err != nil {
		return nil, err
	}

	cd := encryptedKey.CreateElement("xenc:CipherData")
	cd.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	cd.CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(buf))
	encryptedDataEl, err := e.BlockCipher.Encrypt(key, plaintext, nonce)
	if err != nil {
		return nil, err
	}
	encryptedDataEl.InsertChildAt(encryptedDataEl.FindElement("./CipherData").Index(), keyInfoEl)

	return encryptedDataEl, nil
}

// Decrypt implements Decryptor. `key` must be an *rsa.PrivateKey.
func (e RSA) Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error) {
	rsaKey, err := validateRSAKeyIfPresent(key, ciphertextEl)
	if err != nil {
		return nil, err
	}

	ciphertext, err := getCiphertext(ciphertextEl)
	if err != nil {
		return nil, err
	}

	{
		digestMethodEl := ciphertextEl.FindElement("./EncryptionMethod/DigestMethod")
		if digestMethodEl == nil {
			e.DigestMethod = SHA1
		} else {
			hashAlgorithmStr := digestMethodEl.SelectAttrValue("Algorithm", "")
			digestMethod, ok := digestMethods[hashAlgorithmStr]
			if !ok {
				return nil, ErrAlgorithmNotImplemented(hashAlgorithmStr)
			}
			e.DigestMethod = digestMethod
		}
	}

	e.mgfHash = 0
	if mgfEl := ciphertextEl.FindElement("./EncryptionMethod/MGF"); mgfEl != nil {
		if e.algorithm != algorithmRSAOAEP11 {
			return nil, ErrAlgorithmNotImplemented("MGF with " + e.algorithm)
		}
		mgfURI := mgfEl.SelectAttrValue("Algorithm", "")
		h, ok := mgfHashes[mgfURI]
		if !ok {
			return nil, ErrAlgorithmNotImplemented(mgfURI)
		}
		e.mgfHash = h
	}

	e.oaepLabel = nil
	if paramsEl := ciphertextEl.FindElement("./EncryptionMethod/OAEPparams"); paramsEl != nil {
		label, err := base64.StdEncoding.DecodeString(strings.TrimSpace(paramsEl.Text()))
		if err != nil {
			return nil, fmt.Errorf("cannot decode OAEPparams: %w", err)
		}
		e.oaepLabel = label
	}

	return e.keyDecrypter(e, rsaKey, ciphertext)
}

// OAEP returns a version of RSA that implements RSA in OAEP-MGF1P mode. By default
// the block cipher used is AES-256 CBC and the digest method is SHA-256. You can
// specify other ciphers and digest methods by assigning to BlockCipher or
// DigestMethod. As the algorithm name says, the mask generation function is
// always MGF1 with SHA-1, whatever the digest method.
//
// OAEP implements the older RSA-OAEP (2001 spec) for backward compatibility, you might
// prefer OAEP_SHA256 over using this method.
func OAEP() RSA {
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: SHA256,
		algorithm:    algorithmRSAOAEPMGF1P,
		keyEncrypter: func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return encryptOAEP(e.DigestMethod, crypto.SHA1, pubKey, plaintext)
		},
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return decryptOAEP(e.DigestMethod, crypto.SHA1, true, e.oaepLabel, privKey, ciphertext)
		},
	}
}

// OAEP_SHA256 returns a version of RSA that implements RSA in OAEP mode
// (XML Encryption 1.1). By default the block cipher used is AES-256 CBC and the
// digest method is SHA-256. You can specify other ciphers and digest methods by
// assigning to BlockCipher or DigestMethod. The mask generation function is
// MGF1 with the same hash as the digest method, and is stated in the output.
func OAEP_SHA256() RSA { //nolint:revive
	e := oaep11()
	e.DigestMethod = SHA256
	return e
}

// OAEP_SHA384 returns a version of RSA that implements RSA in OAEP mode
// (XML Encryption 1.1). By default the block cipher used is AES-256 CBC and the
// digest method is SHA-384. You can specify other ciphers and digest methods by
// assigning to BlockCipher or DigestMethod. The mask generation function is
// MGF1 with the same hash as the digest method, and is stated in the output.
func OAEP_SHA384() RSA { //nolint:revive
	e := oaep11()
	e.DigestMethod = SHA384
	return e
}

// OAEP_SHA512 returns a version of RSA that implements RSA in OAEP mode
// (XML Encryption 1.1). By default the block cipher used is AES-256 CBC and the
// digest method is SHA-512. You can specify other ciphers and digest methods by
// assigning to BlockCipher or DigestMethod. The mask generation function is
// MGF1 with the same hash as the digest method, and is stated in the output.
func OAEP_SHA512() RSA { //nolint:revive
	e := oaep11()
	e.DigestMethod = SHA512
	return e
}

func oaep11() RSA {
	return RSA{
		BlockCipher: AES256CBC,
		algorithm:   algorithmRSAOAEP11,
		keyEncrypter: func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			mgfHash, err := cryptoHashOf(e.DigestMethod)
			if err != nil {
				return nil, err
			}
			return encryptOAEP(e.DigestMethod, mgfHash, pubKey, plaintext)
		},
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			mgfHash := e.mgfHash
			if mgfHash == 0 {
				// The XML Encryption 1.1 default when no MGF element is given.
				mgfHash = crypto.SHA1
			}
			return decryptOAEP(e.DigestMethod, mgfHash, e.mgfHash == 0, e.oaepLabel, privKey, ciphertext)
		},
	}
}

// PKCS1v15 returns a version of RSA that implements RSA in PKCS1v15 mode. By default
// the block cipher used is AES-256 CBC. The DigestMethod field is ignored because PKCS1v15
// does not use a digest function.
func PKCS1v15() RSA {
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: nil,
		algorithm:    "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
		keyEncrypter: func(_ RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptPKCS1v15(RandReader, pubKey, plaintext) //nolint:staticcheck // SA1019: rsa-1_5 is an XML-Enc algorithm; opt-in only, see note below
		},
		keyDecrypter: func(_ RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return rsa.DecryptPKCS1v15(RandReader, privKey, ciphertext) //nolint:staticcheck // SA1019: rsa-1_5 is an XML-Enc algorithm; opt-in only, see note below
		},
	}
}

// PKCS1v15 is not registered as a decrypter. RSA PKCS#1 v1.5 key transport is
// open to Bleichenbacher padding-oracle attacks, so a document naming rsa-1_5
// gets ErrAlgorithmNotImplemented. Service provider metadata advertises
// rsa-oaep-mgf1p only.
func init() {
	RegisterDecrypter(OAEP())
	RegisterDecrypter(oaep11())
}
