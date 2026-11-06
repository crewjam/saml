package xmlenc

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
)

// RSA implements Encrypter and Decrypter using RSA public key encryption.
//
// Use function like OAEP(), or PKCS1v15() to get an instance of this type ready
// to use.
type RSA struct {
	BlockCipher  BlockCipher
	DigestMethod DigestMethod // only for OAEP

	mgfHash      crypto.Hash // set by Decrypt for the XML Encryption 1.1 RSA-OAEP algorithm
	algorithm    string
	keyEncrypter func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error)
	keyDecrypter func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error)
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
	if e.algorithm == rsaOAEP11Algorithm {
		hash, ok := cryptoHashOf(e.DigestMethod)
		if !ok {
			return nil, ErrAlgorithmNotImplemented(e.DigestMethod.Algorithm())
		}
		mgfAlgorithm, ok := mgfAlgorithmFor(hash)
		if !ok {
			return nil, ErrAlgorithmNotImplemented(e.DigestMethod.Algorithm())
		}
		mgf := encryptionMethodEl.CreateElement("xenc11:MGF")
		mgf.CreateAttr("Algorithm", mgfAlgorithm)
		mgf.CreateAttr("xmlns:xenc11", "http://www.w3.org/2009/xmlenc11#")
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

	if e.algorithm == rsaOAEP11Algorithm {
		// XML Encryption 1.1 section 5.5.2: without an MGF element, the mask
		// generation function is MGF1 with SHA-1.
		e.mgfHash = crypto.SHA1
		if mgfEl := ciphertextEl.FindElement("./EncryptionMethod/MGF"); mgfEl != nil {
			mgfAlgorithm := mgfEl.SelectAttrValue("Algorithm", "")
			mgfHash, ok := mgfAlgorithms[mgfAlgorithm]
			if !ok {
				return nil, ErrAlgorithmNotImplemented(mgfAlgorithm)
			}
			e.mgfHash = mgfHash
		}
	}

	return e.keyDecrypter(e, rsaKey, ciphertext)
}

// OAEP returns a version of RSA that implements RSA in OAEP-MGF1P mode. By default
// the block cipher used is AES-256 CBC and the digest method is SHA-256. You can
// specify other ciphers and digest methods by assigning to BlockCipher or
// DigestMethod.
//
// OAEP implements the older RSA-OAEP (2001 spec) for backward compatibility, you might
// perfer OAEP_2009_256 over using this method.
func OAEP() RSA {
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: SHA256,
		algorithm:    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
		keyEncrypter: func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptOAEP(e.DigestMethod.Hash(), RandReader, pubKey, plaintext, nil)
		},
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			return rsa.DecryptOAEP(e.DigestMethod.Hash(), RandReader, privKey, ciphertext, nil)
		},
	}
}

// rsaOAEP11Algorithm is the XML Encryption 1.1 RSA-OAEP key transport
// algorithm. Unlike rsa-oaep-mgf1p, its mask generation function is named by an
// optional xenc11:MGF element and defaults to MGF1 with SHA-1.
const rsaOAEP11Algorithm = "http://www.w3.org/2009/xmlenc11#rsa-oaep"

// mgfAlgorithms maps the XML Encryption 1.1 mask generation function URIs to
// the hash used by MGF1.
var mgfAlgorithms = map[string]crypto.Hash{
	"http://www.w3.org/2009/xmlenc11#mgf1sha1":   crypto.SHA1,
	"http://www.w3.org/2009/xmlenc11#mgf1sha224": crypto.SHA224,
	"http://www.w3.org/2009/xmlenc11#mgf1sha256": crypto.SHA256,
	"http://www.w3.org/2009/xmlenc11#mgf1sha384": crypto.SHA384,
	"http://www.w3.org/2009/xmlenc11#mgf1sha512": crypto.SHA512,
}

// cryptoHashOf returns the crypto.Hash that computes the same digest as dm.
func cryptoHashOf(dm DigestMethod) (crypto.Hash, bool) {
	want := dm.Hash().Sum(nil)
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.RIPEMD160} {
		if h.Available() && bytes.Equal(h.New().Sum(nil), want) {
			return h, true
		}
	}
	return 0, false
}

// mgfAlgorithmFor returns the MGF URI for MGF1 with hash h.
func mgfAlgorithmFor(h crypto.Hash) (string, bool) {
	for uri, mgfHash := range mgfAlgorithms {
		if mgfHash == h {
			return uri, true
		}
	}
	return "", false
}

func oaep11(digestMethod DigestMethod) RSA {
	return RSA{
		BlockCipher:  AES256CBC,
		DigestMethod: digestMethod,
		algorithm:    rsaOAEP11Algorithm,

		// The encrypter uses the digest hash for MGF1 too, and Encrypt names it
		// in an xenc11:MGF element.
		keyEncrypter: func(e RSA, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
			return rsa.EncryptOAEP(e.DigestMethod.Hash(), RandReader, pubKey, plaintext, nil)
		},
		keyDecrypter: func(e RSA, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
			hash, ok := cryptoHashOf(e.DigestMethod)
			if !ok {
				return nil, ErrAlgorithmNotImplemented(e.DigestMethod.Algorithm())
			}
			return privKey.Decrypt(RandReader, ciphertext, &rsa.OAEPOptions{Hash: hash, MGFHash: e.mgfHash})
		},
	}
}

// OAEP_SHA256 returns a version of RSA that implements the XML Encryption 1.1
// RSA-OAEP algorithm. By default the block cipher used is AES-256 CBC and the
// digest method (and MGF1 hash) is SHA-256. You can specify other ciphers and
// digest methods by assigning to BlockCipher or DigestMethod.
//
// When decrypting, the digest and MGF1 hash are taken from the document, so
// OAEP_SHA256 and OAEP_SHA512 decrypt the same documents.
func OAEP_SHA256() RSA { //nolint:revive
	return oaep11(SHA256)
}

// OAEP_SHA512 returns a version of RSA that implements the XML Encryption 1.1
// RSA-OAEP algorithm. By default the block cipher used is AES-256 CBC and the
// digest method (and MGF1 hash) is SHA-512. You can specify other ciphers and
// digest methods by assigning to BlockCipher or DigestMethod.
func OAEP_SHA512() RSA { //nolint:revive
	return oaep11(SHA512)
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
//
// OAEP_SHA256 and OAEP_SHA512 share an algorithm URI and take the digest from
// the document when decrypting, so registering one covers both.
func init() {
	RegisterDecrypter(OAEP())
	RegisterDecrypter(OAEP_SHA256())
}
