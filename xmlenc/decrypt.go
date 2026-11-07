package xmlenc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"strings"

	"github.com/beevik/etree"
)

// ErrAlgorithmNotImplemented is returned when encryption used is not
// supported.
type ErrAlgorithmNotImplemented string

func (e ErrAlgorithmNotImplemented) Error() string {
	return "algorithm is not implemented: " + string(e)
}

// ErrCannotFindRequiredElement is returned by Decrypt when a required
// element cannot be found.
type ErrCannotFindRequiredElement string

func (e ErrCannotFindRequiredElement) Error() string {
	return "cannot find required element: " + string(e)
}

// ErrIncorrectTag is returned when Decrypt is passed an element which
// is neither an EncryptedType nor an EncryptedKey
var ErrIncorrectTag = fmt.Errorf("tag must be an EncryptedType or EncryptedKey")

// ErrIncorrectKeyLength is returned when the fixed length key is not
// of the required length.
type ErrIncorrectKeyLength int

func (e ErrIncorrectKeyLength) Error() string {
	return fmt.Sprintf("expected key to be %d bytes", int(e))
}

// ErrIncorrectKeyType is returned when the key is not the correct type
type ErrIncorrectKeyType string

func (e ErrIncorrectKeyType) Error() string {
	return fmt.Sprintf("expected key to be %s", string(e))
}

// ErrKeyAlgorithmNotAllowed is returned by Decrypt for an xenc:EncryptedKey
// whose EncryptionMethod names a block cipher such as aes128-cbc or
// aes256-gcm. An EncryptedKey carries a content key, which must be
// transported with a key-transport algorithm (RSA-OAEP) or wrapped with a
// key-wrap algorithm.
//
// Accepting a block cipher there would let a sender nest a captured,
// legitimately wrapped content key inside an EncryptedKey of its own and have
// the recipient decrypt ciphertext of the sender's choosing under that key:
// a CBC padding oracle that the uniform errors of the data decryption do not
// cover.
type ErrKeyAlgorithmNotAllowed string

func (e ErrKeyAlgorithmNotAllowed) Error() string {
	return "algorithm is not allowed for an EncryptedKey: " + string(e)
}

// Decrypt decrypts the encrypted data using the provided key. If the
// data are encrypted using AES, then the key should be a []byte.
// If the data are encrypted with RSA-OAEP-MGF1P or RSA-OAEP then key
// should be a *rsa.PrivateKey.
//
// The algorithm is the one the EncryptionMethod of ciphertextEl names, among
// those registered with RegisterDecrypter. For an xenc:EncryptedKey it must
// not be a block cipher (a Decrypter that is also a BlockCipher), so that an
// EncryptedKey is never followed into another EncryptedKey: see
// ErrKeyAlgorithmNotAllowed.
func Decrypt(key interface{}, ciphertextEl *etree.Element) ([]byte, error) {
	encryptionMethodEl := ciphertextEl.FindElement("./EncryptionMethod")
	if encryptionMethodEl == nil {
		return nil, ErrCannotFindRequiredElement("EncryptionMethod")
	}
	algorithm := encryptionMethodEl.SelectAttrValue("Algorithm", "")
	decrypter, ok := lookupDecrypter(algorithm)
	if !ok {
		return nil, ErrAlgorithmNotImplemented(algorithm)
	}
	if ciphertextEl.Tag == "EncryptedKey" {
		if _, isBlockCipher := decrypter.(BlockCipher); isBlockCipher {
			return nil, ErrKeyAlgorithmNotAllowed(algorithm)
		}
	}
	return decrypter.Decrypt(key, ciphertextEl)
}

func getCiphertext(encryptedKey *etree.Element) ([]byte, error) {
	ciphertextEl := encryptedKey.FindElement("./CipherData/CipherValue")
	if ciphertextEl == nil {
		return nil, fmt.Errorf("cannot find CipherData element containing a CipherValue element")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ciphertextEl.Text()))
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func validateRSAKeyIfPresent(key interface{}, encryptedKey *etree.Element) (*rsa.PrivateKey, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("expected key to be a *rsa.PrivateKey")
	}

	// extract and verify that the public key matches the certificate
	// this section is included to either let the service know up front
	// if the key will work, or let the service provider know which key
	// to use to decrypt the message. Either way, verification is not
	// security-critical.
	//nolint:revive,staticcheck // Keep the later empty branch so that we know to address this at a later date.
	if el := encryptedKey.FindElement("./KeyInfo/X509Data/X509Certificate"); el != nil {
		certPEMbuf := el.Text()
		certPEMbuf = "-----BEGIN CERTIFICATE-----\n" + certPEMbuf + "\n-----END CERTIFICATE-----\n"
		certPEM, _ := pem.Decode([]byte(certPEMbuf))
		if certPEM == nil {
			return nil, fmt.Errorf("invalid certificate")
		}
		cert, err := x509.ParseCertificate(certPEM.Bytes)
		if err != nil {
			return nil, err
		}
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected certificate to be an *rsa.PublicKey")
		}
		if rsaKey.N.Cmp(pubKey.N) != 0 || rsaKey.E != pubKey.E {
			return nil, fmt.Errorf("certificate does not match provided key")
		}
	} else if el = encryptedKey.FindElement("./KeyInfo/X509Data/X509IssuerSerial"); el != nil {
		// TODO: determine how to validate the issuer serial information
	}
	return rsaKey, nil
}
