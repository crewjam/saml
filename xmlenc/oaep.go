package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

const (
	algorithmRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	algorithmRSAOAEP11    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
)

// mgfHashes maps the XML Encryption 1.1 mask generation function URIs to the
// hash used by MGF1.
var mgfHashes = map[string]crypto.Hash{
	"http://www.w3.org/2009/xmlenc11#mgf1sha1":   crypto.SHA1,
	"http://www.w3.org/2009/xmlenc11#mgf1sha224": crypto.SHA224,
	"http://www.w3.org/2009/xmlenc11#mgf1sha256": crypto.SHA256,
	"http://www.w3.org/2009/xmlenc11#mgf1sha384": crypto.SHA384,
	"http://www.w3.org/2009/xmlenc11#mgf1sha512": crypto.SHA512,
}

// cryptoHashes maps digest method URIs to the corresponding crypto.Hash.
var cryptoHashes = map[string]crypto.Hash{
	SHA1.Algorithm():            crypto.SHA1,
	SHA256.Algorithm():          crypto.SHA256,
	SHA512.Algorithm():          crypto.SHA512,
	RIPEMD160.Algorithm():       crypto.RIPEMD160,
	legacySHA256.Algorithm():    crypto.SHA256,
	legacySHA512.Algorithm():    crypto.SHA512,
	legacyRIPEMD160.Algorithm(): crypto.RIPEMD160,
}

func cryptoHashOf(dm DigestMethod) (crypto.Hash, error) {
	if dm == nil {
		return 0, ErrAlgorithmNotImplemented("OAEP without a digest method")
	}
	h, ok := cryptoHashes[dm.Algorithm()]
	if !ok {
		return 0, ErrAlgorithmNotImplemented(dm.Algorithm())
	}
	return h, nil
}

// mgfURIFor returns the MGF URI for MGF1 using the same hash as dm.
func mgfURIFor(dm DigestMethod) (string, error) {
	h, err := cryptoHashOf(dm)
	if err != nil {
		return "", err
	}
	for uri, mh := range mgfHashes {
		if mh == h {
			return uri, nil
		}
	}
	return "", ErrAlgorithmNotImplemented(fmt.Sprintf("MGF1 with %s", dm.Algorithm()))
}

// encryptOAEP wraps plaintext with RSA-OAEP using dm as the OAEP digest and
// MGF1 with mgfHash.
//
// A digest method registered by the caller that this package does not know
// cannot be given to MGF1 separately, so it is used for both, as earlier
// releases did.
func encryptOAEP(dm DigestMethod, mgfHash crypto.Hash, pubKey *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	h, err := cryptoHashOf(dm)
	if err != nil {
		if dm == nil {
			return nil, err
		}
		return rsa.EncryptOAEP(dm.Hash(), RandReader, pubKey, plaintext, nil)
	}
	return rsa.EncryptOAEPWithOptions(RandReader, pubKey, plaintext, &rsa.OAEPOptions{
		Hash:    h,
		MGFHash: mgfHash,
	})
}

// decryptOAEP unwraps ciphertext with RSA-OAEP using dm as the OAEP digest and
// MGF1 with mgfHash.
//
// Earlier releases of this package always used the digest method's hash for
// MGF1, which does not follow the specs when the digest is not SHA-1 and no
// MGF is stated. When allowLegacyMGF is set (the document names no MGF), a
// failed unwrap is retried that way so documents from those releases still
// decrypt. Both attempts fail with the same error.
func decryptOAEP(dm DigestMethod, mgfHash crypto.Hash, allowLegacyMGF bool, label []byte, privKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	h, err := cryptoHashOf(dm)
	if err != nil {
		if dm == nil || !allowLegacyMGF {
			return nil, err
		}
		return rsa.DecryptOAEP(dm.Hash(), RandReader, privKey, ciphertext, label)
	}
	plaintext, err := privKey.Decrypt(RandReader, ciphertext, &rsa.OAEPOptions{
		Hash:    h,
		MGFHash: mgfHash,
		Label:   label,
	})
	if err == nil || !allowLegacyMGF || mgfHash == h {
		return plaintext, err
	}
	return privKey.Decrypt(RandReader, ciphertext, &rsa.OAEPOptions{
		Hash:    h,
		MGFHash: h,
		Label:   label,
	})
}
