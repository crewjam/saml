package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // rsa-oaep-mgf1p uses SHA-1
	"encoding/base64"
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// Once one EncryptedKey has unwrapped a content key, decryptWithKeys takes
// the result of decrypting the EncryptedData with it as final and tries no
// other candidate. If it went on after a failure (bad CBC padding, say) but
// stopped after a success, the private-key operations of the further
// candidates, which an attacker can add to an unsigned Response, would let
// the response time tell good padding from bad: a padding oracle.
func TestDecryptWithKeysStopsOnceAContentKeyIsUnwrapped(t *testing.T) {
	e := spcovSetup(t)
	plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
	thisSP := multiKeyRecipient{cert: e.sp.Certificate, recipient: e.sp.entityID()}

	// Both EncryptedKeys are for this SP, but only the second holds the key
	// the EncryptedData was encrypted with; the first, tried first because
	// its Recipient matches, holds another.
	ea := multiKeyEncrypt(t, "saml:EncryptedAssertion", plaintext, thisSP, multiKeyRecipient{cert: e.sp.Certificate})
	wrongKey := make([]byte, xmlenc.AES128CBC.KeySize())
	_, err := rand.Read(wrongKey)
	assert.NilError(t, err)
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, e.sp.Certificate.PublicKey.(*rsa.PublicKey), wrongKey, nil) //nolint:gosec // rsa-oaep-mgf1p
	assert.NilError(t, err)
	first := ea.FindElement("./EncryptedKey[@Id='_key0']/CipherData/CipherValue")
	assert.Assert(t, first != nil)
	first.SetText(base64.StdEncoding.EncodeToString(wrapped))

	_, err = e.specSigParse(t, e.specSigResponse(ea))
	assert.Check(t, errors.Is(err, ErrDecryptionFailed), "%v", err)

	// The second EncryptedKey alone decrypts it.
	ea = multiKeyEncrypt(t, "saml:EncryptedAssertion", plaintext, multiKeyRecipient{cert: e.sp.Certificate})
	assertion, err := e.specSigParse(t, e.specSigResponse(ea))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
}
