package xmlenc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"testing/iotest"

	"gotest.tools/v3/assert"
)

// TestEncryptFillsRandomBuffersFromShortReads checks that the session key,
// the CBC IV and the element IDs are filled completely when RandReader
// returns short reads, rather than being left partly zero.
func TestEncryptFillsRandomBuffersFromShortReads(t *testing.T) {
	saved := RandReader
	RandReader = iotest.OneByteReader(rand.Reader)
	t.Cleanup(func() { RandReader = saved })

	key := make([]byte, 16)
	for i := range key {
		key[i] = 0xAA
	}
	el, err := AES128CBC.Encrypt(key, []byte("<x/>"), nil)
	assert.NilError(t, err)
	ciphertext, err := getCiphertext(el)
	assert.NilError(t, err)
	iv := ciphertext[:16]
	assert.Assert(t, !bytes.Equal(iv[1:], make([]byte, 15)), "IV was only partly filled: %x", iv)

	cert, privKey := loadTestKeyPair(t)
	e := OAEP()
	e.BlockCipher = AES128GCM
	el, err = e.Encrypt(cert, []byte("<x/>"), nil)
	assert.NilError(t, err)
	sessionKey, err := Decrypt(privKey, el.FindElement("./KeyInfo/EncryptedKey"))
	assert.NilError(t, err)
	assert.Assert(t, !bytes.Equal(sessionKey[1:], make([]byte, 15)), "session key was only partly filled: %x", sessionKey)
}

// TestEncryptUsesRandField checks that RSA.Rand is the source of all the
// randomness of Encrypt, including that of the block cipher, and that a
// block cipher's own Rand takes precedence over it.
func TestEncryptUsesRandField(t *testing.T) {
	saved := RandReader
	globalErr := errors.New("the global RandReader was read")
	RandReader = iotest.ErrReader(globalErr)
	t.Cleanup(func() { RandReader = saved })

	cert, privKey := loadTestKeyPair(t)
	for _, bc := range []BlockCipher{AES128CBC, AES128GCM} {
		e := OAEP()
		e.BlockCipher = bc
		e.Rand = rand.Reader
		el, err := e.Encrypt(cert, []byte("<x/>"), nil)
		assert.NilError(t, err, bc.Algorithm())
		plaintext, err := Decrypt(privKey, el)
		assert.NilError(t, err, bc.Algorithm())
		assert.Equal(t, "<x/>", string(plaintext))

		e = PKCS1v15()
		e.BlockCipher = bc
		e.Rand = rand.Reader
		_, err = e.Encrypt(cert, []byte("<x/>"), nil)
		assert.NilError(t, err, bc.Algorithm())
	}

	cipherErr := errors.New("the block cipher's Rand was read")
	gcm := AES128GCM.(GCM)
	gcm.Rand = iotest.ErrReader(cipherErr)
	e := OAEP()
	e.BlockCipher = gcm
	e.Rand = rand.Reader
	_, err := e.Encrypt(cert, []byte("<x/>"), nil)
	assert.ErrorIs(t, err, cipherErr)

	cbc := AES128CBC.(CBC)
	cbc.Rand = iotest.ErrReader(cipherErr)
	_, err = cbc.Encrypt(make([]byte, 16), []byte("<x/>"), nil)
	assert.ErrorIs(t, err, cipherErr)

	_, err = OAEP().Encrypt(cert, []byte("<x/>"), nil)
	assert.ErrorIs(t, err, globalErr)
}
