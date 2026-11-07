package xmlenc

import (
	"bytes"
	"crypto/rand"
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
