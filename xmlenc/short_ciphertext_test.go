package xmlenc

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// encryptedData builds an EncryptedData element for algorithm whose
// CipherValue holds n zero bytes. Anyone holding the service provider's
// public key can wrap a key of their choosing, so the length of the data
// that reaches a block cipher is attacker-controlled.
func encryptedData(algorithm string, n int) *etree.Element {
	el := etree.NewElement("EncryptedData")
	el.CreateElement("EncryptionMethod").CreateAttr("Algorithm", algorithm)
	el.CreateElement("CipherData").CreateElement("CipherValue").
		SetText(base64.StdEncoding.EncodeToString(make([]byte, n)))
	return el
}

// Ciphertext too short or of the wrong length is refused with an error
// rather than a panic.
func TestDecryptRejectsMalformedCiphertextLength(t *testing.T) {
	cases := []struct {
		cipher BlockCipher
		n      int
	}{
		{AES128GCM, 0},
		{AES128GCM, 11}, // shorter than the nonce
		{AES128GCM, 12}, // nonce only, no tag
		{AES128GCM, 27}, // one byte short of nonce and tag
		{AES128CBC, 0},
		{AES128CBC, 15}, // shorter than the IV
		{AES128CBC, 16}, // IV only, no block
		{AES128CBC, 17}, // not a whole number of blocks
		{AES256CBC, 47},
	}
	for _, c := range cases {
		// The algorithm URI holds slashes, which go test reads as subtest levels.
		name := c.cipher.Algorithm()[strings.LastIndex(c.cipher.Algorithm(), "#")+1:]
		t.Run(fmt.Sprintf("%s-%d", name, c.n), func(t *testing.T) {
			key := make([]byte, c.cipher.KeySize())
			_, err := c.cipher.Decrypt(key, encryptedData(c.cipher.Algorithm(), c.n))
			assert.Check(t, is.ErrorContains(err, "ciphertext"))
		})
	}
}

// TripleDES takes the IV at its own 8 byte block size, not AES's 16.
func TestTripleDESDecryptUsesItsBlockSize(t *testing.T) {
	plaintext := []byte("eight by")
	el, err := TripleDES.Encrypt(make([]byte, TripleDES.KeySize()), plaintext, nil)
	assert.NilError(t, err)

	actual, err := TripleDES.Decrypt(make([]byte, TripleDES.KeySize()), el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(plaintext, actual))
}

// tripledes-cbc is not offered for decryption, because TripleDES is single DES.
func TestTripleDESIsNotRegisteredForDecryption(t *testing.T) {
	_, err := Decrypt(make([]byte, TripleDES.KeySize()), encryptedData(TripleDES.Algorithm(), 24))
	assert.Check(t, is.Error(err, ErrAlgorithmNotImplemented(TripleDES.Algorithm()).Error()))
}
