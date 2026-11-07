package xmlenc

import (
	"bytes"
	"crypto/cipher"
	"crypto/des" // nolint: gosec
	"encoding/base64"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// tripledes-cbc takes a 24 byte key (XML Encryption section 5.2.1).
func TestTripleDESKeySize(t *testing.T) {
	assert.Check(t, is.Equal(24, TripleDES.KeySize()))

	_, err := TripleDES.Encrypt(make([]byte, 8), []byte("x"), nil)
	assert.Check(t, is.Error(err, ErrIncorrectKeyLength(24).Error()))
}

// TripleDES is DES-EDE3: it decrypts what crypto/des's 3DES encrypts in CBC
// mode, and all three 8 byte subkeys matter.
func TestTripleDESMatchesCryptoDES(t *testing.T) {
	key := []byte("0123456789abcdefFEDCBA98")
	iv := []byte("initvect")
	plaintext := []byte("sixteen byte msg")

	block, err := des.NewTripleDESCipher(key) //nolint:gosec // known-answer test for the legacy tripledes-cbc algorithm
	assert.NilError(t, err)
	padded := appendPadding(append([]byte{}, plaintext...), block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded) //nolint:gosec // fixed IV for a deterministic test vector

	el := encryptedData(TripleDES.Algorithm(), 0)
	el.FindElement("./CipherData/CipherValue").
		SetText(base64.StdEncoding.EncodeToString(append(append([]byte{}, iv...), ciphertext...)))

	actual, err := TripleDES.Decrypt(key, el)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(plaintext, actual))

	// Single DES under the first subkey, which is what the old 8 byte key
	// meant, gives different ciphertext.
	single, err := des.NewCipher(key[:8]) //nolint:gosec // single DES on purpose, to show it differs from 3DES
	assert.NilError(t, err)
	singleCiphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(single, iv).CryptBlocks(singleCiphertext, padded) //nolint:gosec // fixed IV for a deterministic test vector
	assert.Check(t, !bytes.Equal(ciphertext, singleCiphertext))
}
