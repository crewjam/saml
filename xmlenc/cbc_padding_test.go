package xmlenc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// decryptAES128CBC encrypts padded, which must be a whole number of blocks,
// with key in AES-128-CBC under a zero IV, and returns what Decrypt makes of
// it.
func decryptAES128CBC(t *testing.T, key, padded []byte) ([]byte, error) {
	t.Helper()
	block, err := aes.NewCipher(key)
	assert.NilError(t, err)
	iv := make([]byte, block.BlockSize(), block.BlockSize()+len(padded))
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded) //nolint:gosec // fixed IV for a deterministic test
	el := encryptedData(AES128CBC.Algorithm(), 0)
	el.FindElement("./CipherData/CipherValue").
		SetText(base64.StdEncoding.EncodeToString(append(iv, ciphertext...)))
	return AES128CBC.Decrypt(key, el)
}

// XML Encryption padding is not PKCS#7: only the last byte, the count, is
// defined. Apache Santuario and .NET's EncryptedXml pad with random bytes
// (ISO 10126), which must decrypt.
func TestCBCDecryptAcceptsArbitraryPaddingBytes(t *testing.T) {
	key := make([]byte, 16)
	padded := append([]byte("<a/>"), 0x9c, 0x01, 0xff, 0x42, 0x00, 0x13, 0x37, 0xee, 0x7f, 0x80, 0xaa, 12)
	plaintext, err := decryptAES128CBC(t, key, padded)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(plaintext, []byte("<a/>")))
}

// A bad padding count gets ErrDecryptionFailed, without detail, whatever is
// wrong with it.
func TestCBCDecryptBadPaddingReturnsErrDecryptionFailed(t *testing.T) {
	key := make([]byte, 16)
	for _, count := range []byte{0, 17, 255} {
		_, err := decryptAES128CBC(t, key, append([]byte("0123456789abcde"), count))
		assert.Check(t, errors.Is(err, ErrDecryptionFailed), "count %d: %v", count, err)
		assert.Check(t, is.Error(err, "xmlenc: decryption failed"), "count %d", count)
	}
}
