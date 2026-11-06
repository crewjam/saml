package xmlenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestCovCBCRoundTrip(t *testing.T) {
	for _, bc := range []BlockCipher{AES128CBC, AES192CBC, AES256CBC, TripleDES} {
		key := bytes.Repeat([]byte{7}, bc.KeySize())
		// Every length across two blocks, including the empty plaintext and
		// whole blocks, which take a full block of padding.
		for n := 0; n <= 33; n++ {
			plaintext := bytes.Repeat([]byte{'a'}, n)
			el, err := bc.Encrypt(key, plaintext, nil)
			assert.NilError(t, err)
			got, err := bc.Decrypt(key, el)
			assert.NilError(t, err, "%s %d", bc.Algorithm(), n)
			assert.Check(t, is.Equal(string(plaintext), string(got)), "%s %d", bc.Algorithm(), n)
		}
	}
}

func TestCovCBCEncryptErrors(t *testing.T) {
	t.Run("key type", func(t *testing.T) {
		_, err := AES128CBC.Encrypt("key", []byte("x"), nil)
		assert.Check(t, is.Error(err, ErrIncorrectKeyType("[]byte").Error()))
	})
	t.Run("key length", func(t *testing.T) {
		_, err := AES128CBC.Encrypt(make([]byte, 15), []byte("x"), nil)
		assert.Check(t, is.Error(err, ErrIncorrectKeyLength(16).Error()))
	})
	t.Run("cipher", func(t *testing.T) {
		c := CBC{keySize: 16, algorithm: "cov", cipher: covFailingCipher}
		_, err := c.Encrypt(make([]byte, 16), []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovCipher))
	})
	t.Run("rand for Id", func(t *testing.T) {
		covSetRandReader(t, &covFailingReader{ok: 0})
		_, err := AES128CBC.Encrypt(make([]byte, 16), []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovRand))
	})
	t.Run("rand for IV", func(t *testing.T) {
		covSetRandReader(t, &covFailingReader{ok: 1})
		_, err := AES128CBC.Encrypt(make([]byte, 16), []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovRand))
	})
}

// covCBCData returns an EncryptedData element holding a random IV followed by
// the CBC encryption of plaintext (which must be whole blocks and is not
// padded here, so the caller controls the padding bytes).
func covCBCData(t *testing.T, key, plaintext []byte) *etree.Element {
	t.Helper()
	block, err := aes.NewCipher(key)
	assert.NilError(t, err)
	buf := make([]byte, aes.BlockSize+len(plaintext))
	iv, ct := buf[:aes.BlockSize], buf[aes.BlockSize:]
	_, err = rand.Read(iv)
	assert.NilError(t, err)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plaintext) //nolint:gosec // iv is filled from crypto/rand above
	el := etree.NewElement("EncryptedData")
	el.CreateElement("EncryptionMethod").CreateAttr("Algorithm", AES128CBC.Algorithm())
	el.CreateElement("CipherData").CreateElement("CipherValue").
		SetText(base64.StdEncoding.EncodeToString(buf))
	return el
}

func TestCovCBCDecryptErrors(t *testing.T) {
	key := make([]byte, 16)

	t.Run("encrypted key", func(t *testing.T) {
		el := encryptedData(AES128CBC.Algorithm(), 32)
		ek := el.CreateElement("KeyInfo").CreateElement("EncryptedKey")
		ek.CreateElement("EncryptionMethod").CreateAttr("Algorithm", "cov:unknown")
		_, err := AES128CBC.Decrypt(key, el)
		assert.Check(t, is.Error(err, ErrAlgorithmNotImplemented("cov:unknown").Error()))
	})
	t.Run("key type", func(t *testing.T) {
		_, err := AES128CBC.Decrypt("key", encryptedData(AES128CBC.Algorithm(), 32))
		assert.Check(t, is.Error(err, ErrIncorrectKeyType("[]byte").Error()))
	})
	t.Run("key length", func(t *testing.T) {
		_, err := AES128CBC.Decrypt(make([]byte, 32), encryptedData(AES128CBC.Algorithm(), 32))
		assert.Check(t, is.Error(err, ErrIncorrectKeyLength(16).Error()))
	})
	t.Run("cipher", func(t *testing.T) {
		c := CBC{keySize: 16, algorithm: "cov", cipher: covFailingCipher}
		_, err := c.Decrypt(key, encryptedData("cov", 32))
		assert.Check(t, errors.Is(err, errCovCipher))
	})
	t.Run("no cipher value", func(t *testing.T) {
		el := etree.NewElement("EncryptedData")
		_, err := AES128CBC.Decrypt(key, el)
		assert.Check(t, is.ErrorContains(err, "cannot find CipherData"))
	})

	// Padding is checked after decryption: the last byte must be between 1
	// and the block size.
	for _, last := range []byte{0, 17, 255} {
		t.Run(fmt.Sprintf("padding byte %d", last), func(t *testing.T) {
			pt := make([]byte, 32)
			pt[31] = last
			_, err := AES128CBC.Decrypt(key, covCBCData(t, key, pt))
			assert.Check(t, err != nil)
		})
	}
	t.Run("padding of a whole block", func(t *testing.T) {
		pt := make([]byte, 16)
		pt[15] = 16
		got, err := AES128CBC.Decrypt(key, covCBCData(t, key, pt))
		assert.NilError(t, err)
		assert.Check(t, is.Len(got, 0))
	})
	t.Run("padding bytes other than the last are arbitrary", func(t *testing.T) {
		pt := []byte("0123456789\xff\xfe\xfd\xfc\xfb\x06")
		got, err := AES128CBC.Decrypt(key, covCBCData(t, key, pt))
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual([]byte("0123456789"), got))
	})
}

func TestCovStripPadding(t *testing.T) {
	cases := []struct {
		buf  []byte
		want []byte
		err  string
	}{
		{buf: nil, err: "buffer is too short for padding"},
		{buf: []byte{}, err: "buffer is too short for padding"},
		{buf: []byte{1}, want: []byte{}},
		{buf: []byte{2}, err: "buffer is too short for padding"},
		{buf: []byte{'a', 0}, err: "padding must be at least one byte"},
		{buf: append(make([]byte, 31), 17), err: "buffer is too short for padding"},
		{buf: append(make([]byte, 15), 16), want: []byte{}},
		{buf: []byte{'a', 'b', 'c', 2}, want: []byte{'a', 'b'}},
	}
	for i, c := range cases {
		got, err := stripPadding(c.buf, 16)
		if c.err != "" {
			assert.Check(t, is.Error(err, c.err), "case %d", i)
			continue
		}
		assert.NilError(t, err, "case %d", i)
		assert.Check(t, is.DeepEqual(c.want, got), "case %d", i)
	}
}
