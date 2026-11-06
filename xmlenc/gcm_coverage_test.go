package xmlenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // a 64 bit block cipher, which GCM refuses
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

func TestCovGCMRoundTrip(t *testing.T) {
	for _, bc := range []BlockCipher{AES128GCM, AES192GCM, AES256GCM} {
		key := bytes.Repeat([]byte{9}, bc.KeySize())
		for _, n := range []int{0, 1, 15, 16, 17, 100} {
			plaintext := bytes.Repeat([]byte{'g'}, n)
			el, err := bc.Encrypt(key, plaintext, nil)
			assert.NilError(t, err)
			got, err := bc.Decrypt(key, el)
			assert.NilError(t, err, "%s %d", bc.Algorithm(), n)
			assert.Check(t, is.Equal(string(plaintext), string(got)), "%s %d", bc.Algorithm(), n)
		}
	}
}

// The CipherValue is nonce || ciphertext || tag (XML Encryption 1.1 section
// 5.2.4), with the plaintext actually encrypted and no padding added, so other
// implementations can decrypt it.
func TestCovGCMEncryptOutputFormat(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 16)
	nonce := []byte("0123456789AB")
	plaintext := []byte("hello, world")

	el, err := AES128GCM.Encrypt(key, plaintext, nonce)
	assert.NilError(t, err)
	buf, err := base64.StdEncoding.DecodeString(el.FindElement("./CipherData/CipherValue").Text())
	assert.NilError(t, err)

	block, err := aes.NewCipher(key)
	assert.NilError(t, err)
	aesgcm, err := cipher.NewGCM(block)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(nonce, buf[:aesgcm.NonceSize()]))
	assert.Check(t, is.Len(buf, aesgcm.NonceSize()+len(plaintext)+aesgcm.Overhead()))
	got, err := aesgcm.Open(nil, buf[:aesgcm.NonceSize()], buf[aesgcm.NonceSize():], nil)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(plaintext, got))
}

// The golden GCM ciphertext decrypts back to its plaintext.
func TestCovGCMGoldenRoundTrip(t *testing.T) {
	b, _ := pem.Decode(golden.Get(t, "cert.key"))
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	assert.NilError(t, err)

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(golden.Get(t, "ciphertext_gcm.xml")))
	got, err := Decrypt(key, doc.Root())
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(golden.Get(t, "plaintext_gcm.xml")), string(got)))
}

func TestCovGCMEncryptErrors(t *testing.T) {
	key := make([]byte, 16)

	t.Run("key type", func(t *testing.T) {
		_, err := AES128GCM.Encrypt("key", []byte("x"), nil)
		assert.Check(t, is.Error(err, ErrIncorrectKeyType("[]byte").Error()))
	})
	t.Run("key length", func(t *testing.T) {
		_, err := AES128GCM.Encrypt(make([]byte, 15), []byte("x"), nil)
		assert.Check(t, is.Error(err, ErrIncorrectKeyLength(16).Error()))
	})
	t.Run("cipher", func(t *testing.T) {
		g := GCM{keySize: 16, algorithm: "cov", cipher: covFailingCipher}
		_, err := g.Encrypt(key, []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovCipher))
	})
	t.Run("block size", func(t *testing.T) {
		g := GCM{keySize: 8, algorithm: "cov", cipher: des.NewCipher}
		_, err := g.Encrypt(make([]byte, 8), []byte("x"), nil)
		assert.Check(t, err != nil)
	})
	t.Run("rand for Id", func(t *testing.T) {
		covSetRandReader(t, &covFailingReader{ok: 0})
		_, err := AES128GCM.Encrypt(key, []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovRand))
	})
	t.Run("rand for nonce", func(t *testing.T) {
		covSetRandReader(t, &covFailingReader{ok: 1})
		_, err := AES128GCM.Encrypt(key, []byte("x"), nil)
		assert.Check(t, errors.Is(err, errCovRand))
	})
	t.Run("nonce length", func(t *testing.T) {
		// cipher.AEAD.Seal panics on a nonce of the wrong length.
		_, err := AES128GCM.Encrypt(key, []byte("x"), []byte("short"))
		assert.Check(t, is.Error(err, "nonce must be 12 bytes"))
	})
}

func TestCovGCMDecryptErrors(t *testing.T) {
	key := make([]byte, 16)

	t.Run("encrypted key", func(t *testing.T) {
		el := encryptedData(AES128GCM.Algorithm(), 32)
		ek := el.CreateElement("KeyInfo").CreateElement("EncryptedKey")
		ek.CreateElement("EncryptionMethod").CreateAttr("Algorithm", "cov:unknown")
		_, err := AES128GCM.Decrypt(key, el)
		assert.Check(t, is.Error(err, ErrAlgorithmNotImplemented("cov:unknown").Error()))
	})
	t.Run("key type", func(t *testing.T) {
		_, err := AES128GCM.Decrypt("key", encryptedData(AES128GCM.Algorithm(), 32))
		assert.Check(t, is.Error(err, ErrIncorrectKeyType("[]byte").Error()))
	})
	t.Run("key length", func(t *testing.T) {
		_, err := AES128GCM.Decrypt(make([]byte, 32), encryptedData(AES128GCM.Algorithm(), 32))
		assert.Check(t, is.Error(err, ErrIncorrectKeyLength(16).Error()))
	})
	t.Run("cipher", func(t *testing.T) {
		g := GCM{keySize: 16, algorithm: "cov", cipher: covFailingCipher}
		_, err := g.Decrypt(key, encryptedData("cov", 32))
		assert.Check(t, errors.Is(err, errCovCipher))
	})
	t.Run("block size", func(t *testing.T) {
		g := GCM{keySize: 8, algorithm: "cov", cipher: des.NewCipher}
		_, err := g.Decrypt(make([]byte, 8), encryptedData("cov", 32))
		assert.Check(t, err != nil)
	})
	t.Run("no cipher value", func(t *testing.T) {
		_, err := AES128GCM.Decrypt(key, etree.NewElement("EncryptedData"))
		assert.Check(t, is.ErrorContains(err, "cannot find CipherData"))
	})
	t.Run("authentication", func(t *testing.T) {
		el, err := AES128GCM.Encrypt(key, []byte("attack at dawn"), nil)
		assert.NilError(t, err)
		cv := el.FindElement("./CipherData/CipherValue")
		buf, err := base64.StdEncoding.DecodeString(cv.Text())
		assert.NilError(t, err)
		buf[len(buf)-1] ^= 1
		cv.SetText(base64.StdEncoding.EncodeToString(buf))
		_, err = AES128GCM.Decrypt(key, el)
		assert.Check(t, is.ErrorContains(err, "authentication failed"))
	})
	t.Run("wrong key", func(t *testing.T) {
		el, err := AES128GCM.Encrypt(key, []byte("attack at dawn"), nil)
		assert.NilError(t, err)
		_, err = AES128GCM.Decrypt(bytes.Repeat([]byte{1}, 16), el)
		assert.Check(t, is.ErrorContains(err, "authentication failed"))
	})
}
