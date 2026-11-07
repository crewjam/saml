package xmlenc

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/golden"
)

func loadTestKeyPair(t *testing.T) (*x509.Certificate, interface{}) {
	t.Helper()
	b, _ := pem.Decode(golden.Get(t, "cert.cert"))
	cert, err := x509.ParseCertificate(b.Bytes)
	assert.NilError(t, err)
	kb, _ := pem.Decode(golden.Get(t, "cert.key"))
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	assert.NilError(t, err)
	return cert, key
}

// TestEncryptedKeyRefusesBlockCipher checks that an EncryptedKey naming a
// block cipher is refused, so that a captured content key cannot be nested
// inside an attacker's EncryptedKey to decrypt ciphertext of the attacker's
// choosing under it (a CBC padding oracle).
func TestEncryptedKeyRefusesBlockCipher(t *testing.T) {
	saved := RandReader
	RandReader = rand.Reader
	t.Cleanup(func() { RandReader = saved })

	cert, key := loadTestKeyPair(t)
	e := OAEP()
	e.BlockCipher = AES128CBC
	legit, err := e.Encrypt(cert, []byte("<x/>"), nil)
	assert.NilError(t, err)

	// The legitimate message decrypts.
	_, err = Decrypt(key, legit)
	assert.NilError(t, err)

	captured := legit.FindElement("./KeyInfo/EncryptedKey")
	assert.Assert(t, captured != nil)

	attackerBlocks := base64.StdEncoding.EncodeToString(make([]byte, 32))

	// An attacker's EncryptedKey (aes128-cbc) wrapping the captured key.
	evilKey := etree.NewElement("xenc:EncryptedKey")
	evilKey.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	evilKey.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", AES128CBC.Algorithm())
	evilKey.CreateElement("ds:KeyInfo").AddChild(captured.Copy())
	evilKey.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(attackerBlocks)

	t.Run("EncryptedKey passed to Decrypt", func(t *testing.T) {
		_, err := Decrypt(key, evilKey.Copy())
		var target ErrKeyAlgorithmNotAllowed
		assert.Assert(t, errors.As(err, &target), "got %v", err)
	})

	t.Run("EncryptedKey nested in EncryptedData", func(t *testing.T) {
		for _, bc := range []BlockCipher{AES128CBC, AES128GCM} {
			data := etree.NewElement("xenc:EncryptedData")
			data.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
			data.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", bc.Algorithm())
			data.CreateElement("ds:KeyInfo").AddChild(evilKey.Copy())
			data.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(attackerBlocks)

			_, err := Decrypt(key, data)
			var target ErrKeyAlgorithmNotAllowed
			assert.Assert(t, errors.As(err, &target), "%s: got %v", bc.Algorithm(), err)
		}
	})
}
