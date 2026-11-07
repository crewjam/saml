package xmlenc

import (
	"crypto/rand"
	"errors"
	"sync"
	"testing"

	"gotest.tools/v3/assert"
)

// TestUnregisterDecrypterRefusesCBC checks that an application can refuse
// CBC, so that GCM ciphertext relabelled as CBC is not decrypted in CBC mode.
func TestUnregisterDecrypterRefusesCBC(t *testing.T) {
	saved := RandReader
	RandReader = rand.Reader
	t.Cleanup(func() { RandReader = saved })

	cert, key := loadTestKeyPair(t)
	e := OAEP()
	e.BlockCipher = AES128GCM
	el, err := e.Encrypt(cert, []byte("<x/>"), nil)
	assert.NilError(t, err)

	// Relabel the GCM ciphertext as CBC.
	el.FindElement("./EncryptionMethod").CreateAttr("Algorithm", AES128CBC.Algorithm())

	UnregisterDecrypter(AES128CBC.Algorithm())
	t.Cleanup(func() { RegisterDecrypter(AES128CBC) })

	_, err = Decrypt(key, el)
	var notImplemented ErrAlgorithmNotImplemented
	assert.Assert(t, errors.As(err, &notImplemented), "got %v", err)
	assert.Equal(t, string(notImplemented), AES128CBC.Algorithm())

	// Unregistering an unknown algorithm is a no-op.
	UnregisterDecrypter("urn:example:unknown")
}

// TestRegistryConcurrentUse checks, under -race, that registering
// algorithms while Decrypt looks them up is safe.
func TestRegistryConcurrentUse(t *testing.T) {
	saved := RandReader
	RandReader = rand.Reader
	cert, key := loadTestKeyPair(t)
	e := OAEP()
	e.BlockCipher = AES256GCM
	el, err := e.Encrypt(cert, []byte("<x/>"), nil)
	RandReader = saved
	assert.NilError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				RegisterDecrypter(AES256GCM)
				RegisterDigestMethod(SHA256)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := Decrypt(key, el.Copy()); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
