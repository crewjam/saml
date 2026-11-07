package xmlenc

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// saml-conformance-2.0-os §4.2 (lines 250-253): "Block Encryption: TRIPLE
// DES, AES-128, AES-256. Key Transport: RSA-v1.5, RSA-OAEP" MUST be
// implemented. AES-128/256 with RSA-OAEP decrypt by default. Triple DES and
// RSA-v1.5 are implemented but not registered by default (see cbc.go and
// pubkey.go); an application that opts in can decrypt them.
func TestSpecSig_Conformance_4_2_MandatoryEncryptionAlgorithms(t *testing.T) {
	key, cert := newKeyAndCert(t)
	plaintext := []byte("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>")

	t.Run("AES with RSA-OAEP by default", func(t *testing.T) {
		for _, bc := range []BlockCipher{AES128CBC, AES256CBC} {
			enc := OAEP()
			enc.BlockCipher = bc
			el, err := enc.Encrypt(cert, plaintext, nil)
			assert.NilError(t, err)
			got, err := Decrypt(key, el)
			assert.NilError(t, err, bc.Algorithm())
			assert.Check(t, is.DeepEqual(plaintext, got))
		}
	})

	t.Run("Triple DES with RSA-OAEP", func(t *testing.T) {
		enc := OAEP()
		enc.BlockCipher = TripleDES
		el, err := enc.Encrypt(cert, plaintext, nil)
		assert.NilError(t, err)
		got, err := TripleDES.Decrypt(key, el)
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(plaintext, got))
	})

	t.Run("AES with RSA-v1.5 once registered", func(t *testing.T) {
		alg := PKCS1v15().Algorithm()
		_, registered := decrypters[alg]
		assert.Assert(t, !registered)
		RegisterDecrypter(PKCS1v15())
		t.Cleanup(func() { delete(decrypters, alg) })

		el, err := PKCS1v15().Encrypt(cert, plaintext, nil)
		assert.NilError(t, err)
		got, err := Decrypt(key, el)
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(plaintext, got))
	})
}
