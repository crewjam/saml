package xmlenc

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Triple DES block encryption and RSA-v1.5 key transport are mandatory in
// saml-conformance-2.0-os §4.2 but, as the README's "Conformance notes"
// say, are not accepted for decryption unless the application registers
// them with RegisterDecrypter. These tests pin both halves: refused by
// default, decrypted once registered.
func TestConformanceDeviation_OptInDecrypters(t *testing.T) {
	key, cert := newKeyAndCert(t)
	plaintext := []byte("<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>")

	tripleDES := OAEP()
	tripleDES.BlockCipher = TripleDES

	for _, tc := range []struct {
		name      string
		encrypter Encrypter
		decrypter Decrypter
	}{
		{"Triple DES", tripleDES, TripleDES},
		{"RSA-v1.5", PKCS1v15(), PKCS1v15()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			el, err := tc.encrypter.Encrypt(cert, plaintext, nil)
			assert.NilError(t, err)

			_, err = Decrypt(key, el)
			var notImplemented ErrAlgorithmNotImplemented
			assert.Check(t, errors.As(err, &notImplemented), "refused by default: %v", err)
			assert.Check(t, is.Equal(tc.decrypter.Algorithm(), string(notImplemented)))

			alg := tc.decrypter.Algorithm()
			_, registered := decrypters[alg]
			assert.Assert(t, !registered)
			RegisterDecrypter(tc.decrypter)
			t.Cleanup(func() { delete(decrypters, alg) })

			got, err := Decrypt(key, el)
			assert.NilError(t, err, "decrypted once registered")
			assert.Check(t, is.DeepEqual(plaintext, got))
		})
	}
}
