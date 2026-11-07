package xmlenc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// encryptOAEPMGF produces ciphertexts that crypto/rsa decrypts, whichever
// OAEP digest and MGF1 hash are combined, with and without a label, up to the
// largest message that fits.
func TestEncryptOAEPMGF(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512}
	for _, h := range hashes {
		for _, mgf := range hashes {
			for _, label := range [][]byte{nil, []byte("label")} {
				maxLen := key.Size() - 2*h.Size() - 2
				for _, n := range []int{0, 1, 32, maxLen} {
					t.Run(fmt.Sprintf("%v/%v/label=%q/len=%d", h, mgf, label, n), func(t *testing.T) {
						opts := &rsa.OAEPOptions{Hash: h, MGFHash: mgf, Label: label}
						msg := bytes.Repeat([]byte{0xa5}, n)
						ct, err := encryptOAEPMGF(rand.Reader, &key.PublicKey, msg, opts)
						assert.NilError(t, err)
						assert.Check(t, is.Len(ct, key.Size()))

						pt, err := key.Decrypt(rand.Reader, ct, opts)
						assert.NilError(t, err)
						assert.Check(t, bytes.Equal(msg, pt))
					})
				}
			}
		}
	}
}

func TestEncryptOAEPMGFErrors(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	opts := &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1}

	tooLong := make([]byte, key.Size()-2*crypto.SHA256.Size()-1)
	_, err = encryptOAEPMGF(rand.Reader, &key.PublicKey, tooLong, opts)
	assert.Check(t, errors.Is(err, rsa.ErrMessageTooLong))

	_, err = encryptOAEPMGF(rand.Reader, &rsa.PublicKey{}, []byte("x"), opts)
	assert.Check(t, is.ErrorContains(err, "invalid RSA public key"))

	_, err = encryptOAEPMGF(rand.Reader, &key.PublicKey, []byte("x"),
		&rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.MD4})
	assert.Check(t, is.ErrorContains(err, "not available"))

	_, err = encryptOAEPMGF(bytes.NewReader(nil), &key.PublicKey, []byte("x"), opts)
	assert.Check(t, err != nil)
}
