//go:build go1.26

package xmlenc

import (
	"crypto/rsa"
	"io"
)

// rsaEncryptOAEP encrypts msg with RSA-OAEP using the hashes and label in
// opts. The OAEP digest and the MGF1 hash may differ.
func rsaEncryptOAEP(random io.Reader, pub *rsa.PublicKey, msg []byte, opts *rsa.OAEPOptions) ([]byte, error) {
	return rsa.EncryptOAEPWithOptions(random, pub, msg, opts)
}
