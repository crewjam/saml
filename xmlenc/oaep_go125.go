//go:build !go1.26

package xmlenc

import (
	"crypto/rsa"
	"io"
)

// rsaEncryptOAEP encrypts msg with RSA-OAEP using the hashes and label in
// opts. The OAEP digest and the MGF1 hash may differ.
//
// Before Go 1.26, crypto/rsa cannot encrypt with an MGF1 hash that differs
// from the OAEP digest, so that case is done by encryptOAEPMGF.
func rsaEncryptOAEP(random io.Reader, pub *rsa.PublicKey, msg []byte, opts *rsa.OAEPOptions) ([]byte, error) {
	if opts.MGFHash == 0 || opts.MGFHash == opts.Hash {
		return rsa.EncryptOAEP(opts.Hash.New(), random, pub, msg, opts.Label)
	}
	return encryptOAEPMGF(random, pub, msg, opts)
}
