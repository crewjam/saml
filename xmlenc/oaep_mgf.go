package xmlenc

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// encryptOAEPMGF encrypts msg with RSA-OAEP as RFC 8017 section 7.1.1
// describes, using opts.Hash for the label digest and opts.MGFHash for MGF1.
//
// It is only used when crypto/rsa cannot do this itself (before Go 1.26), but
// is built for every version so that it is always tested against
// crypto/rsa's decryption.
func encryptOAEPMGF(random io.Reader, pub *rsa.PublicKey, msg []byte, opts *rsa.OAEPOptions) ([]byte, error) {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 || pub.E < 2 {
		return nil, errors.New("xmlenc: invalid RSA public key")
	}
	for _, h := range []crypto.Hash{opts.Hash, opts.MGFHash} {
		if !h.Available() {
			return nil, fmt.Errorf("xmlenc: hash %v is not available", h)
		}
	}

	k := pub.Size()
	hLen := opts.Hash.Size()
	if len(msg) > k-2*hLen-2 {
		return nil, rsa.ErrMessageTooLong
	}

	// EM = 0x00 || maskedSeed || maskedDB
	em := make([]byte, k)
	seed := em[1 : 1+hLen]
	db := em[1+hLen:]

	// DB = lHash || PS || 0x01 || M
	lHash := opts.Hash.New()
	lHash.Write(opts.Label)
	copy(db, lHash.Sum(nil))
	db[len(db)-len(msg)-1] = 0x01
	copy(db[len(db)-len(msg):], msg)

	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	mgf1XOR(db, opts.MGFHash, seed)
	mgf1XOR(seed, opts.MGFHash, db)

	// c = m^e mod n, as a k byte string.
	m := new(big.Int).SetBytes(em)
	c := m.Exp(m, big.NewInt(int64(pub.E)), pub.N)
	return c.FillBytes(make([]byte, k)), nil
}

// mgf1XOR XORs out with MGF1(seed) using hash h, as RFC 8017 appendix B.2.1
// describes.
func mgf1XOR(out []byte, h crypto.Hash, seed []byte) {
	var counter [4]byte
	done := 0
	for done < len(out) {
		d := h.New()
		d.Write(seed)
		d.Write(counter[:])
		for _, b := range d.Sum(nil) {
			if done >= len(out) {
				break
			}
			out[done] ^= b
			done++
		}
		for i := 3; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}
