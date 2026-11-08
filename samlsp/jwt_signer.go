package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/signerutil"
)

// signToken signs token with signer.
//
// Concrete in-memory keys (*rsa.PrivateKey, *ecdsa.PrivateKey and
// ed25519.PrivateKey) are handed to the jwt library directly. Any other
// crypto.Signer, such as a KMS or HSM backed key, is signed through the
// crypto.Signer interface by signWithCryptoSigner.
func signToken(token *jwt.Token, signer crypto.Signer) (string, error) {
	if signerutil.IsNil(signer) {
		return "", errors.New("signing key is nil")
	}

	switch signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return token.SignedString(signer)
	default:
		return signWithCryptoSigner(token, signer)
	}
}

type keyKind int

const (
	keyKindRSA keyKind = iota
	keyKindECDSA
	keyKindEd25519
)

// cryptoSignerAlg describes how to produce a JWS signature for one JWT
// algorithm using the crypto.Signer interface.
type cryptoSignerAlg struct {
	kind      keyKind
	hash      crypto.Hash // zero for EdDSA, which signs the unhashed message
	pss       bool
	curveBits int // required curve size for ECDSA
}

var cryptoSignerAlgs = map[string]cryptoSignerAlg{
	"RS256": {kind: keyKindRSA, hash: crypto.SHA256},
	"RS384": {kind: keyKindRSA, hash: crypto.SHA384},
	"RS512": {kind: keyKindRSA, hash: crypto.SHA512},
	"PS256": {kind: keyKindRSA, hash: crypto.SHA256, pss: true},
	"PS384": {kind: keyKindRSA, hash: crypto.SHA384, pss: true},
	"PS512": {kind: keyKindRSA, hash: crypto.SHA512, pss: true},
	"ES256": {kind: keyKindECDSA, hash: crypto.SHA256, curveBits: 256},
	"ES384": {kind: keyKindECDSA, hash: crypto.SHA384, curveBits: 384},
	"ES512": {kind: keyKindECDSA, hash: crypto.SHA512, curveBits: 521},
	"EdDSA": {kind: keyKindEd25519},
}

// signWithCryptoSigner signs token using only the crypto.Signer interface,
// so that keys whose private material is not available in process (KMS, HSM)
// can be used. It supports the RS*, PS*, ES* and EdDSA algorithms.
func signWithCryptoSigner(token *jwt.Token, signer crypto.Signer) (string, error) {
	alg := token.Method.Alg()
	spec, ok := cryptoSignerAlgs[alg]
	if !ok {
		return "", fmt.Errorf("unsupported algorithm for crypto.Signer: %s", alg)
	}

	pubKey := signer.Public()
	var ecPub *ecdsa.PublicKey
	switch spec.kind {
	case keyKindRSA:
		if _, ok := pubKey.(*rsa.PublicKey); !ok {
			return "", fmt.Errorf("algorithm %s requires an RSA key, got %T", alg, pubKey)
		}
	case keyKindECDSA:
		ecPub, ok = pubKey.(*ecdsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("algorithm %s requires an ECDSA key, got %T", alg, pubKey)
		}
		if bits := ecPub.Curve.Params().BitSize; bits != spec.curveBits {
			return "", fmt.Errorf("algorithm %s requires a %d-bit ECDSA curve, got %d", alg, spec.curveBits, bits)
		}
	case keyKindEd25519:
		if _, ok := pubKey.(ed25519.PublicKey); !ok {
			return "", fmt.Errorf("algorithm %s requires an Ed25519 key, got %T", alg, pubKey)
		}
	}

	signingString, err := token.SigningString()
	if err != nil {
		return "", err
	}

	// Ed25519 signs the full message; everything else signs a digest.
	message := []byte(signingString)
	var opts crypto.SignerOpts = crypto.Hash(0)
	if spec.hash != 0 {
		h := spec.hash.New()
		h.Write(message)
		message = h.Sum(nil)
		opts = spec.hash
		if spec.pss {
			opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}
		}
	}

	sig, err := signer.Sign(saml.RandReader, message, opts) //nolint:staticcheck // samlsp still reads the deprecated global
	if err != nil {
		return "", fmt.Errorf("signing with crypto.Signer: %w", err)
	}

	// crypto.Signer returns ASN.1 DER for ECDSA, but JWS wants fixed-width R||S.
	if ecPub != nil {
		if sig, err = ecdsaDERToJWS(sig, ecPub); err != nil {
			return "", err
		}
	}

	return signingString + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ecdsaDERToJWS converts an ASN.1 DER encoded ECDSA signature to the
// fixed-width R||S form used by JWS (RFC 7518 section 3.4).
func ecdsaDERToJWS(derSig []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(derSig, &sig)
	if err != nil {
		return nil, fmt.Errorf("parsing ECDSA signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("parsing ECDSA signature: trailing data")
	}
	if sig.R == nil || sig.S == nil || sig.R.Sign() <= 0 || sig.S.Sign() <= 0 {
		return nil, errors.New("invalid ECDSA signature")
	}

	keyBytes := (pubKey.Curve.Params().BitSize + 7) / 8
	if len(sig.R.Bytes()) > keyBytes || len(sig.S.Bytes()) > keyBytes {
		return nil, errors.New("invalid ECDSA signature: component larger than curve size")
	}

	out := make([]byte, 2*keyBytes)
	sig.R.FillBytes(out[:keyBytes])
	sig.S.FillBytes(out[keyBytes:])
	return out, nil
}
