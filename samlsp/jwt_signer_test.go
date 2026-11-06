package samlsp

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestSignTokenRejectsMismatchedKeys(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NilError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NilError(t, err)

	tests := []struct {
		name    string
		method  jwt.SigningMethod
		signer  *mockSigner
		wantErr string
	}{
		{"ES256 with P-384", jwt.SigningMethodES256, &mockSigner{signer: p384}, "requires a 256-bit ECDSA curve, got 384"},
		{"RS256 with ECDSA", jwt.SigningMethodRS256, &mockSigner{signer: p384}, "requires an RSA key"},
		{"ES256 with RSA", jwt.SigningMethodES256, &mockSigner{signer: rsaKey}, "requires an ECDSA key"},
		{"EdDSA with RSA", jwt.SigningMethodEdDSA, &mockSigner{signer: rsaKey}, "requires an Ed25519 key"},
		{"RS256 with Ed25519", jwt.SigningMethodRS256, &mockSigner{signer: edKey}, "requires an RSA key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.NewWithClaims(tt.method, jwt.RegisteredClaims{Subject: "x"})
			_, err := signToken(token, tt.signer)
			assert.Check(t, is.ErrorContains(err, tt.wantErr))
		})
	}
}

func TestSignTokenRejectsNilKey(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{Subject: "x"})
	_, err := signToken(token, nil)
	assert.Check(t, is.ErrorContains(err, "signing key is nil"))
	_, err = signToken(token, (*rsa.PrivateKey)(nil))
	assert.Check(t, is.ErrorContains(err, "signing key is nil"))
}

func TestEcdsaDERToJWS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NilError(t, err)
	pub := &key.PublicKey

	encode := func(r, s *big.Int) []byte {
		der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		assert.NilError(t, err)
		return der
	}

	t.Run("PadsShortComponents", func(t *testing.T) {
		out, err := ecdsaDERToJWS(encode(big.NewInt(1), big.NewInt(2)), pub)
		assert.NilError(t, err)
		assert.Check(t, is.Len(out, 132))
		assert.Check(t, is.Equal(out[65], byte(1)))
		assert.Check(t, is.Equal(out[131], byte(2)))
	})

	t.Run("RejectsTrailingData", func(t *testing.T) {
		der := append(encode(big.NewInt(1), big.NewInt(2)), 0)
		_, err := ecdsaDERToJWS(der, pub)
		assert.Check(t, is.ErrorContains(err, "trailing data"))
	})

	t.Run("RejectsNonPositive", func(t *testing.T) {
		_, err := ecdsaDERToJWS(encode(big.NewInt(0), big.NewInt(2)), pub)
		assert.Check(t, is.ErrorContains(err, "invalid ECDSA signature"))
	})

	t.Run("RejectsOversizedComponent", func(t *testing.T) {
		big67 := new(big.Int).Lsh(big.NewInt(1), 8*67)
		_, err := ecdsaDERToJWS(encode(big67, big.NewInt(2)), pub)
		assert.Check(t, is.ErrorContains(err, "larger than curve size"))
	})
}
