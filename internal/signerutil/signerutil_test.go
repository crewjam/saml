package signerutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestIsNil(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		key  crypto.Signer
		want bool
	}{
		{"untyped nil", nil, true},
		{"typed nil rsa", (*rsa.PrivateKey)(nil), true},
		{"typed nil ecdsa", (*ecdsa.PrivateKey)(nil), true},
		{"nil ed25519", ed25519.PrivateKey(nil), true},
		{"ed25519", edKey, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNil(tt.key); got != tt.want {
				t.Errorf("IsNil() = %v, want %v", got, tt.want)
			}
		})
	}
}
