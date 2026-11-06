package xmlenc

import (
	"bytes"
	"testing"
)

// GCM.Encrypt must actually encrypt the plaintext and produce ciphertext that
// GCM.Decrypt can recover. Before the fix it sealed a zero buffer and never
// prepended the nonce, so this round trip failed with an authentication error.
func TestGCMEncryptRoundTrip(t *testing.T) {
	key := make([]byte, 16) // AES-128
	plaintext := []byte("super-secret-assertion-payload")
	nonce := make([]byte, 12)

	el, err := AES128GCM.Encrypt(key, plaintext, nonce)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := AES128GCM.Decrypt(key, el)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip lost the plaintext: got %q, want %q", got, plaintext)
	}
}

// A nil nonce must make Encrypt generate one (and still round-trip), not panic.
func TestGCMEncryptGeneratedNonce(t *testing.T) {
	key := make([]byte, 16)
	plaintext := []byte("payload-with-generated-nonce")

	el, err := AES128GCM.Encrypt(key, plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt(nil nonce): %v", err)
	}
	got, err := AES128GCM.Decrypt(key, el)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("nil-nonce round trip lost the plaintext: got %q, want %q", got, plaintext)
	}
}
