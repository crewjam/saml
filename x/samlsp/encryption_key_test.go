package samlsp_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/x/samlsp"
)

func newECKeyPair(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "sp-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func TestWithEncryptionKey(t *testing.T) {
	ti := newTestIDP(t)
	sigKey, sigCert := newECKeyPair(t)
	encKey, encCert := newKeyPair(t, "sp-encryption")

	// The ECDSA key signs; only the RSA key can decrypt.
	cfg := newTestConfig(t, ti, samlsp.WithSigningKey(sigKey, sigCert), samlsp.WithEncryptionKey(encKey, encCert))

	var signing, encryption []string
	for _, kd := range cfg.Metadata(t.Context()).SPSSODescriptors[0].KeyDescriptors {
		data := kd.KeyInfo.X509Data.X509Certificates[0].Data
		switch kd.Use {
		case "signing":
			signing = append(signing, data)
		case "encryption":
			encryption = append(encryption, data)
		}
	}
	if len(signing) != 1 || len(encryption) != 1 || signing[0] == encryption[0] {
		t.Fatalf("metadata keys: signing %d, encryption %d", len(signing), len(encryption))
	}

	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	acs := login(t, ti, msg)
	if !strings.Contains(decodedResponse(t, acs), "EncryptedAssertion") {
		t.Fatal("the IdP did not encrypt the assertion")
	}
	if _, err := cfg.ParseResponse(t.Context(), acs, samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
	}
}

func TestWithEncryptionKeyErrors(t *testing.T) {
	ti := newTestIDP(t)
	encKey, encCert := newKeyPair(t, "a")
	otherKey, _ := newKeyPair(t, "b")
	for name, opt := range map[string]samlsp.Option{
		"no cert":    samlsp.WithEncryptionKey(encKey, nil),
		"no key":     samlsp.WithEncryptionKey(nil, encCert),
		"mismatched": samlsp.WithEncryptionKey(otherKey, encCert),
	} {
		if _, err := samlsp.New(spEntityID, staticIDP(ti), opt); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestDecryptionKeysForRotation: the IdP still has the SP's old encryption
// certificate while the SP has moved to a new one; WithDecryptionKeys keeps
// the old key to decrypt with.
func TestDecryptionKeysForRotation(t *testing.T) {
	ti := newTestIDP(t)
	oldKey, oldCert := newKeyPair(t, "old encryption")
	newKey, newCert := newKeyPair(t, "new encryption")

	// The SP as registered with the IdP: encrypting to the old key.
	newTestConfig(t, ti, samlsp.WithEncryptionKey(oldKey, oldCert))
	registered := ti.spMeta

	login := func(cfg *samlsp.Config) error {
		ti.spMeta = registered
		msg, err := cfg.AuthnRequest(t.Context(), "s")
		if err != nil {
			t.Fatal(err)
		}
		acs := login(t, ti, msg)
		if !strings.Contains(decodedResponse(t, acs), "EncryptedAssertion") {
			t.Fatal("the IdP did not encrypt the assertion")
		}
		_, err = cfg.ParseResponse(t.Context(), acs, samlsp.WithRequestID(msg.ID))
		return err
	}

	sigKey, sigCert := newKeyPair(t, "signing")
	rotated, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithSigningKey(sigKey, sigCert),
		samlsp.WithEncryptionKey(newKey, newCert), samlsp.WithDecryptionKeys(oldKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := login(rotated); err != nil {
		t.Errorf("with the old key kept: %v (%v)", err, errors.Unwrap(err))
	}

	forgot, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithSigningKey(sigKey, sigCert),
		samlsp.WithEncryptionKey(newKey, newCert))
	if err != nil {
		t.Fatal(err)
	}
	if err := login(forgot); err == nil {
		t.Error("an assertion encrypted to a key the SP does not have was decrypted")
	}
}

// TestSigningKeyOnlySigns checks that the key of WithSigningKey is not
// published for encryption, even an RSA one, and that WithEncryptionKey
// with the same key is.
func TestSigningKeyOnlySigns(t *testing.T) {
	ti := newTestIDP(t)
	key, cert := newKeyPair(t, "sp")
	uses := func(opts ...samlsp.Option) map[string]bool {
		t.Helper()
		cfg := newTestConfigWithIDP(t, ti, staticIDP(ti), opts...)
		got := map[string]bool{}
		for _, kd := range cfg.Metadata(t.Context()).SPSSODescriptors[0].KeyDescriptors {
			got[kd.Use] = true
		}
		return got
	}
	if got := uses(samlsp.WithSigningKey(key, cert)); got["encryption"] || !got["signing"] {
		t.Errorf("signing key only: key uses %v", got)
	}
	if got := uses(samlsp.WithSigningKey(key, cert), samlsp.WithEncryptionKey(key, cert)); !got["encryption"] || !got["signing"] {
		t.Errorf("same key for both: key uses %v", got)
	}
}
