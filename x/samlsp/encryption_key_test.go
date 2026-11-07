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
	cfg := newTestConfig(t, ti, samlsp.WithKey(sigKey, sigCert), samlsp.WithEncryptionKey(encKey, encCert))

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
		if _, err := samlsp.New(staticIDP(ti), spEntityID, opt); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
