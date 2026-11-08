package saml

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"testing/iotest"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// failGlobalRand makes the deprecated package-level RandReader fail for the
// rest of the test, so that a test can show that it was not read.
func failGlobalRand(t *testing.T) {
	t.Helper()
	saved := RandReader
	RandReader = iotest.ErrReader(errors.New("the global RandReader was read"))
	t.Cleanup(func() { RandReader = saved })
}

func TestServiceProviderRandIsUsedForIDs(t *testing.T) {
	failGlobalRand(t)
	sp := &ServiceProvider{
		EntityID: "https://sp.example.com/saml2/metadata",
		Rand:     bytes.NewReader(bytes.Repeat([]byte{0xab}, 20)),
	}
	req, err := sp.MakeAuthenticationRequest("https://idp.example.com/saml/sso", HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(fmt.Sprintf("id-%x", bytes.Repeat([]byte{0xab}, 20)), req.ID))
}

func TestIdentityProviderRandIsUsedForIDs(t *testing.T) {
	failGlobalRand(t)
	idp := &IdentityProvider{Rand: bytes.NewReader(bytes.Repeat([]byte{0xcd}, 20))}
	req := &IdpLogoutRequest{IDP: idp}
	resp := req.MakeLogoutResponse(StatusSuccess)
	assert.Check(t, is.Equal(fmt.Sprintf("id-%x", bytes.Repeat([]byte{0xcd}, 20)), resp.ID))
}

func TestRandomBytesWithoutRandUsesGlobal(t *testing.T) {
	saved := RandReader
	RandReader = bytes.NewReader(bytes.Repeat([]byte{0xef}, 20))
	t.Cleanup(func() { RandReader = saved })

	var sp *ServiceProvider
	assert.Check(t, is.DeepEqual(bytes.Repeat([]byte{0xef}, 20), randomBytes(sp.randReader(), 20)))
}

func TestEncrypterWithRand(t *testing.T) {
	r := bytes.NewReader(nil)
	other := bytes.NewReader(nil)

	got, ok := encrypterWithRand(xmlenc.OAEP(), r).(xmlenc.RSA)
	assert.Assert(t, ok)
	assert.Check(t, got.Rand == r, "the Rand of the RSA was not set")

	withOwn := xmlenc.OAEP()
	withOwn.Rand = other
	got, ok = encrypterWithRand(withOwn, r).(xmlenc.RSA)
	assert.Assert(t, ok)
	assert.Check(t, got.Rand == other, "the RSA's own Rand was replaced")

	ptr := xmlenc.OAEP()
	got, ok = encrypterWithRand(&ptr, r).(xmlenc.RSA)
	assert.Assert(t, ok)
	assert.Check(t, got.Rand == r, "the Rand of the *RSA was not set")
	assert.Check(t, ptr.Rand == nil, "the caller's *RSA was modified")

	got, ok = encrypterWithRand(xmlenc.OAEP(), nil).(xmlenc.RSA)
	assert.Assert(t, ok)
	assert.Check(t, got.Rand == nil, "a nil Rand was set")
}

func TestIdentityProviderRandIsUsedToEncrypt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	readErr := errors.New("the IdentityProvider's Rand was read")
	idp := &IdentityProvider{Rand: iotest.ErrReader(readErr)}
	nameID := &NameID{Value: "alice"}
	_, err = encryptIdentifier(nameID.Element(), cert, encrypterWithRand(identifierEncrypter(nil, nil), idp.configuredRand()))
	assert.Check(t, errors.Is(err, readErr), "got %v", err)
}
