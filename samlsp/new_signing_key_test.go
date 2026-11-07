package samlsp

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// An Ed25519 Key can sign session JWTs, so New accepts it as long as no XML
// signature is requested, and returns an error (instead of panicking) when
// one is.
func TestNewEd25519Key(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	assert.Assert(t, err)
	base := Options{
		URL: url.URL{Scheme: "https", Host: "sp.example.com"},
		Key: key,
	}

	m, err := New(base)
	assert.Assert(t, err)
	assert.Check(t, is.Equal("", m.ServiceProvider.SignatureMethod))
	assert.Check(t, is.Equal("", m.ServiceProvider.LogoutSignatureMethod))

	for _, opts := range []Options{
		func() Options { o := base; o.SignRequest = true; return o }(),
		func() Options { o := base; o.SignLogout = true; return o }(),
	} {
		_, err := New(opts)
		assert.Assert(t, err != nil)
		assert.Check(t, strings.Contains(err.Error(), "ed25519.PublicKey"), err.Error())
	}
}
