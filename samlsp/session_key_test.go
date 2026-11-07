package samlsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

func sessionKeyTestOptions(t *testing.T, sessionKey crypto.Signer) Options {
	t.Helper()
	return Options{
		URL:        url.URL{Scheme: "https", Host: "sp.example.com"},
		Key:        covRSAKey(t),
		SessionKey: sessionKey,
	}
}

func TestSessionKeyFallsBackToKey(t *testing.T) {
	opts := sessionKeyTestOptions(t, nil)

	sessionCodec := DefaultSessionCodec(opts)
	assert.Check(t, sessionCodec.Key == opts.Key)
	assert.Check(t, is.Equal(jwt.SigningMethodRS256, sessionCodec.SigningMethod))

	trackedCodec := DefaultTrackedRequestCodec(opts)
	assert.Check(t, trackedCodec.Key == opts.Key)
	assert.Check(t, is.Equal(jwt.SigningMethodRS256, trackedCodec.SigningMethod))

	// A typed nil is treated as unset too.
	var nilKey *ecdsa.PrivateKey
	opts.SessionKey = nilKey
	assert.Check(t, DefaultSessionCodec(opts).Key == opts.Key)
}

func TestSessionKeySignsSessionsAndTrackedRequests(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NilError(t, err)

	for _, tc := range []struct {
		name   string
		key    crypto.Signer
		method jwt.SigningMethod
	}{
		{"P-256", covECDSAKey(t, elliptic.P256()), jwt.SigningMethodES256},
		{"P-384", covECDSAKey(t, elliptic.P384()), jwt.SigningMethodES384},
		{"Ed25519", edKey, jwt.SigningMethodEdDSA},
		{"KMS-like P-384", opaqueSigner{covECDSAKey(t, elliptic.P384())}, jwt.SigningMethodES384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := sessionKeyTestOptions(t, tc.key)
			withoutSessionKey := sessionKeyTestOptions(t, nil)

			sessionCodec := DefaultSessionCodec(opts)
			assert.Check(t, is.DeepEqual(tc.key, sessionCodec.Key))
			assert.Check(t, is.Equal(tc.method, sessionCodec.SigningMethod))

			session, err := sessionCodec.New(&saml.Assertion{})
			assert.NilError(t, err)
			signed, err := sessionCodec.Encode(session)
			assert.NilError(t, err)
			_, err = sessionCodec.Decode(signed)
			assert.NilError(t, err)
			// The SAML key does not verify a session signed with the session key.
			_, err = DefaultSessionCodec(withoutSessionKey).Decode(signed)
			assert.Check(t, err != nil)

			trackedCodec := DefaultTrackedRequestCodec(opts)
			assert.Check(t, is.DeepEqual(tc.key, trackedCodec.Key))
			assert.Check(t, is.Equal(tc.method, trackedCodec.SigningMethod))

			signed, err = trackedCodec.Encode(TrackedRequest{Index: "idx", SAMLRequestID: "id-1", URI: "/here"})
			assert.NilError(t, err)
			tr, err := trackedCodec.Decode(signed)
			assert.NilError(t, err)
			assert.Check(t, is.Equal("id-1", tr.SAMLRequestID))
			_, err = DefaultTrackedRequestCodec(withoutSessionKey).Decode(signed)
			assert.Check(t, err != nil)
		})
	}
}

func TestNewUsesSessionKey(t *testing.T) {
	sessionKey := covECDSAKey(t, elliptic.P256())
	opts := sessionKeyTestOptions(t, sessionKey)

	m, err := New(opts)
	assert.NilError(t, err)

	// The SAML side keeps using Key.
	assert.Check(t, m.ServiceProvider.Key == opts.Key)
	// Sessions and tracked requests use SessionKey.
	assert.Check(t, m.Session.(CookieSessionProvider).Codec.(JWTSessionCodec).Key == crypto.Signer(sessionKey))
	assert.Check(t, m.RequestTracker.(CookieRequestTracker).Codec.(JWTTrackedRequestCodec).Key == crypto.Signer(sessionKey))
}

// opaqueSigner hides the concrete key type, like a KMS or HSM backed signer.
type opaqueSigner struct{ crypto.Signer }
