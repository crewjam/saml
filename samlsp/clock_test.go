package samlsp

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// setWrongGlobalClock points the deprecated package-level clocks at a time
// far from any Clock a test sets, to show that the Clock fields take
// precedence over them.
func setWrongGlobalClock(t *testing.T) {
	t.Helper()
	oldTimeNow, oldClock := saml.TimeNow, saml.Clock
	t.Cleanup(func() { saml.TimeNow, saml.Clock = oldTimeNow, oldClock })
	wrong := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	saml.TimeNow = func() time.Time { return wrong }
	saml.Clock = dsig.NewFakeClockAt(wrong)
}

func TestOptionsClockIsPropagated(t *testing.T) {
	clock := dsig.NewFakeClockAt(time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC))
	m, err := New(Options{URL: mustParseURL("https://sp.example.com/"), Key: covRSAKey(t), Clock: clock})
	assert.NilError(t, err)

	assert.Check(t, m.ServiceProvider.Clock == clock)
	sessions := m.Session.(CookieSessionProvider)
	assert.Check(t, sessions.Clock == clock)
	assert.Check(t, sessions.Codec.(JWTSessionCodec).Clock == clock)
	assert.Check(t, sessions.Revocations.(*MemorySessionRevocationStore).Clock == clock)
	assert.Check(t, m.RequestTracker.(CookieRequestTracker).Codec.(JWTTrackedRequestCodec).Clock == clock)
	assert.Check(t, m.LogoutRequestTracker.(CookieRequestTracker).Codec.(JWTTrackedRequestCodec).Clock == clock)
}

func TestJWTSessionCodecClock(t *testing.T) {
	setWrongGlobalClock(t)
	issuedAt := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)
	codec := covSessionCodec(t)
	codec.Clock = dsig.NewFakeClockAt(issuedAt)

	session, err := codec.New(&saml.Assertion{})
	assert.NilError(t, err)
	claims := session.(JWTSessionClaims)
	assert.Check(t, is.Equal(issuedAt, claims.IssuedAt.UTC()))
	assert.Check(t, is.Equal(issuedAt.Add(codec.MaxAge), claims.ExpiresAt.UTC()))

	encoded, err := codec.Encode(session)
	assert.NilError(t, err)
	_, err = codec.Decode(encoded)
	assert.Check(t, err)

	codec.Clock = dsig.NewFakeClockAt(issuedAt.Add(codec.MaxAge + time.Minute))
	_, err = codec.Decode(encoded)
	assert.Check(t, is.ErrorIs(err, jwt.ErrTokenExpired))
}

func TestJWTTrackedRequestCodecClock(t *testing.T) {
	setWrongGlobalClock(t)
	issuedAt := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)
	codec := covTrackedRequestCodec(t)
	codec.Clock = dsig.NewFakeClockAt(issuedAt)

	encoded, err := codec.Encode(TrackedRequest{Index: "idx", SAMLRequestID: "id-1"})
	assert.NilError(t, err)
	tr, err := codec.Decode(encoded)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("id-1", tr.SAMLRequestID))

	codec.Clock = dsig.NewFakeClockAt(issuedAt.Add(codec.MaxAge + time.Minute))
	_, err = codec.Decode(encoded)
	assert.Check(t, is.ErrorIs(err, jwt.ErrTokenExpired))
}

func TestMemoryStoresClock(t *testing.T) {
	setWrongGlobalClock(t)
	now := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("replay cache", func(t *testing.T) {
		c := NewMemoryReplayCache(1)
		c.Clock = dsig.NewFakeClockAt(now)
		assert.NilError(t, c.Consume("a", now.Add(time.Minute)))
		assert.Check(t, is.ErrorIs(c.Consume("a", now.Add(time.Minute)), saml.ErrAssertionReplayed))
		// Once the clock passes the expiry, the record is dropped.
		c.Clock = dsig.NewFakeClockAt(now.Add(2 * time.Minute))
		assert.Check(t, c.Consume("b", now.Add(time.Hour)))
	})

	t.Run("session revocations", func(t *testing.T) {
		s := NewMemorySessionRevocationStore(1)
		s.Clock = dsig.NewFakeClockAt(now)
		ctx := context.Background()
		assert.NilError(t, s.Revoke(ctx, "k", now, now.Add(time.Minute)))
		revokedAt, err := s.RevokedAt(ctx, "k")
		assert.NilError(t, err)
		assert.Check(t, is.Equal(now, revokedAt))
		s.Clock = dsig.NewFakeClockAt(now.Add(2 * time.Minute))
		revokedAt, err = s.RevokedAt(ctx, "k")
		assert.NilError(t, err)
		assert.Check(t, revokedAt.IsZero())
	})

	t.Run("form replay", func(t *testing.T) {
		s := &MemoryFormReplayStore{MaxAge: time.Minute, Clock: dsig.NewFakeClockAt(now)}
		r := httptest.NewRequest("POST", "https://sp.example.com/form", nil)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		saved, err := s.SaveForm(r, "idx")
		assert.NilError(t, err)
		assert.Assert(t, saved)
		s.Clock = dsig.NewFakeClockAt(now.Add(2 * time.Minute))
		_, ok, err := s.TakeForm(r, "idx")
		assert.NilError(t, err)
		assert.Check(t, !ok)
	})
}
