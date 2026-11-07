package samlsp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// SessionTerminator is implemented by a SessionProvider that can end
// sessions on the server, without the browser that holds them. ServeSLO
// needs it to honor a LogoutRequest the IdP sends with the SOAP binding
// (back-channel single logout): no browser is involved, so the session
// cookie cannot be deleted, and the session must be refused the next time
// it is presented instead.
//
// CookieSessionProvider implements it when its Revocations store is set and
// its Codec implements RevocableSessionCodec.
type SessionTerminator interface {
	// TerminateSessions ends the sessions that req, a LogoutRequest from
	// the IdP that has been validated, names (saml-core §3.7.1): those of
	// its NameID with one of its SessionIndexes or, if it has none, every
	// session of its NameID. Sessions made after it returns are not
	// affected. It returns an error if it could not end them all.
	TerminateSessions(ctx context.Context, req *saml.LogoutRequest) error
}

// ErrSessionTerminationUnsupported is returned by
// CookieSessionProvider.TerminateSessions when the provider has no
// Revocations store, so it cannot end a session without the browser.
var ErrSessionTerminationUnsupported = errors.New("saml: the session provider cannot end sessions on the server")

// ErrSessionRevoked is wrapped, together with ErrNoSession, in the error
// CookieSessionProvider.GetSession returns for a session that has been
// ended by back-channel single logout.
var ErrSessionRevoked = errors.New("saml: the session has been revoked")

// RevocableSession is a session that a CookieSessionProvider can check
// against its Revocations: it knows the NameID of its user and when it was
// issued. If it also implements SessionWithAttributes, the values of its
// "SessionIndex" attribute are its SessionIndexes. JWTSessionClaims
// implements it; a custom SessionCodec must make sessions that implement it,
// and declare so by implementing RevocableSessionCodec, for back-channel
// single logout to end them.
type RevocableSession interface {
	SessionWithNameID

	// GetSessionIssuedAt returns when the session was issued.
	GetSessionIssuedAt() time.Time
}

// GetSessionIssuedAt implements RevocableSession. It returns the time of the
// JWT "iat" claim, which has a precision of one second, or the zero time if
// the token has none.
func (c JWTSessionClaims) GetSessionIssuedAt() time.Time {
	if c.IssuedAt == nil {
		return time.Time{}
	}
	return c.IssuedAt.Time
}

var _ RevocableSession = JWTSessionClaims{}

// RevocableSessionCodec is a SessionCodec that declares whether the sessions
// it decodes can be checked against the Revocations of a
// CookieSessionProvider. CookieSessionProvider.TerminateSessions ends
// sessions only when its Codec implements it and RevocableSessions reports
// true: otherwise GetSession could not refuse the sessions it records, and
// the IdP would be told that they had ended when they had not.
//
// JWTSessionCodec implements it. A custom SessionCodec whose sessions
// implement RevocableSession should implement it too.
type RevocableSessionCodec interface {
	SessionCodec

	// RevocableSessions reports whether every Session that Decode returns
	// implements RevocableSession, with the NameID value and (as the
	// "SessionIndex" attribute of SessionWithAttributes) the SessionIndexes
	// of the assertion it was made from, and the time it was issued. These
	// must be protected from change by the client, as the signature of a
	// JWT protects them.
	RevocableSessions() bool
}

// RevocableSessions implements RevocableSessionCodec: the JWTSessionClaims
// it decodes are RevocableSessions, and the JWT signature covers what
// identifies them.
func (JWTSessionCodec) RevocableSessions() bool { return true }

var _ RevocableSessionCodec = JWTSessionCodec{}

// SessionRevocationStore records revoked sessions for a
// CookieSessionProvider. Each record has a key, which names either every
// session of a user or the sessions of a user with a given SessionIndex, and
// a time: sessions with that key issued at or before it are revoked.
//
// Implementations must be safe for concurrent use. MemorySessionRevocationStore
// keeps records in memory, for a single server; deployments with several
// servers must share the records between them, for example in a database or
// a cache server, so that a session revoked by the server that received the
// IdP's LogoutRequest is refused by all of them.
//
// Keys are at most 80 bytes of ASCII letters, digits and colons.
type SessionRevocationStore interface {
	// Revoke records that the sessions with key issued at or before
	// revokedAt are revoked. If key is already recorded, the later of the
	// two times is kept. The record is needed until expiresAt, when every
	// such session has expired, and may be dropped after that.
	Revoke(ctx context.Context, key string, revokedAt, expiresAt time.Time) error

	// RevokedAt returns the time recorded for key, or the zero time if
	// none is recorded (or its record has expired).
	RevokedAt(ctx context.Context, key string) (time.Time, error)
}

// nameIDRevocationKey returns the revocation key of every session of the
// user whose NameID has the value nameID.
//
// Sessions are matched by the NameID value alone, not its Format and
// qualifiers: a samlsp Middleware trusts a single IdP, which issues the
// values, and sessions made before samlsp recorded the Format have only the
// value. Matching by value can only end more sessions than an exact match
// would, never fewer.
func nameIDRevocationKey(nameID string) string {
	sum := sha256.Sum256([]byte(nameID))
	return "nameid:" + hex.EncodeToString(sum[:])
}

// sessionIndexRevocationKey returns the revocation key of the sessions of
// the user whose NameID has the value nameID with the given SessionIndex.
func sessionIndexRevocationKey(nameID, sessionIndex string) string {
	h := sha256.New()
	// The length of nameID separates it from sessionIndex unambiguously.
	_ = binary.Write(h, binary.BigEndian, uint64(len(nameID)))
	h.Write([]byte(nameID))
	h.Write([]byte(sessionIndex))
	return "sessionindex:" + hex.EncodeToString(h.Sum(nil))
}

// TerminateSessions implements SessionTerminator. It records the sessions
// that req names in Revocations, where GetSession finds them: every session
// of req's NameID issued up to now if req has no SessionIndex, and
// otherwise those with one of its SessionIndexes, as well as those with no
// SessionIndex at all, which cannot be told apart from them. Sessions issued
// later, such as after the user logs in again, are not affected. The
// records are kept
// until such sessions have expired, the longer of MaxAge and, if Codec is a
// JWTSessionCodec, its MaxAge, from now.
//
// It returns ErrSessionTerminationUnsupported if Revocations is nil or Codec
// does not declare, by implementing RevocableSessionCodec, that its sessions
// can be revoked, and an error matching saml.ErrUnsupported if req
// identifies the user with a BaseID rather than a NameID.
func (c CookieSessionProvider) TerminateSessions(ctx context.Context, req *saml.LogoutRequest) error {
	if c.Revocations == nil {
		return ErrSessionTerminationUnsupported
	}
	if codec, ok := c.Codec.(RevocableSessionCodec); !ok || !codec.RevocableSessions() {
		// GetSession could not tell the sessions apart, and would go on
		// accepting them: report failure rather than pretend to end them.
		return fmt.Errorf("%w: the sessions of %T cannot be revoked (see RevocableSessionCodec)",
			ErrSessionTerminationUnsupported, c.Codec)
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return fmt.Errorf("%w: the LogoutRequest has no NameID", saml.ErrUnsupported)
	}
	nameID := req.NameID.Value
	now := saml.TimeNow()
	expiresAt := now.Add(c.sessionLifetime())

	sessionIndexes := req.AllSessionIndexes()
	if len(sessionIndexes) == 0 {
		return c.Revocations.Revoke(ctx, nameIDRevocationKey(nameID), now, expiresAt)
	}
	// A session without a SessionIndex cannot be told apart from the ones
	// named, so it is ended too: it is recorded under the empty
	// SessionIndex, which a LogoutRequest cannot name (saml-core §3.7.1
	// makes SessionIndex a non-empty string).
	for _, sessionIndex := range append(sessionIndexes, saml.SessionIndex{}) {
		if err := c.Revocations.Revoke(ctx, sessionIndexRevocationKey(nameID, sessionIndex.Value), now, expiresAt); err != nil {
			return err
		}
	}
	return nil
}

// sessionLifetime returns how long a session issued now may be accepted.
func (c CookieSessionProvider) sessionLifetime() time.Duration {
	lifetime := c.MaxAge
	if codec, ok := c.Codec.(JWTSessionCodec); ok && codec.MaxAge > lifetime {
		lifetime = codec.MaxAge
	}
	if lifetime <= 0 {
		lifetime = defaultSessionMaxAge
	}
	return lifetime
}

// checkRevoked returns an error if session is revoked in Revocations, or if
// that cannot be checked. Sessions that do not implement RevocableSession
// cannot be revoked.
func (c CookieSessionProvider) checkRevoked(ctx context.Context, session Session) error {
	if c.Revocations == nil {
		return nil
	}
	revocable, ok := session.(RevocableSession)
	if !ok {
		return nil
	}
	nameID := revocable.GetNameID()
	if nameID == "" {
		return nil
	}
	var sessionIndexes []string
	if withAttributes, ok := session.(SessionWithAttributes); ok {
		sessionIndexes = withAttributes.GetAttributes()[claimNameSessionIndex]
	}

	if len(sessionIndexes) == 0 {
		// See TerminateSessions.
		sessionIndexes = []string{""}
	}
	keys := make([]string, 0, 1+len(sessionIndexes))
	keys = append(keys, nameIDRevocationKey(nameID))
	for _, sessionIndex := range sessionIndexes {
		keys = append(keys, sessionIndexRevocationKey(nameID, sessionIndex))
	}
	issuedAt := revocable.GetSessionIssuedAt()
	for _, key := range keys {
		revokedAt, err := c.Revocations.RevokedAt(ctx, key)
		if err != nil {
			return fmt.Errorf("saml: cannot check whether the session is revoked: %w", err)
		}
		if !revokedAt.IsZero() && !issuedAt.After(revokedAt) {
			return fmt.Errorf("%w: %w", ErrNoSession, ErrSessionRevoked)
		}
	}
	return nil
}

// DefaultMaxSessionRevocations is the number of records the
// MemorySessionRevocationStore of DefaultSessionProvider holds.
const DefaultMaxSessionRevocations = 100000

// ErrSessionRevocationStoreFull is returned by a MemorySessionRevocationStore
// that holds its maximum number of unexpired records. The sessions are not
// revoked, and back-channel logout answers the IdP that it failed.
var ErrSessionRevocationStoreFull = errors.New("samlsp: session revocation store is full")

// MemorySessionRevocationStore is a SessionRevocationStore that keeps its
// records in memory. It is safe for concurrent use.
//
// It only serves a single process: a session revoked by one server is still
// accepted by another, and by this one after a restart. Deployments with
// more than one server must use a shared store instead.
//
// It holds at most maxEntries records. A record is dropped once it has
// expired, which is when every session it revokes has expired. A logout
// adds one record, or one per SessionIndex. When the store is full of
// unexpired records, Revoke refuses new ones with
// ErrSessionRevocationStoreFull rather than drop an unexpired one, which
// would let a revoked session be used again.
//
// Expiry is judged by saml.TimeNow.
type MemorySessionRevocationStore struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[string]sessionRevocation
	// nextExpiry is the earliest expiry in entries, or zero when it may be
	// stale; no record can be dropped before it.
	nextExpiry time.Time
}

type sessionRevocation struct {
	revokedAt, expiresAt time.Time
}

var _ SessionRevocationStore = (*MemorySessionRevocationStore)(nil)

// NewMemorySessionRevocationStore returns a MemorySessionRevocationStore
// that holds at most maxEntries unexpired records. It panics if maxEntries
// is not positive.
func NewMemorySessionRevocationStore(maxEntries int) *MemorySessionRevocationStore {
	if maxEntries <= 0 {
		panic(fmt.Sprintf("samlsp: NewMemorySessionRevocationStore: maxEntries must be positive, got %d", maxEntries))
	}
	return &MemorySessionRevocationStore{
		maxEntries: maxEntries,
		entries:    map[string]sessionRevocation{},
	}
}

// Revoke implements SessionRevocationStore.
func (s *MemorySessionRevocationStore) Revoke(_ context.Context, key string, revokedAt, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := saml.TimeNow()
	if prev, ok := s.entries[key]; ok && !now.After(prev.expiresAt) {
		if prev.revokedAt.After(revokedAt) {
			revokedAt = prev.revokedAt
		}
		if prev.expiresAt.After(expiresAt) {
			expiresAt = prev.expiresAt
		}
	} else {
		delete(s.entries, key)
		if len(s.entries) >= s.maxEntries {
			s.dropExpired(now)
			if len(s.entries) >= s.maxEntries {
				return ErrSessionRevocationStoreFull
			}
		}
	}

	s.entries[key] = sessionRevocation{revokedAt: revokedAt, expiresAt: expiresAt}
	if s.nextExpiry.IsZero() || expiresAt.Before(s.nextExpiry) {
		s.nextExpiry = expiresAt
	}
	return nil
}

// RevokedAt implements SessionRevocationStore.
func (s *MemorySessionRevocationStore) RevokedAt(_ context.Context, key string) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return time.Time{}, nil
	}
	if saml.TimeNow().After(entry.expiresAt) {
		delete(s.entries, key)
		return time.Time{}, nil
	}
	return entry.revokedAt, nil
}

// dropExpired removes the records whose expiry is before now. It does
// nothing before nextExpiry, so a store full of unexpired records is not
// scanned on every call.
func (s *MemorySessionRevocationStore) dropExpired(now time.Time) {
	if !s.nextExpiry.IsZero() && !now.After(s.nextExpiry) {
		return
	}
	s.nextExpiry = time.Time{}
	for key, entry := range s.entries {
		if now.After(entry.expiresAt) {
			delete(s.entries, key)
			continue
		}
		if s.nextExpiry.IsZero() || entry.expiresAt.Before(s.nextExpiry) {
			s.nextExpiry = entry.expiresAt
		}
	}
}
