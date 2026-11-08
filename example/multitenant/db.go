package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// DB is a pretend database: tables in memory, behind one lock. Each method
// is one statement or transaction of a real database, whose SQL its
// comment gives. Every server of the SP would share the real database, so
// the state below outlives any one request or process.
//
//	CREATE TABLE sso_providers (
//		id text PRIMARY KEY,
//		domain text UNIQUE NOT NULL,       -- users of this email domain log in here
//		entity_id text UNIQUE NOT NULL,    -- the IdP's; unique, see AddProvider
//		metadata_xml bytea NOT NULL,
//		allow_idp_initiated boolean NOT NULL
//	);
//	CREATE TABLE relay_states (           -- logins and logouts in progress
//		id text PRIMARY KEY,               -- the RelayState
//		provider_id text NOT NULL REFERENCES sso_providers,
//		request_id text NOT NULL,          -- the AuthnRequest or LogoutRequest
//		redirect_to text NOT NULL,
//		created_at timestamptz NOT NULL
//	);
//	CREATE TABLE saml_replay (            -- samlsp.ReplayState
//		key bytea PRIMARY KEY,
//		expires_at timestamptz NOT NULL
//	);
//	CREATE TABLE sessions (
//		id text PRIMARY KEY,
//		provider_id text NOT NULL REFERENCES sso_providers,
//		name_id jsonb NOT NULL,            -- for single logout
//		session_indexes text[] NOT NULL,
//		email text NOT NULL,
//		expires_at timestamptz NOT NULL
//	);
type DB struct {
	mu          sync.Mutex
	providers   map[string]*Provider
	relayStates map[string]RelayState
	replay      map[string]time.Time
	sessions    map[string]Session
}

// NewDB returns an empty database.
func NewDB() *DB {
	return &DB{
		providers:   map[string]*Provider{},
		relayStates: map[string]RelayState{},
		replay:      map[string]time.Time{},
		sessions:    map[string]Session{},
	}
}

// Provider is an SSO provider: a tenant's IdP.
type Provider struct {
	ID                string
	Domain            string
	EntityID          string
	MetadataXML       []byte
	AllowIdPInitiated bool
}

// IdentityProvider returns the provider's IdP metadata for samlsp. It
// parses the stored XML, which was checked when the provider was added.
func (p *Provider) IdentityProvider() samlsp.MetadataFunc {
	return samlsp.StaticMetadataBytes(p.MetadataXML)
}

// RelayState is a login or logout in progress, found by its RelayState.
type RelayState struct {
	ID         string
	ProviderID string
	RequestID  string
	RedirectTo string
	CreatedAt  time.Time
}

// Session is a user's session, with what single logout needs.
type Session struct {
	ID             string
	ProviderID     string
	NameID         saml.NameID
	SessionIndexes []string
	Email          string
	ExpiresAt      time.Time
}

var (
	errNotFound        = errors.New("not found")
	errDuplicateEntity = errors.New("another provider has this IdP entity ID")
)

func newID() string { return rand.Text() }

// AddProvider stores a provider. Its IdP entity ID must be unique: it names
// the IdP of an IdP-initiated message, and the replay record is kept per
// entity ID (samlsp.ReplayKey), so two tenants must never share one.
//
//	INSERT INTO sso_providers (...) VALUES (...)  -- fails on a duplicate domain or entity_id
func (db *DB) AddProvider(p *Provider) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, other := range db.providers {
		if other.EntityID == p.EntityID {
			return errDuplicateEntity
		}
		if other.Domain == p.Domain {
			return errors.New("another provider has this domain")
		}
	}
	p.ID = newID()
	db.providers[p.ID] = p
	return nil
}

// ProviderByID: SELECT * FROM sso_providers WHERE id = $1
func (db *DB) ProviderByID(id string) (*Provider, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if p, ok := db.providers[id]; ok {
		return p, nil
	}
	return nil, errNotFound
}

// ProviderByDomain: SELECT * FROM sso_providers WHERE domain = $1
func (db *DB) ProviderByDomain(domain string) (*Provider, error) {
	return db.findProvider(func(p *Provider) bool { return p.Domain == domain })
}

// ProviderByEntityID: SELECT * FROM sso_providers WHERE entity_id = $1
func (db *DB) ProviderByEntityID(entityID string) (*Provider, error) {
	return db.findProvider(func(p *Provider) bool { return p.EntityID == entityID })
}

func (db *DB) findProvider(match func(*Provider) bool) (*Provider, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, p := range db.providers {
		if match(p) {
			return p, nil
		}
	}
	return nil, errNotFound
}

// relayStateLifetime is how long a login or logout may stay in progress.
const relayStateLifetime = 10 * time.Minute

// AddRelayState: INSERT INTO relay_states (...) VALUES (...)
func (db *DB) AddRelayState(rs RelayState) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.relayStates[rs.ID] = rs
}

// TakeRelayState removes and returns a relay state that has not expired,
// so that each is used once:
//
//	DELETE FROM relay_states WHERE id = $1 AND created_at > now() - interval '10 minutes' RETURNING *
//
// Expired rows are deleted by a periodic job.
func (db *DB) TakeRelayState(id string) (RelayState, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	rs, ok := db.relayStates[id]
	if !ok {
		return RelayState{}, errNotFound
	}
	delete(db.relayStates, id)
	if time.Since(rs.CreatedAt) > relayStateLifetime {
		return RelayState{}, errNotFound
	}
	return rs, nil
}

// Consume implements samlsp.ReplayState. ctx would be passed to the
// database driver.
//
//	INSERT INTO saml_replay (key, expires_at) VALUES ($1, $2)
//	ON CONFLICT (key) DO UPDATE SET expires_at = EXCLUDED.expires_at
//	WHERE saml_replay.expires_at < now()
//	-- no row inserted or updated: a replay
func (db *DB) Consume(_ context.Context, key []byte, expiresAt time.Time) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	k := hex.EncodeToString(key)
	if exp, ok := db.replay[k]; ok && time.Now().Before(exp) {
		return saml.ErrAssertionReplayed
	}
	db.replay[k] = expiresAt
	return nil
}

// AddSession: INSERT INTO sessions (...) VALUES (...)
func (db *DB) AddSession(s Session) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.sessions[s.ID] = s
}

// SessionByID: SELECT * FROM sessions WHERE id = $1 AND expires_at > now()
func (db *DB) SessionByID(id string) (Session, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	s, ok := db.sessions[id]
	if !ok || time.Now().After(s.ExpiresAt) {
		return Session{}, errNotFound
	}
	return s, nil
}

// DeleteSession: DELETE FROM sessions WHERE id = $1
func (db *DB) DeleteSession(id string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	delete(db.sessions, id)
}

// DeleteSessionsFor ends the sessions that an IdP's LogoutRequest names:
// the user's sessions with the provider, or only those with one of
// sessionIndexes when it is not empty. It returns how many it ended.
//
//	DELETE FROM sessions WHERE provider_id = $1 AND name_id = $2
//	  AND ($3 = '{}' OR session_indexes && $3)
func (db *DB) DeleteSessionsFor(providerID string, nameID saml.NameID, sessionIndexes []string) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	n := 0
	for id, s := range db.sessions {
		if s.ProviderID != providerID || s.NameID.Value != nameID.Value || s.NameID.Format != nameID.Format {
			continue
		}
		if len(sessionIndexes) > 0 && !overlap(s.SessionIndexes, sessionIndexes) {
			continue
		}
		delete(db.sessions, id)
		n++
	}
	return n
}

func overlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
