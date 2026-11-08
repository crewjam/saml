// Package store keeps the tool's state in SQLite: the test IdPs and SPs
// that visitors create, the messages they exchange, logins in progress,
// and the replay record of the SAML library.
//
// Everything in it is temporary. Each instance expires a fixed time after
// it is created, and Reap deletes it and everything that belongs to it.
// The database itself outlives restarts and deploys (see fly.toml), so
// its schema changes only by migration: see migrations.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crewjam/saml"

	_ "modernc.org/sqlite" // the database/sql driver "sqlite", pure Go
)

// Kind is the kind of an Instance.
type Kind string

// The kinds of Instance.
const (
	KindIDP Kind = "idp" // a test identity provider
	KindSP  Kind = "sp"  // a test service provider
)

// ErrNotFound is returned for an instance, or a pending login, that does
// not exist or has expired.
var ErrNotFound = errors.New("not found or expired")

// ErrTaken is returned by CreateInstance when an instance already has the
// new one's ID or secret.
var ErrTaken = errors.New("the name is taken")

// Instance is a test IdP or SP.
type Instance struct {
	// ID names the instance in its protocol URLs (metadata, SSO, ACS).
	// It is public: it is in the metadata given to other parties.
	ID string

	// Secret names the instance in the URL of its management page. Only
	// whoever created the instance knows it.
	Secret string

	Kind      Kind
	KeyPEM    string
	CertPEM   string
	Config    json.RawMessage
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Event is a message an instance sent or received, or an error.
type Event struct {
	ID         int64
	InstanceID string
	At         time.Time
	// Direction is "in", "out" or "".
	Direction string
	Title     string
	Detail    string
	XML       string
	OK        bool

	// ExchangeID is the HTTP exchange in which the event happened (see
	// Exchange), or 0.
	ExchangeID int64
}

// Exchange is an HTTP request an instance received, and its response,
// as text: the start line, headers and body of each, with secrets such as
// cookie values shortened. It is kept for the events that happened in it.
type Exchange struct {
	ID         int64
	InstanceID string
	Request    string
	Response   string
}

// Store is the database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// migrations bring a database's schema up to date. migrations[i] takes a
// database whose PRAGMA user_version is i to i+1, in one transaction.
// The database outlives deploys, so never edit or remove a migration that
// has shipped, and never drop a table with data in it: add a migration
// that alters what is there.
var migrations = []string{
	// 1: the schema as first deployed with a volume. A database made
	// before versioning has user_version 0 and these tables already;
	// IF NOT EXISTS leaves them as they are.
	schema,
}

const schema = `
CREATE TABLE IF NOT EXISTS instances (
	id         TEXT PRIMARY KEY,
	secret     TEXT NOT NULL UNIQUE,
	kind       TEXT NOT NULL,
	key_pem    TEXT NOT NULL,
	cert_pem   TEXT NOT NULL,
	config     TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS instances_expires ON instances(expires_at);

CREATE TABLE IF NOT EXISTS events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	at          INTEGER NOT NULL,
	direction   TEXT NOT NULL,
	title       TEXT NOT NULL,
	detail      TEXT NOT NULL,
	xml         TEXT NOT NULL,
	ok          INTEGER NOT NULL,
	exchange_id INTEGER
);
CREATE INDEX IF NOT EXISTS events_instance ON events(instance_id, id);

CREATE TABLE IF NOT EXISTS exchanges (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	request     TEXT NOT NULL,
	response    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending (
	id          TEXT PRIMARY KEY,
	instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	data        TEXT NOT NULL,
	expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	id          TEXT PRIMARY KEY,
	instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	data        TEXT NOT NULL,
	created_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_instance ON sessions(instance_id, created_at);

CREATE TABLE IF NOT EXISTS artifacts (
	artifact    TEXT PRIMARY KEY,
	instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	recipient   TEXT NOT NULL,
	xml         BLOB NOT NULL,
	expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS replay (
	key        BLOB PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
`

// MaxEventsPerInstance is how many events are kept for each instance;
// older ones are dropped.
const MaxEventsPerInstance = 50

// Open opens (creating if need be) the database at path. ":memory:" makes
// a database that lives only as long as the Store.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	if path == ":memory:" {
		dsn = "file::memory:?_pragma=foreign_keys(1)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: SQLite serializes writes anyway, and an in-memory
	// database exists per connection.
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, now: time.Now}, nil
}

// migrate runs the migrations a database has not had yet.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("cannot read the schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("the database has schema version %d, but this server knows only up to %d: it was written by a newer server", version, len(migrations))
	}
	for v := version; v < len(migrations); v++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("cannot migrate the schema to version %d: %w", v+1, err)
		}
		// PRAGMA takes no parameters; v+1 is an int.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("cannot migrate the schema to version %d: %w", v+1, err)
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// CountInstances returns the number of instances that have not expired.
func (s *Store) CountInstances(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM instances WHERE expires_at > ?`, s.now().Unix()).Scan(&n)
	return n, err
}

// CreateInstance stores a new instance. It returns ErrTaken if another
// instance, even an expired one not yet reaped, has its ID or secret.
func (s *Store) CreateInstance(ctx context.Context, in *Instance) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO instances (id, secret, kind, key_pem, cert_pem, config, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.Secret, string(in.Kind), in.KeyPEM, in.CertPEM, string(in.Config), in.CreatedAt.Unix(), in.ExpiresAt.Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return fmt.Errorf("%w: %v", ErrTaken, err)
	}
	return err
}

const instanceColumns = `id, secret, kind, key_pem, cert_pem, config, created_at, expires_at`

func scanInstance(row *sql.Row) (*Instance, error) {
	var in Instance
	var kind, config string
	var created, expires int64
	err := row.Scan(&in.ID, &in.Secret, &kind, &in.KeyPEM, &in.CertPEM, &config, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	in.Kind = Kind(kind)
	in.Config = json.RawMessage(config)
	in.CreatedAt = time.Unix(created, 0)
	in.ExpiresAt = time.Unix(expires, 0)
	return &in, nil
}

// Instance returns the instance with the public id and kind.
func (s *Store) Instance(ctx context.Context, kind Kind, id string) (*Instance, error) {
	return scanInstance(s.db.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM instances
		WHERE id = ? AND kind = ? AND expires_at > ?`, id, string(kind), s.now().Unix()))
}

// InstanceBySecret returns the instance with the management secret.
func (s *Store) InstanceBySecret(ctx context.Context, secret string) (*Instance, error) {
	return scanInstance(s.db.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM instances
		WHERE secret = ? AND expires_at > ?`, secret, s.now().Unix()))
}

// UpdateConfig replaces the configuration of an instance.
func (s *Store) UpdateConfig(ctx context.Context, id string, config json.RawMessage) error {
	res, err := s.db.ExecContext(ctx, `UPDATE instances SET config = ? WHERE id = ? AND expires_at > ?`,
		string(config), id, s.now().Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteInstance deletes an instance and everything that belongs to it.
func (s *Store) DeleteInstance(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM instances WHERE id = ?`, id)
	return err
}

// AddEvent records an event, sets its ID and At, and drops the instance's oldest events
// beyond MaxEventsPerInstance.
func (s *Store) AddEvent(ctx context.Context, e *Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	ok := 0
	if e.OK {
		ok = 1
	}
	at := s.now()
	res, err := tx.ExecContext(ctx, `INSERT INTO events (instance_id, at, direction, title, detail, xml, ok)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, e.InstanceID, at.UnixMilli(), e.Direction, e.Title, e.Detail, e.XML, ok)
	if err != nil {
		return err
	}
	if e.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	e.At = time.UnixMilli(at.UnixMilli())
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE instance_id = ? AND id NOT IN
		(SELECT id FROM events WHERE instance_id = ? ORDER BY id DESC LIMIT ?)`,
		e.InstanceID, e.InstanceID, MaxEventsPerInstance); err != nil {
		return err
	}
	if err := deleteOrphanExchanges(ctx, tx, e.InstanceID); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteOrphanExchanges deletes an instance's exchanges that no event
// refers to any more.
func deleteOrphanExchanges(ctx context.Context, tx *sql.Tx, instanceID string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM exchanges WHERE instance_id = ? AND id NOT IN
		(SELECT exchange_id FROM events WHERE instance_id = ? AND exchange_id IS NOT NULL)`, instanceID, instanceID)
	return err
}

// AddExchange stores an exchange, and links the events eventIDs of its
// instance to it.
func (s *Store) AddExchange(ctx context.Context, x *Exchange, eventIDs []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	res, err := tx.ExecContext(ctx, `INSERT INTO exchanges (instance_id, request, response) VALUES (?, ?, ?)`,
		x.InstanceID, x.Request, x.Response)
	if err != nil {
		return err
	}
	if x.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	for _, id := range eventIDs {
		if _, err := tx.ExecContext(ctx, `UPDATE events SET exchange_id = ? WHERE id = ? AND instance_id = ?`,
			x.ID, id, x.InstanceID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetExchange returns an exchange of an instance.
func (s *Store) GetExchange(ctx context.Context, instanceID string, id int64) (*Exchange, error) {
	x := Exchange{ID: id, InstanceID: instanceID}
	err := s.db.QueryRowContext(ctx, `SELECT request, response FROM exchanges WHERE id = ? AND instance_id = ?`,
		id, instanceID).Scan(&x.Request, &x.Response)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &x, err
}

const eventColumns = `id, instance_id, at, direction, title, detail, xml, ok, COALESCE(exchange_id, 0)`

func scanEvent(scan func(...any) error) (Event, error) {
	var e Event
	var at int64
	var ok int
	err := scan(&e.ID, &e.InstanceID, &at, &e.Direction, &e.Title, &e.Detail, &e.XML, &ok, &e.ExchangeID)
	e.At = time.UnixMilli(at)
	e.OK = ok != 0
	return e, err
}

// GetEvent returns an event of an instance.
func (s *Store) GetEvent(ctx context.Context, instanceID string, id int64) (*Event, error) {
	e, err := scanEvent(s.db.QueryRowContext(ctx, `SELECT `+eventColumns+` FROM events WHERE id = ? AND instance_id = ?`,
		id, instanceID).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &e, err
}

// AdjacentEvents returns the IDs of the events of an instance just before
// and just after id, or 0 where there is none.
func (s *Store) AdjacentEvents(ctx context.Context, instanceID string, id int64) (older, newer int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT MAX(id) FROM events WHERE instance_id = ? AND id < ?), 0),
		COALESCE((SELECT MIN(id) FROM events WHERE instance_id = ? AND id > ?), 0)`,
		instanceID, id, instanceID, id).Scan(&older, &newer)
	return older, newer, err
}

// RecentEvents returns the newest events of any of the instances, newest
// first, at most limit.
func (s *Store) RecentEvents(ctx context.Context, instanceIDs []string, limit int) ([]Event, error) {
	if len(instanceIDs) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(instanceIDs)+1)
	marks := make([]string, len(instanceIDs))
	for i, id := range instanceIDs {
		marks[i] = "?"
		args = append(args, id)
	}
	args = append(args, limit)
	//nolint:gosec // G202: only constant columns and "?" placeholders are concatenated
	rows, err := s.db.QueryContext(ctx, `SELECT `+eventColumns+` FROM events
		WHERE instance_id IN (`+strings.Join(marks, ",")+`) ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Events returns an instance's events, newest first.
func (s *Store) Events(ctx context.Context, instanceID string) ([]Event, error) {
	return s.EventsAfter(ctx, instanceID, 0)
}

// EventsAfter returns an instance's events whose ID is greater than
// after, newest first.
func (s *Store) EventsAfter(ctx context.Context, instanceID string, after int64) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+eventColumns+` FROM events
		WHERE instance_id = ? AND id > ? ORDER BY id DESC`, instanceID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []Event
	for rows.Next() {
		e, err := scanEvent(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClearEvents deletes all of an instance's events, and their exchanges.
func (s *Store) ClearEvents(ctx context.Context, instanceID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE instance_id = ?`, instanceID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM exchanges WHERE instance_id = ?`, instanceID)
	return err
}

// PutPending keeps (or replaces) data, such as an AuthnRequest waiting for the user to
// log in, under id until ttl has passed.
func (s *Store) PutPending(ctx context.Context, id, instanceID string, data any, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO pending (id, instance_id, data, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
		WHERE pending.instance_id = excluded.instance_id`,
		id, instanceID, string(b), s.now().Add(ttl).Unix())
	return err
}

// GetPending reads the data kept under id, for instanceID, into v. It is
// not removed, so that a login page can be reloaded or submitted again
// with other choices.
func (s *Store) GetPending(ctx context.Context, id, instanceID string, v any) error {
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM pending WHERE id = ? AND instance_id = ? AND expires_at > ?`,
		id, instanceID, s.now().Unix()).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), v)
}

// DeletePending deletes the data kept under id.
func (s *Store) DeletePending(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending WHERE id = ?`, id)
	return err
}

// Consume implements the ReplayState of x/samlsp and x/samlidp: it
// records key until expiresAt, and fails with saml.ErrAssertionReplayed
// if it is already recorded and has not expired.
func (s *Store) Consume(ctx context.Context, key []byte, expiresAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO replay (key, expires_at) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET expires_at = excluded.expires_at WHERE replay.expires_at <= ?`,
		key, expiresAt.Unix(), s.now().Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return saml.ErrAssertionReplayed
	}
	return nil
}

// Reap deletes everything that has expired, and returns how many
// instances it deleted.
func (s *Store) Reap(ctx context.Context) (int64, error) {
	now := s.now().Unix()
	res, err := s.db.ExecContext(ctx, `DELETE FROM instances WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM pending WHERE expires_at <= ?`, now); err != nil {
		return n, err
	}
	for _, table := range []string{"replay", "sessions", "artifacts"} {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_at <= ?`, now); err != nil { //nolint:gosec // G202: table is from a fixed list
			return n, err
		}
	}
	return n, nil
}

// Session is a user's login session at a test IdP or SP. Data is the
// instance's own record of it, as JSON.
type Session struct {
	ID         string
	InstanceID string
	Data       json.RawMessage
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// MaxSessionsPerInstance is how many sessions are kept for each instance;
// the oldest are dropped.
const MaxSessionsPerInstance = 100

// PutSession stores a session, replacing one with the same ID.
func (s *Store) PutSession(ctx context.Context, sess *Session) error {
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = s.now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (id, instance_id, data, created_at, expires_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
		WHERE sessions.instance_id = excluded.instance_id`,
		sess.ID, sess.InstanceID, string(sess.Data), sess.CreatedAt.UnixMilli(), sess.ExpiresAt.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE instance_id = ? AND id NOT IN
		(SELECT id FROM sessions WHERE instance_id = ? ORDER BY created_at DESC LIMIT ?)`,
		sess.InstanceID, sess.InstanceID, MaxSessionsPerInstance); err != nil {
		return err
	}
	return tx.Commit()
}

// GetSession returns the session with id at instanceID.
func (s *Store) GetSession(ctx context.Context, id, instanceID string) (*Session, error) {
	sess := Session{ID: id, InstanceID: instanceID}
	var data string
	var created, expires int64
	err := s.db.QueryRowContext(ctx, `SELECT data, created_at, expires_at FROM sessions
		WHERE id = ? AND instance_id = ? AND expires_at > ?`, id, instanceID, s.now().Unix()).Scan(&data, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.Data = json.RawMessage(data)
	sess.CreatedAt = time.UnixMilli(created)
	sess.ExpiresAt = time.Unix(expires, 0)
	return &sess, nil
}

// Sessions returns an instance's sessions, newest first.
func (s *Store) Sessions(ctx context.Context, instanceID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, data, created_at, expires_at FROM sessions
		WHERE instance_id = ? AND expires_at > ? ORDER BY created_at DESC`, instanceID, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []Session
	for rows.Next() {
		sess := Session{InstanceID: instanceID}
		var data string
		var created, expires int64
		if err := rows.Scan(&sess.ID, &data, &created, &expires); err != nil {
			return nil, err
		}
		sess.Data = json.RawMessage(data)
		sess.CreatedAt = time.UnixMilli(created)
		sess.ExpiresAt = time.Unix(expires, 0)
		out = append(out, sess)
	}
	return out, rows.Err()
}

// DeleteSession deletes a session of an instance.
func (s *Store) DeleteSession(ctx context.Context, id, instanceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ? AND instance_id = ?`, id, instanceID)
	return err
}

// SaveArtifact keeps a message until its artifact is resolved by
// recipient, for the HTTP-Artifact binding.
func (s *Store) SaveArtifact(ctx context.Context, instanceID, artifact, recipient string, xml []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts (artifact, instance_id, recipient, xml, expires_at) VALUES (?, ?, ?, ?, ?)`,
		artifact, instanceID, recipient, xml, expiresAt.Unix())
	return err
}

// TakeArtifact returns the message kept under artifact for recipient, and
// deletes it, so that it is given out once. It returns found false if
// there is none, or if it is for another recipient, which is then kept.
func (s *Store) TakeArtifact(ctx context.Context, instanceID, artifact, recipient string) (xml []byte, expiresAt time.Time, found bool, err error) {
	var expires int64
	err = s.db.QueryRowContext(ctx, `DELETE FROM artifacts WHERE artifact = ? AND instance_id = ? AND recipient = ?
		RETURNING xml, expires_at`, artifact, instanceID, recipient).Scan(&xml, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, err
	}
	return xml, time.Unix(expires, 0), true, nil
}
