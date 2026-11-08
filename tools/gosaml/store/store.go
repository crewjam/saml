// Package store keeps the tool's state in SQLite: the test IdPs and SPs
// that visitors create, the messages they exchange, logins in progress,
// and the replay record of the SAML library.
//
// Everything in it is temporary. Each instance expires a fixed time after
// it is created, and Reap deletes it and everything that belongs to it.
// The database itself is meant to live on a disk that does not outlive
// the server (see fly.toml), so a restart forgets everything too.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/crewjam/saml"

	_ "modernc.org/sqlite" // the database/sql driver "sqlite", pure Go
)

// Kind is the kind of an Instance.
type Kind string

const (
	KindIdP Kind = "idp"
	KindSP  Kind = "sp"
)

// ErrNotFound is returned for an instance, or a pending login, that does
// not exist or has expired.
var ErrNotFound = errors.New("not found or expired")

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
}

// Store is the database.
type Store struct {
	db  *sql.DB
	now func() time.Time
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
	ok          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_instance ON events(instance_id, id);

CREATE TABLE IF NOT EXISTS pending (
	id          TEXT PRIMARY KEY,
	instance_id TEXT NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
	data        TEXT NOT NULL,
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
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cannot create the schema: %w", err)
	}
	return &Store{db: db, now: time.Now}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// CountInstances returns the number of instances that have not expired.
func (s *Store) CountInstances(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM instances WHERE expires_at > ?`, s.now().Unix()).Scan(&n)
	return n, err
}

// CreateInstance stores a new instance.
func (s *Store) CreateInstance(ctx context.Context, in *Instance) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO instances (id, secret, kind, key_pem, cert_pem, config, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		in.ID, in.Secret, string(in.Kind), in.KeyPEM, in.CertPEM, string(in.Config), in.CreatedAt.Unix(), in.ExpiresAt.Unix())
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

// AddEvent records an event, and drops the instance's oldest events
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO events (instance_id, at, direction, title, detail, xml, ok)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, e.InstanceID, s.now().UnixMilli(), e.Direction, e.Title, e.Detail, e.XML, ok); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE instance_id = ? AND id NOT IN
		(SELECT id FROM events WHERE instance_id = ? ORDER BY id DESC LIMIT ?)`,
		e.InstanceID, e.InstanceID, MaxEventsPerInstance); err != nil {
		return err
	}
	return tx.Commit()
}

// Events returns an instance's events, newest first.
func (s *Store) Events(ctx context.Context, instanceID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, at, direction, title, detail, xml, ok FROM events
		WHERE instance_id = ? ORDER BY id DESC`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []Event
	for rows.Next() {
		e := Event{InstanceID: instanceID}
		var at int64
		var ok int
		if err := rows.Scan(&e.ID, &at, &e.Direction, &e.Title, &e.Detail, &e.XML, &ok); err != nil {
			return nil, err
		}
		e.At = time.UnixMilli(at)
		e.OK = ok != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClearEvents deletes all of an instance's events.
func (s *Store) ClearEvents(ctx context.Context, instanceID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE instance_id = ?`, instanceID)
	return err
}

// PutPending keeps data, such as an AuthnRequest waiting for the user to
// log in, under id until ttl has passed.
func (s *Store) PutPending(ctx context.Context, id, instanceID string, data any, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO pending (id, instance_id, data, expires_at) VALUES (?, ?, ?, ?)`,
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
	if _, err := s.db.ExecContext(ctx, `DELETE FROM replay WHERE expires_at <= ?`, now); err != nil {
		return n, err
	}
	return n, nil
}
