package artifact

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/sqlstore"
)

// Dialect is the SQL dialect of the database of a SQLStore: it sets the
// placeholders of its statements and the column types of its table.
type Dialect = sqlstore.Dialect

// The dialects a SQLStore supports. Save and Take run only plain INSERT,
// SELECT and DELETE statements, which they all treat alike; only the
// placeholders and the statements of SQLSchema differ.
const (
	PostgreSQL = sqlstore.PostgreSQL // $1 placeholders
	MySQL      = sqlstore.MySQL      // ? placeholders; MariaDB too; InnoDB tables
	SQLite     = sqlstore.SQLite     // ? placeholders
)

// DefaultSQLTable is the table of a SQLStore made with no table name.
const DefaultSQLTable = "saml_artifact"

// DefaultMaxMessageSize is the size, in bytes, of the largest message a
// SQLStore keeps, unless SQLStore.MaxMessageSize says otherwise.
const DefaultMaxMessageSize = 1 << 20

// DefaultPurgeInterval is how often, at most, a SQLStore removes the
// expired messages of its table, unless SQLStore.PurgeInterval says
// otherwise.
const DefaultPurgeInterval = time.Minute

// The longest artifact and recipient a SQLStore keeps: the sizes of their
// columns. A type 0x0004 artifact is 60 characters long, and saml-core
// §8.3.6 limits entity IDs to 1024 characters.
const (
	maxSQLArtifactLen  = 255
	maxSQLRecipientLen = 1024
)

// ErrMessageTooLarge is the error of SQLStore.Save for a message larger
// than its MaxMessageSize. The Binding's Encode returns it as it is.
var ErrMessageTooLarge = errors.New("artifact: the message is too large to store")

// SQLStore is a Store in a table of a database reached through
// database/sql, which the processes that serve a Binding can share: the
// IdP's ArtifactResolve may reach any of them, not only the one that saved
// the message. It suits github.com/crewjam/saml/x/samlidp/idpartifact
// too, whose Store is this package's.
//
// Take gives each message out at most once, however many processes take
// it at the same time: it reads the row of the artifact and recipient,
// and then deletes it by the random token that Save gave it; only the
// Take whose DELETE affects the row returns the message. A database
// deletes a row once, so the others' DELETEs affect none, at any
// isolation level. A Take for another recipient finds no row, and so
// neither deletes the message nor learns of it, as with MemoryStore. The
// statements are plain INSERT, SELECT and DELETE, each run on its own;
// see Dialect for the databases that are supported, and SQLSchema for the
// table.
//
// Save replaces a message kept under the same artifact, as MemoryStore
// does, by a DELETE and then an INSERT. Two Saves under one artifact at
// the same time may make one of them fail; a Binding saves a message
// under the same artifact only to keep it again after the IdP failed to
// get it.
//
// # Expired messages
//
// Take may return a message whose ExpiresAt has passed, which the Binding
// refuses. Messages are removed once ClockSkew past their ExpiresAt, by a
// DELETE that a Save runs after it inserts its message, at most once a
// PurgeInterval per SQLStore; call Purge from a job of your own, and set
// PurgeInterval negative, to keep it away from logins. The ExpiresAt is
// kept as Unix time in nanoseconds.
//
// The processes set the ExpiresAt of a message by their own clocks, and
// the one that resolves the artifact compares it with its own: keep their
// clocks closer than ClockSkew, such as by NTP, so that no process
// removes a message that another would still give out. A clock that runs
// behind gives a message out a little after it expired by the clock of
// the process that saved it, by at most the difference.
//
// Anyone who can start a login can make a Binding save a message. Unlike
// MemoryStore, a SQLStore does not bound the number of rows: a message
// lives for the Binding's lifetime only, so the table holds about the
// rate of logins times that lifetime, but a flood of logins makes it
// grow with the flood. Limit the rate at which each client may start
// logins with the artifact binding, as the MemoryStore documentation
// explains. MaxMessageSize bounds each row.
//
// A SQLStore is safe for concurrent use. Set its fields before the first
// Save.
type SQLStore struct {
	// Now is the time source by which messages expire; nil means
	// time.Now. It must be the time source by which ExpiresAt is set (see
	// samlsp.WithClock and samlidp.WithClock): unlike a MemoryStore's, it
	// is not set by New.
	Now func() time.Time

	// ClockSkew is how long messages are kept past their ExpiresAt before
	// they are removed, to allow for the clocks of the processes that
	// share the table being apart. Zero means saml.MaxClockSkew, as it is
	// when the messages are removed; a negative value means none.
	ClockSkew time.Duration

	// PurgeInterval is how often, at most, Save removes the expired
	// messages of the table. Zero means DefaultPurgeInterval; a negative
	// value means never, for a caller that runs Purge itself.
	PurgeInterval time.Duration

	// MaxMessageSize is the size, in bytes, of the largest message Save
	// keeps; it returns ErrMessageTooLarge for a larger one. Zero means
	// DefaultMaxMessageSize. The message column of the MySQL table is a
	// MEDIUMBLOB, which keeps at most 16 MiB.
	MaxMessageSize int

	db      *sql.DB
	dialect Dialect
	table   string
	purger  sqlstore.Purger

	deleteArtifactQuery, insertQuery, selectQuery, deleteTokenQuery, purgeQuery string
}

var _ Store = (*SQLStore)(nil)

// NewSQLStore returns a SQLStore that keeps messages in the table named
// table of db, whose dialect is dialect. An empty table means
// DefaultSQLTable. The table must exist: create it with CreateTable, or
// with the statements of SQLSchema.
func NewSQLStore(db *sql.DB, dialect Dialect, table string) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("artifact: no database")
	}
	table, err := sqlTable(dialect, table)
	if err != nil {
		return nil, err
	}
	s := &SQLStore{db: db, dialect: dialect, table: table}
	s.deleteArtifactQuery = dialect.Rebind("DELETE FROM " + table + " WHERE artifact = ?")
	s.insertQuery = dialect.Rebind("INSERT INTO " + table + " (artifact, recipient, message, expires_ns, token) VALUES (?, ?, ?, ?, ?)")
	s.selectQuery = dialect.Rebind("SELECT message, expires_ns, token FROM " + table + " WHERE artifact = ? AND recipient = ?")
	s.deleteTokenQuery = dialect.Rebind("DELETE FROM " + table + " WHERE artifact = ? AND token = ?")
	s.purgeQuery = dialect.Rebind("DELETE FROM " + table + " WHERE expires_ns < ?")
	return s, nil
}

func sqlTable(dialect Dialect, table string) (string, error) {
	if err := dialect.Check(); err != nil {
		return "", fmt.Errorf("artifact: %w", err)
	}
	if table == "" {
		table = DefaultSQLTable
	}
	if err := sqlstore.CheckTable(table); err != nil {
		return "", fmt.Errorf("artifact: %w", err)
	}
	return table, nil
}

// SQLSchema returns the statements that create the table of a SQLStore
// named table in a database of dialect, if it does not exist yet: a
// primary key on the artifact, and an index on the expiry for Purge. An
// empty table means DefaultSQLTable. On MySQL the artifact and recipient
// columns are VARBINARY, so that they are compared byte for byte, not by
// a case-insensitive collation.
func SQLSchema(dialect Dialect, table string) ([]string, error) {
	table, err := sqlTable(dialect, table)
	if err != nil {
		return nil, err
	}
	switch dialect {
	case MySQL:
		return []string{"CREATE TABLE IF NOT EXISTS " + table + " (" +
			"artifact VARBINARY(255) NOT NULL PRIMARY KEY, " +
			"recipient VARBINARY(1024) NOT NULL, " +
			"message MEDIUMBLOB NOT NULL, " +
			"expires_ns BIGINT NOT NULL, " +
			"token VARBINARY(32) NOT NULL, " +
			"INDEX (expires_ns)" +
			") ENGINE=InnoDB"}, nil
	case SQLite:
		return []string{
			"CREATE TABLE IF NOT EXISTS " + table + " (" +
				"artifact TEXT NOT NULL PRIMARY KEY, " +
				"recipient TEXT NOT NULL, " +
				"message BLOB NOT NULL, " +
				"expires_ns INTEGER NOT NULL, " +
				"token TEXT NOT NULL)",
			sqlstore.CreateIndex(dialect, table, "expires_ns"),
		}, nil
	default: // PostgreSQL
		return []string{
			"CREATE TABLE IF NOT EXISTS " + table + " (" +
				"artifact VARCHAR(255) NOT NULL PRIMARY KEY, " +
				"recipient VARCHAR(1024) NOT NULL, " +
				"message BYTEA NOT NULL, " +
				"expires_ns BIGINT NOT NULL, " +
				"token VARCHAR(32) NOT NULL)",
			sqlstore.CreateIndex(dialect, table, "expires_ns"),
		}, nil
	}
}

// CreateTable creates the table of s, with the statements of SQLSchema,
// if it does not exist yet.
func (s *SQLStore) CreateTable(ctx context.Context) error {
	stmts, err := SQLSchema(s.dialect, s.table)
	if err != nil {
		return err
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("artifact: cannot create the table %s: %w", s.table, err)
		}
	}
	return nil
}

func (s *SQLStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SQLStore) clockSkew() time.Duration {
	switch {
	case s.ClockSkew < 0:
		return 0
	case s.ClockSkew == 0:
		return saml.MaxClockSkew
	}
	return s.ClockSkew
}

// Save implements Store. It returns ErrMessageTooLarge for a message
// larger than MaxMessageSize, and an error for an artifact longer than
// 255 bytes or a recipient longer than 1024.
func (s *SQLStore) Save(ctx context.Context, artifact string, m StoredMessage) error {
	maxSize := s.MaxMessageSize
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	switch {
	case len(m.XML) > maxSize:
		return ErrMessageTooLarge
	case len(artifact) > maxSQLArtifactLen:
		return fmt.Errorf("artifact: an artifact of %d bytes is too long to store", len(artifact))
	case len(m.Recipient) > maxSQLRecipientLen:
		return fmt.Errorf("artifact: a recipient of %d bytes is too long to store", len(m.Recipient))
	}
	var t [16]byte
	if _, err := rand.Read(t[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(t[:])
	if _, err := s.db.ExecContext(ctx, s.deleteArtifactQuery, artifact); err != nil { //nolint:gosec // G701: the statement is built at NewSQLStore from a table name CheckTable allows; values are parameters
		return fmt.Errorf("artifact: cannot save the message: %w", err)
	}
	msg := m.XML
	if msg == nil {
		msg = []byte{} // the column is NOT NULL
	}
	if _, err := s.db.ExecContext(ctx, s.insertQuery, artifact, m.Recipient, msg, m.ExpiresAt.UnixNano(), token); err != nil { //nolint:gosec // G701: the statement is built at NewSQLStore from a table name CheckTable allows; values are parameters
		return fmt.Errorf("artifact: cannot save the message: %w", err)
	}
	interval := s.PurgeInterval
	if interval == 0 {
		interval = DefaultPurgeInterval
	}
	if s.purger.Due(interval) {
		// The error is dropped: the expired messages do no harm, and the
		// next Purge removes them.
		_, _ = s.Purge(ctx)
	}
	return nil
}

// Take implements Store.
func (s *SQLStore) Take(ctx context.Context, artifact, recipient string) (*StoredMessage, error) {
	if len(artifact) > maxSQLArtifactLen || len(recipient) > maxSQLRecipientLen {
		return nil, nil // Save keeps no such message
	}
	var (
		msg   []byte
		ns    int64
		token string
	)
	err := s.db.QueryRowContext(ctx, s.selectQuery, artifact, recipient).Scan(&msg, &ns, &token) //nolint:gosec // G701: the statement is built at NewSQLStore from a table name CheckTable allows; values are parameters
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("artifact: cannot read the message: %w", err)
	}
	// Only the Take whose DELETE removes the row gives the message out.
	res, err := s.db.ExecContext(ctx, s.deleteTokenQuery, artifact, token)
	if err != nil {
		return nil, fmt.Errorf("artifact: cannot take the message: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("artifact: cannot tell whether the message was taken: %w", err)
	}
	if n != 1 {
		return nil, nil // another Take got it first
	}
	return &StoredMessage{XML: msg, Recipient: recipient, ExpiresAt: time.Unix(0, ns)}, nil
}

// Purge removes the messages that expired more than ClockSkew ago by Now,
// and returns how many it removed.
func (s *SQLStore) Purge(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.purgeQuery, s.now().Add(-s.clockSkew()).UnixNano())
	if err != nil {
		return 0, fmt.Errorf("artifact: cannot remove the expired messages: %w", err)
	}
	// The rows are removed even if a driver cannot count them.
	n, _ := res.RowsAffected()
	return n, nil
}
