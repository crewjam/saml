package replay

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/sqlstore"
)

// Dialect is the SQL dialect of the database of a SQL record: it sets the
// placeholders of its statements and the column types of its table.
type Dialect = sqlstore.Dialect

// The dialects a SQL record supports. Each Consume runs only plain INSERT,
// SELECT and DELETE statements, which they all treat alike; only the
// placeholders and the statements of Schema differ.
const (
	PostgreSQL = sqlstore.PostgreSQL // $1 placeholders
	MySQL      = sqlstore.MySQL      // ? placeholders; MariaDB too; InnoDB tables
	SQLite     = sqlstore.SQLite     // ? placeholders
)

// DefaultTable is the table of a SQL record made with no table name.
const DefaultTable = "saml_replay"

// MaxKeyLen is the length, in bytes, of the longest key a SQL record
// keeps: that of samlsp.ReplayKey and samlidp.ReplayKey.
const MaxKeyLen = 32

// DefaultPurgeInterval is how often, at most, each SQL record removes the
// expired rows of its table, unless SQL.PurgeInterval says otherwise.
const DefaultPurgeInterval = time.Minute

// SQL records message keys in a table of a database reached through
// database/sql, which protects every process that shares the table: a
// message accepted by one is refused by the others. Use it in place of
// Memory when an SP (or an IdP) is served by several processes, since a
// login's response, or a replay of it, may reach any of them.
//
// Each key is kept, in hex, in a row whose primary key it is, so that the
// database itself makes sure that only one of the processes that record a
// key at the same time succeeds: Consume inserts the row, and if that
// fails because the key is there, the message is a replay. The expiry is
// kept as Unix time in nanoseconds. The statements are plain INSERT,
// SELECT and DELETE, each run on its own, at any isolation level; see
// Dialect for the databases that are supported, and Schema for the table.
//
// # Clocks
//
// The processes compute each expiry by their own clocks, and Consume
// compares it with Now of the process that runs it. A row is therefore
// kept, and the key refused, for ClockSkew past its expiry, so that a
// process whose clock is behind that of another still finds the record of
// a message it would accept. Keep the clocks of the processes, such as by
// NTP, closer than ClockSkew: if one runs further ahead, another may find
// the row of a message removed while it would still accept the message,
// and accept it again. That is the one replay a shared record cannot
// stop, and the reason to keep ClockSkew at least as long as the clock
// skew the providers allow (saml.MaxClockSkew by default).
//
// # Expired rows
//
// Rows are removed once ClockSkew past their expiry: by a Consume that
// finds one under its key, and by a DELETE of every such row that a
// Consume runs after it records its key, at most once a PurgeInterval per
// SQL. As with Memory, a row is inserted only for a message that has been
// fully verified, so the table holds only the messages the peers really
// issued in the last few minutes. Call Purge from a job of your own, and
// set PurgeInterval negative, to keep the DELETE away from logins.
//
// A SQL is safe for concurrent use, and may be shared by several
// samlsp.Configs and samlidp.Configs, as may its table by several
// processes. Set its fields before the first Consume.
type SQL struct {
	// Now is the time source by which rows expire; nil means time.Now. It
	// must be the clock by which the callers compute the expiries they
	// pass to Consume (see samlsp.WithClock and samlidp.WithClock): unlike
	// a Memory's, it is not set by samlsp.New or samlidp.New.
	Now func() time.Time

	// ClockSkew is how long rows are kept, and their keys refused, past
	// their expiry, to allow for the clocks of the processes that share
	// the table being apart. Zero means saml.MaxClockSkew, as it is when
	// Consume runs; a negative value means none, for a table used by one
	// process only.
	ClockSkew time.Duration

	// PurgeInterval is how often, at most, Consume removes the expired
	// rows of the table. Zero means DefaultPurgeInterval; a negative
	// value means never, for a caller that runs Purge itself.
	PurgeInterval time.Duration

	db      *sql.DB
	dialect Dialect
	table   string
	purger  sqlstore.Purger

	insertQuery, selectQuery, deleteQuery, purgeQuery string
}

// NewSQL returns a SQL record that keeps message keys in the table named
// table of db, whose dialect is dialect. An empty table means
// DefaultTable. The table must exist: create it with CreateTable, or with
// the statements of Schema.
func NewSQL(db *sql.DB, dialect Dialect, table string) (*SQL, error) {
	if db == nil {
		return nil, errors.New("replay: no database")
	}
	if err := dialect.Check(); err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
	if table == "" {
		table = DefaultTable
	}
	if err := sqlstore.CheckTable(table); err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
	s := &SQL{db: db, dialect: dialect, table: table}
	s.insertQuery = dialect.Rebind("INSERT INTO " + table + " (replay_key, expires_ns) VALUES (?, ?)")
	s.selectQuery = dialect.Rebind("SELECT expires_ns FROM " + table + " WHERE replay_key = ?")
	s.deleteQuery = dialect.Rebind("DELETE FROM " + table + " WHERE replay_key = ? AND expires_ns = ?")
	s.purgeQuery = dialect.Rebind("DELETE FROM " + table + " WHERE expires_ns < ?")
	return s, nil
}

// Schema returns the statements that create the table of a SQL record
// named table in a database of dialect, if it does not exist yet: a
// primary key on the key, and an index on the expiry for Purge. An empty
// table means DefaultTable. On MySQL the key's column is VARBINARY, so
// that it is compared byte for byte.
func Schema(dialect Dialect, table string) ([]string, error) {
	if err := dialect.Check(); err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
	if table == "" {
		table = DefaultTable
	}
	if err := sqlstore.CheckTable(table); err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
	switch dialect {
	case MySQL:
		return []string{"CREATE TABLE IF NOT EXISTS " + table + " (" +
			"replay_key VARBINARY(64) NOT NULL PRIMARY KEY, " +
			"expires_ns BIGINT NOT NULL, " +
			"INDEX (expires_ns)" +
			") ENGINE=InnoDB"}, nil
	case SQLite:
		return []string{
			"CREATE TABLE IF NOT EXISTS " + table + " (" +
				"replay_key TEXT NOT NULL PRIMARY KEY, " +
				"expires_ns INTEGER NOT NULL)",
			sqlstore.CreateIndex(dialect, table, "expires_ns"),
		}, nil
	default: // PostgreSQL
		return []string{
			"CREATE TABLE IF NOT EXISTS " + table + " (" +
				"replay_key VARCHAR(64) NOT NULL PRIMARY KEY, " +
				"expires_ns BIGINT NOT NULL)",
			sqlstore.CreateIndex(dialect, table, "expires_ns"),
		}, nil
	}
}

// CreateTable creates the table of s, with the statements of Schema, if
// it does not exist yet.
func (s *SQL) CreateTable(ctx context.Context) error {
	stmts, err := Schema(s.dialect, s.table)
	if err != nil {
		return err
	}
	for _, q := range stmts {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("replay: cannot create the table %s: %w", s.table, err)
		}
	}
	return nil
}

func (s *SQL) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *SQL) clockSkew() time.Duration {
	switch {
	case s.ClockSkew < 0:
		return 0
	case s.ClockSkew == 0:
		return saml.MaxClockSkew
	}
	return s.ClockSkew
}

func (s *SQL) purgeInterval() time.Duration {
	if s.PurgeInterval == 0 {
		return DefaultPurgeInterval
	}
	return s.PurgeInterval
}

// consumeAttempts bounds how often Consume tries to insert its row: each
// time after the first follows the removal of an expired row under the
// key, or the disappearance of the row that made the insert fail.
const consumeAttempts = 3

// Consume records the message identified by key as accepted until
// expiresAt. It returns saml.ErrAssertionReplayed if key is recorded and
// has not expired, ClockSkew allowed. It implements samlsp.ReplayState
// and samlidp.ReplayState; the statements run with ctx.
//
// key must be at most MaxKeyLen bytes long. As with Memory, a message
// whose expiry is already past by Now is not recorded at all: package
// saml refuses it anyway.
//
// Any error but saml.ErrAssertionReplayed means the database could not
// tell whether the message was recorded, and refuses the message too. If
// the insert fails for some reason other than the key being there, and
// the key is not there either, Consume returns the insert's error.
func (s *SQL) Consume(ctx context.Context, key []byte, expiresAt time.Time) error {
	if len(key) > MaxKeyLen {
		return fmt.Errorf("replay: a key of %d bytes is longer than %d", len(key), MaxKeyLen)
	}
	now := s.now()
	if !now.Before(expiresAt) {
		return nil
	}
	k := hex.EncodeToString(key)
	var insertErr error
	for range consumeAttempts {
		_, insertErr = s.db.ExecContext(ctx, s.insertQuery, k, expiresAt.UnixNano())
		if insertErr == nil {
			s.purgeIfDue(ctx, now)
			return nil
		}
		// The insert failed: most likely because the key is there, which a
		// SELECT tells apart from other failures without depending on the
		// error codes of each driver.
		var exp int64
		err := s.db.QueryRowContext(ctx, s.selectQuery, k).Scan(&exp)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// Not there (any more): it was removed in the meantime, or the
			// insert failed for another reason. Try again.
			continue
		case err != nil:
			return fmt.Errorf("replay: cannot record the message: %w", errors.Join(insertErr, err))
		}
		if !now.After(time.Unix(0, exp).Add(s.clockSkew())) {
			return saml.ErrAssertionReplayed
		}
		// An expired row under the key. Remove it, unless another process
		// has replaced it in the meantime, and try again.
		if _, err := s.db.ExecContext(ctx, s.deleteQuery, k, exp); err != nil {
			return fmt.Errorf("replay: cannot remove an expired record: %w", err)
		}
	}
	return fmt.Errorf("replay: cannot record the message: %w", insertErr)
}

// purgeIfDue runs Purge if PurgeInterval has passed since it last did.
// Its error is dropped: the rows it would remove do no harm, and the next
// Purge removes them.
func (s *SQL) purgeIfDue(ctx context.Context, now time.Time) {
	if s.purger.Due(s.purgeInterval()) {
		_, _ = s.purge(ctx, now)
	}
}

// Purge removes the rows of the table that expired more than ClockSkew
// ago by Now, and returns how many it removed.
func (s *SQL) Purge(ctx context.Context) (int64, error) {
	return s.purge(ctx, s.now())
}

func (s *SQL) purge(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, s.purgeQuery, now.Add(-s.clockSkew()).UnixNano())
	if err != nil {
		return 0, fmt.Errorf("replay: cannot remove the expired records: %w", err)
	}
	// The rows are removed even if a driver cannot count them.
	n, _ := res.RowsAffected()
	return n, nil
}
