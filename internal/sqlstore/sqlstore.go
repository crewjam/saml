// Package sqlstore holds what the database/sql stores of
// github.com/crewjam/saml/x/samlsp/replay and
// github.com/crewjam/saml/x/samlsp/artifact share: the SQL dialects they
// support, the check of a table name, and the schedule on which they
// remove expired rows.
package sqlstore

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialect is a SQL dialect: it sets the placeholders of the statements a
// store runs, and the column types of the table it creates.
type Dialect int

// The supported dialects. Every statement a store runs is a plain INSERT,
// SELECT or DELETE that each of them treats alike; only the placeholders
// and the CREATE TABLE statements differ.
const (
	// PostgreSQL uses $1, $2, ... placeholders.
	PostgreSQL Dialect = iota + 1
	// MySQL (and MariaDB) use ? placeholders. The tables use InnoDB, so
	// that a DELETE of a row that another transaction has just deleted
	// waits for it and then affects no row.
	MySQL
	// SQLite uses ? placeholders.
	SQLite
)

func (d Dialect) String() string {
	switch d {
	case PostgreSQL:
		return "PostgreSQL"
	case MySQL:
		return "MySQL"
	case SQLite:
		return "SQLite"
	}
	return "Dialect(" + strconv.Itoa(int(d)) + ")"
}

// Check returns an error if d is not one of the supported dialects.
func (d Dialect) Check() error {
	switch d {
	case PostgreSQL, MySQL, SQLite:
		return nil
	}
	return fmt.Errorf("unsupported SQL dialect %s", d)
}

// Rebind returns q with each ? replaced by the placeholder of d: $1, $2,
// ... for PostgreSQL. q must have no ? other than placeholders.
func (d Dialect) Rebind(q string) string {
	if d != PostgreSQL {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// CheckTable returns an error unless name is a table name that is safe to
// put in a statement as it is: an identifier of ASCII letters, digits and
// underscores that does not start with a digit, optionally qualified by a
// schema (or database) name of the same form and a dot.
func CheckTable(name string) error {
	parts := strings.Split(name, ".")
	if len(parts) > 2 {
		return fmt.Errorf("the table name %q has more than one dot", name)
	}
	for _, p := range parts {
		if !isIdentifier(p) {
			return fmt.Errorf("the table name %q is not of ASCII letters, digits and underscores, starting with a letter or underscore", name)
		}
	}
	return nil
}

func isIdentifier(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_', 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z':
		case '0' <= r && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// CreateIndex returns the statement that creates an index on the column
// col of table, if there is none yet, for PostgreSQL or SQLite. The index
// is named after the table and the column. MySQL has no CREATE INDEX IF
// NOT EXISTS: declare the index in its CREATE TABLE instead.
func CreateIndex(d Dialect, table, col string) string {
	schema, name := "", table
	if i := strings.IndexByte(table, '.'); i >= 0 {
		schema, name = table[:i+1], table[i+1:]
	}
	index := name + "_" + col
	if d == SQLite {
		// SQLite qualifies the index, and takes the table in its schema.
		return "CREATE INDEX IF NOT EXISTS " + schema + index + " ON " + name + " (" + col + ")"
	}
	// PostgreSQL puts the index in the schema of the table.
	return "CREATE INDEX IF NOT EXISTS " + index + " ON " + table + " (" + col + ")"
}

// Purger says when a store should next remove its expired rows: at most
// once an interval, by the monotonic system clock, whatever the store's
// Now says. The zero value is ready to use, and is due at once.
type Purger struct {
	mu   sync.Mutex
	next time.Time
}

// Due reports whether the rows should be removed now, and if so counts
// the interval from now. An interval that is not positive is never due.
func (p *Purger) Due(interval time.Duration) bool {
	if interval <= 0 {
		return false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.Before(p.next) {
		return false
	}
	p.next = now.Add(interval)
	return true
}
