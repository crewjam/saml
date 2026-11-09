package sqlfake

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/crewjam/saml/internal/sqlstore"
)

// Environment variables that name a real database for FromEnv.
const (
	EnvDriver  = "SAML_TEST_SQL_DRIVER"  // a database/sql driver name, such as "pgx"
	EnvDSN     = "SAML_TEST_SQL_DSN"     // its data source name
	EnvDialect = "SAML_TEST_SQL_DIALECT" // postgresql, mysql or sqlite
)

// FromEnv opens the real database that EnvDriver, EnvDSN and EnvDialect
// name, and closes it when t ends. It skips t unless all three are set
// and the driver is registered: this module depends on no driver, so a
// test binary has one only if a file of the test imports it, such as a
// file a developer adds locally and does not commit:
//
//	package replay_test
//
//	import _ "github.com/jackc/pgx/v5/stdlib"
func FromEnv(t testing.TB) (*sql.DB, sqlstore.Dialect) {
	t.Helper()
	name, dsn, dialectName := os.Getenv(EnvDriver), os.Getenv(EnvDSN), os.Getenv(EnvDialect)
	if name == "" || dsn == "" || dialectName == "" {
		t.Skipf("set %s, %s and %s to test against a real database", EnvDriver, EnvDSN, EnvDialect)
	}
	if !slices.Contains(sql.Drivers(), name) {
		t.Skipf("the SQL driver %q is not registered in this test binary", name)
	}
	var dialect sqlstore.Dialect
	switch strings.ToLower(dialectName) {
	case "postgresql", "postgres":
		dialect = sqlstore.PostgreSQL
	case "mysql", "mariadb":
		dialect = sqlstore.MySQL
	case "sqlite":
		dialect = sqlstore.SQLite
	default:
		t.Fatalf("%s=%q is not postgresql, mysql or sqlite", EnvDialect, dialectName)
	}
	db, err := sql.Open(name, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	return db, dialect
}

// TempTable returns a table name for a test that is unlikely to be in
// use, and drops the table of that name from db when t ends.
func TempTable(t testing.TB, db *sql.DB, prefix string) string {
	t.Helper()
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := prefix + "_" + hex.EncodeToString(b[:])
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+name) })
	return name
}
