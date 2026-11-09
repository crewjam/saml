package replay_test

import (
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/sqlstore/sqlfake"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/replay"
)

var (
	_ samlsp.ReplayState  = (*replay.SQL)(nil)
	_ samlidp.ReplayState = (*replay.SQL)(nil)
)

var dialects = []replay.Dialect{replay.PostgreSQL, replay.MySQL, replay.SQLite}

// testClock is a clock that a test moves by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestSQL runs testSQL on the fake database in each dialect, which also
// checks the placeholders of each.
func TestSQL(t *testing.T) {
	for _, d := range dialects {
		t.Run(d.String(), func(t *testing.T) {
			fake := sqlfake.New(d)
			testSQL(t, fake.SQL(), d, "", func() int { return fake.Rows(replay.DefaultTable) })
		})
	}
}

// TestSQLRealDatabase runs testSQL on the real database that the
// SAML_TEST_SQL_* environment variables name, if any (see
// sqlfake.FromEnv).
func TestSQLRealDatabase(t *testing.T) {
	db, d := sqlfake.FromEnv(t)
	table := sqlfake.TempTable(t, db, "saml_replay_test")
	testSQL(t, db, d, table, func() int {
		var n int
		if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	})
}

// testSQL checks a SQL record in db: that it refuses a key recorded by
// another process sharing the table, that its rows expire by Now with
// ClockSkew allowed, that it removes expired rows, and that of the
// processes that record a key at the same time only one succeeds.
func testSQL(t *testing.T, db *sql.DB, d replay.Dialect, table string, rows func() int) {
	clock := newTestClock()
	newSQL := func() *replay.SQL {
		t.Helper()
		s, err := replay.NewSQL(db, d, table)
		if err != nil {
			t.Fatal(err)
		}
		s.Now = clock.now
		s.ClockSkew = time.Minute
		return s
	}
	consume := func(s *replay.SQL, key []byte, lifetime time.Duration) error {
		t.Helper()
		return s.Consume(t.Context(), key, clock.now().Add(lifetime))
	}
	// Two processes sharing the table.
	s1, s2 := newSQL(), newSQL()
	for range 2 { // CreateTable may run again
		if err := s1.CreateTable(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	a := samlsp.ReplayKey("https://idp.example.com", "id-a")
	if err := consume(s1, a, 90*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := consume(s2, a, 90*time.Second); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replay on another process: err = %v", err)
	}
	if err := consume(s1, a, 90*time.Second); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replay on the same process: err = %v", err)
	}
	// Already expired: not recorded.
	if err := consume(s1, samlsp.ReplayKey("https://idp.example.com", "id-old"), 0); err != nil {
		t.Fatal(err)
	}
	if n := rows(); n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}

	// The record is kept for ClockSkew past its expiry, inclusive...
	clock.add(90*time.Second + time.Minute)
	if err := s2.Consume(t.Context(), a, clock.now()); err != nil {
		t.Fatalf("an expiry already past is not recorded, so not refused: %v", err)
	}
	if err := consume(s2, a, time.Second); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replay within ClockSkew of the expiry: err = %v", err)
	}
	// ... and then replaced.
	clock.add(time.Nanosecond)
	if err := consume(s2, a, 90*time.Second); err != nil {
		t.Fatalf("expired record: %v", err)
	}
	if err := consume(s1, a, 90*time.Second); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replay of the replaced record: err = %v", err)
	}
	if n := rows(); n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}

	// Purge removes the rows ClockSkew past their expiry.
	b := samlsp.ReplayKey("https://idp.example.com", "id-b")
	if err := consume(s1, b, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	clock.add(90*time.Second + time.Minute + time.Nanosecond)
	if n, err := s1.Purge(t.Context()); err != nil || n != 1 {
		t.Fatalf("Purge removed %d rows (%v), want 1", n, err)
	}
	if n := rows(); n != 1 {
		t.Fatalf("%d rows after Purge, want 1", n)
	}

	// A process's first Consume removes the expired rows too, and the
	// next only after PurgeInterval.
	clock.add(time.Hour)
	s3 := newSQL()
	if err := consume(s3, samlsp.ReplayKey("https://idp.example.com", "id-c"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := rows(); n != 1 {
		t.Fatalf("%d rows after the first Consume of a process, want 1", n)
	}
	clock.add(time.Hour)
	if err := consume(s3, samlsp.ReplayKey("https://idp.example.com", "id-d"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if n := rows(); n != 2 {
		t.Fatalf("%d rows after the second Consume of a process, want 2", n)
	}

	// Of the processes that record a key at the same time, one succeeds.
	for i := range 20 {
		key := samlsp.ReplayKey("https://idp.example.com", "race-"+string(rune('a'+i)))
		var (
			wg               sync.WaitGroup
			mu               sync.Mutex
			accepted, refuse int
		)
		for j := range 16 {
			s := s1
			if j%2 == 1 {
				s = s2
			}
			wg.Go(func() {
				err := s.Consume(t.Context(), key, clock.now().Add(time.Minute))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					accepted++
				case errors.Is(err, saml.ErrAssertionReplayed):
					refuse++
				default:
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if accepted != 1 || refuse != 15 {
			t.Fatalf("race %d: %d accepted, %d refused; want 1, 15", i, accepted, refuse)
		}
	}
}

// TestSQLReplacedConcurrently checks that a process that finds an expired
// row does not remove the row that another process has put in its place
// in the meantime.
func TestSQLReplacedConcurrently(t *testing.T) {
	fake := sqlfake.New(replay.SQLite)
	db := fake.SQL()
	clock := newTestClock()
	s, err := replay.NewSQL(db, replay.SQLite, "")
	if err != nil {
		t.Fatal(err)
	}
	s.Now, s.ClockSkew = clock.now, -1
	if err := s.CreateTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	key := []byte("k")
	if err := s.Consume(t.Context(), key, clock.now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	clock.add(time.Minute)
	// Between this Consume's SELECT of the expired row and its DELETE,
	// another process replaces the row with one that has not expired.
	fake.SetHook(func(q string) {
		if strings.HasPrefix(q, "DELETE") && strings.Contains(q, "replay_key") {
			fake.SetHook(nil)
			if err := fake.Set(replay.DefaultTable, "expires_ns", clock.now().Add(time.Hour).UnixNano()); err != nil {
				t.Error(err)
			}
		}
	})
	if err := s.Consume(t.Context(), key, clock.now().Add(time.Minute)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("err = %v, want a replay of the replacing record", err)
	}
	if n := fake.Rows(replay.DefaultTable); n != 1 {
		t.Fatalf("%d rows, want the replacing one", n)
	}
}

func TestSQLErrors(t *testing.T) {
	fake := sqlfake.New(replay.PostgreSQL)
	db := fake.SQL()
	if _, err := replay.NewSQL(nil, replay.PostgreSQL, ""); err == nil {
		t.Error("NewSQL accepted no database")
	}
	if _, err := replay.NewSQL(db, replay.Dialect(0), ""); err == nil {
		t.Error("NewSQL accepted an unknown dialect")
	}
	for _, table := range []string{"a-b", "1abc", "a.b.c", "x; DROP TABLE y", "a.", strings.Repeat("a", 64)} {
		if _, err := replay.NewSQL(db, replay.PostgreSQL, table); err == nil {
			t.Errorf("NewSQL accepted the table %q", table)
		}
	}

	s, err := replay.NewSQL(db, replay.PostgreSQL, "")
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	// No table: the insert fails, and the key is not found, so the error
	// is that of the insert, not a replay.
	if err := s.Consume(t.Context(), []byte("k"), future); err == nil || errors.Is(err, saml.ErrAssertionReplayed) {
		t.Errorf("Consume without a table: err = %v", err)
	}
	if err := s.CreateTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(t.Context(), make([]byte, replay.MaxKeyLen+1), future); err == nil {
		t.Error("Consume accepted a key longer than MaxKeyLen")
	}
	if err := s.Consume(t.Context(), make([]byte, replay.MaxKeyLen), future); err != nil {
		t.Error(err)
	}
}

func TestSchema(t *testing.T) {
	for _, d := range dialects {
		stmts, err := replay.Schema(d, "")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stmts[0], "CREATE TABLE IF NOT EXISTS saml_replay (") {
			t.Errorf("%s: %q", d, stmts[0])
		}
	}
	// An index goes in the schema of its table.
	for d, want := range map[replay.Dialect]string{
		replay.PostgreSQL: "CREATE INDEX IF NOT EXISTS r_expires_ns ON app.r (expires_ns)",
		replay.SQLite:     "CREATE INDEX IF NOT EXISTS app.r_expires_ns ON r (expires_ns)",
	} {
		stmts, err := replay.Schema(d, "app.r")
		if err != nil {
			t.Fatal(err)
		}
		if got := stmts[len(stmts)-1]; got != want {
			t.Errorf("%s: %q, want %q", d, got, want)
		}
	}
	if stmts, _ := replay.Schema(replay.MySQL, "app.r"); len(stmts) != 1 || !strings.Contains(stmts[0], "INDEX (expires_ns)") {
		t.Errorf("MySQL: %q", stmts)
	}
	if _, err := replay.Schema(replay.Dialect(9), ""); err == nil {
		t.Error("Schema accepted an unknown dialect")
	}
}
