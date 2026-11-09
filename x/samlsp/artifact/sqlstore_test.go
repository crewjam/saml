package artifact_test

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml/internal/sqlstore/sqlfake"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/artifact"
)

var sqlDialects = []artifact.Dialect{artifact.PostgreSQL, artifact.MySQL, artifact.SQLite}

// TestSQLStore runs testSQLStore on the fake database in each dialect,
// which also checks the placeholders of each.
func TestSQLStore(t *testing.T) {
	for _, d := range sqlDialects {
		t.Run(d.String(), func(t *testing.T) {
			fake := sqlfake.New(d)
			testSQLStore(t, fake.SQL(), d, "", func() int { return fake.Rows(artifact.DefaultSQLTable) })
		})
	}
}

// TestSQLStoreRealDatabase runs testSQLStore on the real database that
// the SAML_TEST_SQL_* environment variables name, if any (see
// sqlfake.FromEnv).
func TestSQLStoreRealDatabase(t *testing.T) {
	db, d := sqlfake.FromEnv(t)
	table := sqlfake.TempTable(t, db, "saml_artifact_test")
	testSQLStore(t, db, d, table, func() int {
		var n int
		if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	})
}

func newSQLStore(t *testing.T, db *sql.DB, d artifact.Dialect, table string) *artifact.SQLStore {
	t.Helper()
	s, err := artifact.NewSQLStore(db, d, table)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// testSQLStore checks a SQLStore in db with the semantics of MemoryStore:
// a message is given out once, to its recipient only, by any process that
// shares the table, and only one of the processes that take it at the
// same time gets it.
func testSQLStore(t *testing.T, db *sql.DB, d artifact.Dialect, table string, rows func() int) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Two processes sharing the table.
	s1, s2 := newSQLStore(t, db, d, table), newSQLStore(t, db, d, table)
	for _, s := range []*artifact.SQLStore{s1, s2} {
		s.Now = func() time.Time { return now }
		s.ClockSkew = time.Minute
	}
	for range 2 { // CreateTable may run again
		if err := s1.CreateTable(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	ctx := t.Context()
	m := artifact.StoredMessage{XML: []byte("<samlp:AuthnRequest/>"), Recipient: "https://idp.example.com", ExpiresAt: now.Add(time.Minute)}
	if err := s1.Save(ctx, "art-1", m); err != nil {
		t.Fatal(err)
	}

	// Another recipient gets nothing, and does not make the message
	// unusable.
	if got, err := s2.Take(ctx, "art-1", "https://evil.example.com"); err != nil || got != nil {
		t.Fatalf("Take for another recipient: %v, %v", got, err)
	}
	if got, err := s2.Take(ctx, "ART-1", "https://idp.example.com"); err != nil || got != nil {
		t.Fatalf("Take of another artifact: %v, %v", got, err)
	}
	got, err := s2.Take(ctx, "art-1", "https://idp.example.com")
	if err != nil || got == nil {
		t.Fatalf("Take by another process: %v, %v", got, err)
	}
	if !bytes.Equal(got.XML, m.XML) || got.Recipient != m.Recipient || !got.ExpiresAt.Equal(m.ExpiresAt) {
		t.Errorf("Take = %+v, want %+v", got, m)
	}
	// Once.
	if got, err := s1.Take(ctx, "art-1", "https://idp.example.com"); err != nil || got != nil {
		t.Fatalf("second Take: %v, %v", got, err)
	}

	// Save replaces the message under the same artifact.
	if err := s1.Save(ctx, "art-2", m); err != nil {
		t.Fatal(err)
	}
	m2 := m
	m2.XML = []byte("<samlp:LogoutRequest/>")
	if err := s2.Save(ctx, "art-2", m2); err != nil {
		t.Fatal(err)
	}
	if got, err := s1.Take(ctx, "art-2", m.Recipient); err != nil || got == nil || !bytes.Equal(got.XML, m2.XML) {
		t.Fatalf("Take after Save again: %v, %v", got, err)
	}

	testSQLStoreExpiry(t, db, d, table, rows, s1, s2, m, &now)
	testSQLStoreRace(t, s1, s2, m)
}

// testSQLStoreExpiry checks that expired messages are removed, ClockSkew
// past their expiry, by Purge and by the first Save of a process. now is
// the clock of s1 and s2.
func testSQLStoreExpiry(t *testing.T, db *sql.DB, d artifact.Dialect, table string, rows func() int, s1, s2 *artifact.SQLStore, m artifact.StoredMessage, now *time.Time) {
	ctx := t.Context()
	// An expired message may still be taken; the Binding refuses it.
	// Purge removes those ClockSkew past their expiry.
	if err := s1.Save(ctx, "art-3", m); err != nil {
		t.Fatal(err)
	}
	if err := s1.Save(ctx, "art-4", artifact.StoredMessage{Recipient: m.Recipient, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	if got, err := s1.Take(ctx, "art-3", m.Recipient); err != nil || got == nil {
		t.Fatalf("Take of an expired message: %v, %v", got, err)
	}
	if err := s1.Save(ctx, "art-3", m); err != nil {
		t.Fatal(err)
	}
	if n, err := s1.Purge(ctx); err != nil || n != 0 {
		t.Fatalf("Purge within ClockSkew removed %d (%v), want 0", n, err)
	}
	*now = now.Add(time.Nanosecond)
	if n, err := s1.Purge(ctx); err != nil || n != 1 {
		t.Fatalf("Purge removed %d (%v), want 1", n, err)
	}
	if got, err := s2.Take(ctx, "art-4", m.Recipient); err != nil || got == nil || len(got.XML) != 0 {
		t.Fatalf("Take of an empty message: %v, %v", got, err)
	}
	if n := rows(); n != 0 {
		t.Fatalf("%d rows, want 0", n)
	}

	// A process's first Save removes the expired messages too.
	if err := s1.Save(ctx, "art-5", m); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Hour)
	s3 := newSQLStore(t, db, d, table)
	s3.Now = func() time.Time { return *now }
	if err := s3.Save(ctx, "art-6", artifact.StoredMessage{Recipient: m.Recipient, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if n := rows(); n != 1 {
		t.Fatalf("%d rows after the first Save of a process, want 1", n)
	}

}

// testSQLStoreRace checks that, of the processes that take a message at
// the same time, one gets it.
func testSQLStoreRace(t *testing.T, s1, s2 *artifact.SQLStore, m artifact.StoredMessage) {
	ctx := t.Context()
	for i := range 20 {
		if err := s1.Save(ctx, "race", m); err != nil {
			t.Fatal(err)
		}
		var (
			wg  sync.WaitGroup
			got atomic.Int32
		)
		for j := range 16 {
			s := s1
			if j%2 == 1 {
				s = s2
			}
			wg.Go(func() {
				m, err := s.Take(ctx, "race", "https://idp.example.com")
				if err != nil {
					t.Error(err)
				}
				if m != nil {
					got.Add(1)
				}
			})
		}
		wg.Wait()
		if n := got.Load(); n != 1 {
			t.Fatalf("race %d: %d Takes got the message, want 1", i, n)
		}
	}
}

// TestSQLStoreTakeInterleaved checks the Take that reads the message but
// loses it to another Take before it deletes it: it gets nothing.
func TestSQLStoreTakeInterleaved(t *testing.T) {
	fake := sqlfake.New(artifact.MySQL)
	db := fake.SQL()
	s1, s2 := newSQLStore(t, db, artifact.MySQL, ""), newSQLStore(t, db, artifact.MySQL, "")
	if err := s1.CreateTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	m := artifact.StoredMessage{XML: []byte("<m/>"), Recipient: "idp", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s1.Save(t.Context(), "a", m); err != nil {
		t.Fatal(err)
	}

	paused, resume := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	fake.SetHook(func(q string) {
		// Pause the first DELETE by token only: the second runs at once.
		if strings.Contains(q, "token = ?") && first.CompareAndSwap(false, true) {
			close(paused)
			<-resume
		}
	})
	firstTake := make(chan *artifact.StoredMessage)
	go func() {
		got, err := s1.Take(t.Context(), "a", "idp")
		if err != nil {
			t.Error(err)
		}
		firstTake <- got
	}()
	<-paused // s1 has read the row, and not yet deleted it
	if got, err := s2.Take(t.Context(), "a", "idp"); err != nil || got == nil {
		t.Fatalf("Take while another is between its SELECT and DELETE: %v, %v", got, err)
	}
	close(resume)
	if got := <-firstTake; got != nil {
		t.Fatal("both Takes got the message")
	}
}

func TestSQLStoreLimits(t *testing.T) {
	fake := sqlfake.New(artifact.PostgreSQL)
	db := fake.SQL()
	s := newSQLStore(t, db, artifact.PostgreSQL, "")
	if err := s.CreateTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	m := artifact.StoredMessage{XML: make([]byte, artifact.DefaultMaxMessageSize), Recipient: "idp", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Save(ctx, "a", m); err != nil {
		t.Fatalf("message of DefaultMaxMessageSize: %v", err)
	}
	m.XML = append(m.XML, 0)
	if err := s.Save(ctx, "b", m); !errors.Is(err, artifact.ErrMessageTooLarge) {
		t.Fatalf("larger message: err = %v", err)
	}
	s.MaxMessageSize = 10
	m.XML = make([]byte, 11)
	if err := s.Save(ctx, "c", m); !errors.Is(err, artifact.ErrMessageTooLarge) {
		t.Fatalf("message larger than MaxMessageSize: err = %v", err)
	}
	m.XML = nil
	if err := s.Save(ctx, strings.Repeat("a", 256), m); err == nil {
		t.Error("Save accepted an artifact of 256 bytes")
	}
	if got, err := s.Take(ctx, strings.Repeat("a", 256), "idp"); got != nil || err != nil {
		t.Errorf("Take of an artifact of 256 bytes: %v, %v", got, err)
	}
	m.Recipient = strings.Repeat("r", 1025)
	if err := s.Save(ctx, "d", m); err == nil {
		t.Error("Save accepted a recipient of 1025 bytes")
	}

	if _, err := artifact.NewSQLStore(nil, artifact.PostgreSQL, ""); err == nil {
		t.Error("NewSQLStore accepted no database")
	}
	if _, err := artifact.NewSQLStore(db, artifact.Dialect(0), ""); err == nil {
		t.Error("NewSQLStore accepted an unknown dialect")
	}
	if _, err := artifact.NewSQLStore(db, artifact.PostgreSQL, "t; DROP TABLE x"); err == nil {
		t.Error("NewSQLStore accepted a bad table name")
	}
	stmts, err := artifact.SQLSchema(artifact.MySQL, "")
	if err != nil || len(stmts) != 1 || !strings.Contains(stmts[0], "artifact VARBINARY(255)") {
		t.Errorf("MySQL schema: %q, %v", stmts, err)
	}
}

// TestBindingSQLStore checks that an artifact saved by the Binding of one
// process is resolved by that of another, once.
func TestBindingSQLStore(t *testing.T) {
	idp, cfg, _, _, spCert := setup(t)
	fake := sqlfake.New(artifact.SQLite)
	db := fake.SQL()
	s1, s2 := newSQLStore(t, db, artifact.SQLite, ""), newSQLStore(t, db, artifact.SQLite, "")
	if err := s1.CreateTable(t.Context()); err != nil {
		t.Fatal(err)
	}
	b1, b2 := newBinding(t, cfg, s1), newBinding(t, cfg, s2)

	msg, err := cfg.AuthnRequest(t.Context(), "relay", samlsp.WithCustomBinding(b1))
	if err != nil {
		t.Fatal(err)
	}
	art := msg.RedirectURL().Query().Get("SAMLart")
	got := artifactResponse(t, idp.resolve(t, b2, art, idpEntityID, idp.key, idp.cert), spCert)
	if got == nil || got.SelectAttrValue("ID", "") != msg.ID {
		t.Fatalf("the other process resolved %v", got)
	}
	if again := artifactResponse(t, idp.resolve(t, b1, art, idpEntityID, idp.key, idp.cert), spCert); again != nil {
		t.Error("the artifact was resolved twice")
	}
	if n := fake.Rows(artifact.DefaultSQLTable); n != 0 {
		t.Errorf("%d rows left", n)
	}
}
