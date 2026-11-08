package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }

	in := &Instance{ID: "a", Secret: "s", Kind: KindIdP, Config: []byte(`{}`), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateInstance(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Instance(ctx, KindSP, "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong kind: %v", err)
	}
	if got, err := s.InstanceBySecret(ctx, "s"); err != nil || got.ID != "a" {
		t.Fatalf("by secret: %v %v", got, err)
	}

	for i := range MaxEventsPerInstance + 5 {
		if err := s.AddEvent(ctx, &Event{InstanceID: "a", Title: fmt.Sprint(i)}); err != nil {
			t.Fatal(err)
		}
	}
	events, _ := s.Events(ctx, "a")
	if len(events) != MaxEventsPerInstance || events[0].Title != fmt.Sprint(MaxEventsPerInstance+4) {
		t.Errorf("events: %d, newest %q", len(events), events[0].Title)
	}

	if err := s.PutPending(ctx, "p", "a", map[string]string{"x": "y"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := s.GetPending(ctx, "p", "a", &v); err != nil || v["x"] != "y" {
		t.Errorf("pending: %v %v", v, err)
	}
	if err := s.GetPending(ctx, "p", "other", &v); !errors.Is(err, ErrNotFound) {
		t.Errorf("pending of another instance: %v", err)
	}

	key := []byte("0123456789abcdef0123456789abcdef")
	if err := s.Consume(ctx, key, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(ctx, key, now.Add(time.Minute)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Errorf("replay: %v", err)
	}

	// Two hours later everything has expired.
	now = now.Add(2 * time.Hour)
	if _, err := s.InstanceBySecret(ctx, "s"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired instance: %v", err)
	}
	if err := s.Consume(ctx, key, now.Add(time.Minute)); err != nil {
		t.Errorf("an expired replay record must not block: %v", err)
	}
	if n, err := s.Reap(ctx); err != nil || n != 1 {
		t.Errorf("reap: %d %v", n, err)
	}
	if events, _ := s.Events(ctx, "a"); len(events) != 0 {
		t.Errorf("events of a reaped instance: %d", len(events))
	}
}

func TestSessionsAndArtifacts(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	for _, id := range []string{"a", "b"} {
		if err := s.CreateInstance(ctx, &Instance{ID: id, Secret: id, Kind: KindIdP, Config: []byte(`{}`), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutSession(ctx, &Session{ID: "s1", InstanceID: "a", Data: []byte(`{"v":1}`), ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSession(ctx, &Session{ID: "s1", InstanceID: "a", Data: []byte(`{"v":2}`), ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	// Another instance cannot overwrite or read it.
	_ = s.PutSession(ctx, &Session{ID: "s1", InstanceID: "b", Data: []byte(`{"v":3}`), ExpiresAt: now.Add(time.Minute)})
	if _, err := s.GetSession(ctx, "s1", "b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("other instance: %v", err)
	}
	got, err := s.GetSession(ctx, "s1", "a")
	if err != nil || string(got.Data) != `{"v":2}` {
		t.Fatalf("%v %v", got, err)
	}
	if list, _ := s.Sessions(ctx, "a"); len(list) != 1 {
		t.Errorf("sessions: %d", len(list))
	}

	if err := s.SaveArtifact(ctx, "a", "art", "sp", []byte("<x/>"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := s.TakeArtifact(ctx, "a", "art", "other"); found {
		t.Error("taken by another recipient")
	}
	if xml, _, found, err := s.TakeArtifact(ctx, "a", "art", "sp"); !found || err != nil || string(xml) != "<x/>" {
		t.Errorf("take: %q %v %v", xml, found, err)
	}
	if _, _, found, _ := s.TakeArtifact(ctx, "a", "art", "sp"); found {
		t.Error("taken twice")
	}

	now = now.Add(2 * time.Minute)
	if _, err := s.GetSession(ctx, "s1", "a"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired session: %v", err)
	}
}

func TestCreateInstanceTaken(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	now := time.Now()
	in := &Instance{ID: "comic-krill", Secret: "wholly-blessed-mammoth", Kind: KindIdP, Config: []byte(`{}`), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateInstance(ctx, in); err != nil {
		t.Fatal(err)
	}
	sameID := *in
	sameID.Secret = "other-secret-name"
	if err := s.CreateInstance(ctx, &sameID); !errors.Is(err, ErrTaken) {
		t.Errorf("same ID: %v", err)
	}
	sameSecret := *in
	sameSecret.ID = "other-name"
	if err := s.CreateInstance(ctx, &sameSecret); !errors.Is(err, ErrTaken) {
		t.Errorf("same secret: %v", err)
	}
}

// The database outlives restarts: reopening keeps what was stored, and
// migrations run once.
func TestReopenKeepsData(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/gosaml.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	in := &Instance{ID: "a", Secret: "s", Kind: KindSP, Config: []byte(`{}`), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := s.CreateInstance(ctx, in); err != nil {
		t.Fatal(err)
	}
	if err := s.AddEvent(ctx, &Event{InstanceID: "a", Title: "kept"}); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck // test
	if got, err := s.InstanceBySecret(ctx, "s"); err != nil || got.ID != "a" {
		t.Fatalf("instance after reopening: %v %v", got, err)
	}
	if events, _ := s.Events(ctx, "a"); len(events) != 1 || events[0].Title != "kept" {
		t.Fatalf("events after reopening: %v", events)
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != len(migrations) {
		t.Fatalf("user_version = %d, %v; want %d", version, err, len(migrations))
	}
}

// A database made before versioning (user_version 0, tables present)
// keeps its data when migrated; one from a newer server is refused.
func TestMigrate(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/gosaml.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.CreateInstance(ctx, &Instance{ID: "a", Secret: "s", Kind: KindIdP, Config: []byte(`{}`), CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s, err = Open(path); err != nil {
		t.Fatalf("unversioned database: %v", err)
	}
	if _, err := s.InstanceBySecret(ctx, "s"); err != nil {
		t.Fatalf("data lost migrating an unversioned database: %v", err)
	}
	if _, err := s.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)+1)); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if s, err = Open(path); err == nil {
		_ = s.Close()
		t.Fatal("a database from a newer server was opened")
	}
}
