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
