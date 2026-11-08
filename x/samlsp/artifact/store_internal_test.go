package artifact

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeTimers records the timers a MemoryStore starts, so that a test can
// fire them.
type fakeTimers struct {
	mu     sync.Mutex
	delays []time.Duration
	fns    []func()
}

func (f *fakeTimers) afterFunc(d time.Duration, fn func()) func() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delays = append(f.delays, d)
	f.fns = append(f.fns, fn)
	return func() bool { return true }
}

// fireLast fires the last timer started and returns its delay.
func (f *fakeTimers) fireLast(t *testing.T) time.Duration {
	f.mu.Lock()
	if len(f.fns) == 0 {
		f.mu.Unlock()
		t.Fatal("no timer was started")
	}
	d, fn := f.delays[len(f.delays)-1], f.fns[len(f.fns)-1]
	f.mu.Unlock()
	fn()
	return d
}

// TestMemoryStoreTimerFollowsNow checks that a message's timer waits at
// most maxTimerDelay, and that the message is forgotten by Now, not by
// the system clock: kept while Now has not passed its expiry, however
// often the timer fires, and forgotten once Now has.
func TestMemoryStoreTimerFollowsNow(t *testing.T) {
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	timers := &fakeTimers{}
	s := &MemoryStore{Now: func() time.Time { return now }, afterFunc: timers.afterFunc}
	ctx := context.Background()
	if err := s.Save(ctx, "a", StoredMessage{Recipient: "idp", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if d := timers.fireLast(t); d != maxTimerDelay {
		t.Errorf("the timer waits %s, not %s", d, maxTimerDelay)
	}
	if s.Len() != 1 {
		t.Fatal("the message was forgotten before it expired by Now")
	}

	now = now.Add(2 * time.Hour)
	timers.fireLast(t)
	if s.Len() != 0 {
		t.Error("the message was kept after it expired by Now")
	}
}

// TestMemoryStoreFullForgetsExpired checks that Save into a full store
// first forgets the messages that have expired by Now, before any that
// has not, however recently the expired ones were saved.
func TestMemoryStoreFullForgetsExpired(t *testing.T) {
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &MemoryStore{MaxEntries: 2, Now: func() time.Time { return now }, afterFunc: (&fakeTimers{}).afterFunc}
	ctx := context.Background()
	if err := s.Save(ctx, "a", StoredMessage{Recipient: "idp", ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "b", StoredMessage{Recipient: "idp", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := s.Save(ctx, "c", StoredMessage{Recipient: "idp", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Save into a full store: %v", err)
	}
	if got, _ := s.Take(ctx, "a", "idp"); got == nil {
		t.Error("the oldest message was forgotten rather than the expired one")
	}
	if got, _ := s.Take(ctx, "b", "idp"); got != nil {
		t.Error("the expired message was kept")
	}
}

// TestMemoryStoreEvictsOldest checks that Save into a full store forgets
// the message saved longest ago, in the order they were saved, that
// saving under an artifact again counts as saving it anew, and that the
// store never keeps more than MaxEntries.
func TestMemoryStoreEvictsOldest(t *testing.T) {
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &MemoryStore{MaxEntries: 3, Now: func() time.Time { return now }, afterFunc: (&fakeTimers{}).afterFunc}
	ctx := context.Background()
	save := func(art string) {
		t.Helper()
		if err := s.Save(ctx, art, StoredMessage{Recipient: "idp", ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("Save(%s): %v", art, err)
		}
		if s.Len() > 3 {
			t.Fatalf("Len = %d after Save(%s), more than MaxEntries", s.Len(), art)
		}
	}
	// a b c; saving a again makes it the newest: b c a.
	for _, art := range []string{"a", "b", "c", "a"} {
		save(art)
	}
	save("d") // forgets b: c a d
	save("e") // forgets c: a d e
	for art, want := range map[string]bool{"a": true, "b": false, "c": false, "d": true, "e": true} {
		got, err := s.Take(ctx, art, "idp")
		if err != nil {
			t.Fatal(err)
		}
		if (got != nil) != want {
			t.Errorf("Take(%s) found the message: %v, want %v", art, got != nil, want)
		}
	}
	if s.Len() != 0 || s.order.Len() != 0 {
		t.Errorf("Len = %d, order has %d, after taking every message", s.Len(), s.order.Len())
	}
}

// TestMemoryStoreExpiryKeepsOrder checks that a message forgotten by its
// timer leaves the eviction order too.
func TestMemoryStoreExpiryKeepsOrder(t *testing.T) {
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	timers := &fakeTimers{}
	s := &MemoryStore{MaxEntries: 2, Now: func() time.Time { return now }, afterFunc: timers.afterFunc}
	ctx := context.Background()
	if err := s.Save(ctx, "a", StoredMessage{Recipient: "idp", ExpiresAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	timers.fireLast(t)
	if s.Len() != 0 || s.order.Len() != 0 {
		t.Fatalf("Len = %d, order has %d, after the message expired", s.Len(), s.order.Len())
	}
	for _, art := range []string{"b", "c", "d"} {
		if err := s.Save(ctx, art, StoredMessage{Recipient: "idp", ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.Take(ctx, "d", "idp"); got == nil {
		t.Error("the newest message was forgotten")
	}
}
