package artifact

import (
	"context"
	"errors"
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
// first forgets the messages that have expired by Now.
func TestMemoryStoreFullForgetsExpired(t *testing.T) {
	now := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &MemoryStore{MaxEntries: 1, Now: func() time.Time { return now }, afterFunc: (&fakeTimers{}).afterFunc}
	ctx := context.Background()
	if err := s.Save(ctx, "a", StoredMessage{ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "b", StoredMessage{ExpiresAt: now.Add(time.Minute)}); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("Save into a full store: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := s.Save(ctx, "b", StoredMessage{ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("Save into a store full of expired messages: %v", err)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
}
