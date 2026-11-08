package replay

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// fakeTimers stands in for time.AfterFunc and the clock: advance moves the
// time on and runs the timers that are due.
type fakeTimers struct {
	now     time.Time
	pending map[int]fakeTimer
	next    int
}

type fakeTimer struct {
	at time.Time
	f  func()
}

func newFakeTimers() *fakeTimers {
	return &fakeTimers{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), pending: map[int]fakeTimer{}}
}

func (ft *fakeTimers) afterFunc(d time.Duration, f func()) func() bool {
	id := ft.next
	ft.next++
	ft.pending[id] = fakeTimer{at: ft.now.Add(d), f: f}
	return func() bool {
		_, ok := ft.pending[id]
		delete(ft.pending, id)
		return ok
	}
}

func (ft *fakeTimers) advance(d time.Duration) {
	ft.now = ft.now.Add(d)
	for {
		ran := false
		for id, t := range ft.pending {
			if !t.at.After(ft.now) {
				delete(ft.pending, id)
				t.f()
				ran = true
				break
			}
		}
		if !ran {
			return
		}
	}
}

func newTestReplayState() (*Memory, *fakeTimers) {
	ft := newFakeTimers()
	s := &Memory{Now: func() time.Time { return ft.now }, afterFunc: ft.afterFunc}
	return s, ft
}

func TestMemoryReplayState(t *testing.T) {
	s, ft := newTestReplayState()
	if len(ft.pending) != 0 {
		t.Fatal("a timer is set while the state is empty")
	}

	if err := s.Consume(t.Context(), []byte("a"), ft.now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(t.Context(), []byte("a"), ft.now.Add(90*time.Second)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replay: err = %v", err)
	}
	if err := s.Consume(t.Context(), []byte("b"), ft.now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(ft.pending) != 1 {
		t.Fatalf("%d timers, want 1", len(ft.pending))
	}

	// An earlier expiry moves the timer earlier.
	if err := s.Consume(t.Context(), []byte("c"), ft.now.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(ft.pending) != 1 {
		t.Fatalf("%d timers, want 1", len(ft.pending))
	}

	// A record is valid until its expiry, inclusive.
	ft.advance(30 * time.Second)
	if err := s.Consume(t.Context(), []byte("c"), ft.now); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("c at its expiry: err = %v", err)
	}
	ft.advance(time.Second)
	if n := s.Len(); n != 2 {
		t.Fatalf("%d records once c expired, want 2", n)
	}

	ft.advance(time.Minute)
	if n := s.Len(); n != 1 {
		t.Fatalf("%d records once a expired, want 1", n)
	}
	// An expired ID is accepted again; package saml refuses the expired
	// message itself.
	if err := s.Consume(t.Context(), []byte("a"), ft.now.Add(time.Hour)); err != nil {
		t.Fatalf("expired ID: %v", err)
	}

	ft.advance(time.Hour + time.Second)
	if n := s.Len(); n != 0 {
		t.Fatalf("%d records once all expired, want 0", n)
	}
	if len(ft.pending) != 0 {
		t.Fatal("a timer is still set while the state is empty")
	}
}

// TestMemoryReplayStateReRecorded checks that the stale queue entry of an ID
// recorded again does not remove its new record.
func TestMemoryReplayStateReRecorded(t *testing.T) {
	s, ft := newTestReplayState()
	if err := s.Consume(t.Context(), []byte("a"), ft.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Expired, but its timer has not run yet.
	ft.now = ft.now.Add(2 * time.Second)
	if err := s.Consume(t.Context(), []byte("a"), ft.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ft.advance(0)
	if err := s.Consume(t.Context(), []byte("a"), ft.now.Add(time.Minute)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("re-recorded ID: err = %v", err)
	}
}

// TestMemoryReplayStateBounded checks that a steady rate of logins keeps a
// steady number of records: there is no need for a size limit.
func TestMemoryReplayStateBounded(t *testing.T) {
	s, ft := newTestReplayState()
	lifetime := saml.MaxIssueDelay
	interval := 100 * time.Millisecond

	peak := 0
	for i := range 100_000 { // ten logins a second for nearly three hours
		ft.advance(interval)
		if err := s.Consume(t.Context(), []byte(fmt.Sprint(i)), ft.now.Add(lifetime)); err != nil {
			t.Fatal(err)
		}
		peak = max(peak, s.Len())
	}
	if limit := int(lifetime/interval) + 1; peak > limit {
		t.Errorf("peak of %d records, want at most %d", peak, limit)
	}
	if len(s.queue) != s.Len() {
		t.Errorf("%d queued for %d records", len(s.queue), s.Len())
	}
}

func TestMemoryReplayStateRealTimer(t *testing.T) {
	s := NewMemory()
	if err := s.Consume(t.Context(), []byte("a"), time.Now().Add(10*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the record was not removed by the timer")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestMemoryNow checks that IDs expire by the Memory's Now: an ID valid for
// a minute by a clock set in the past is recorded, and refused the second
// time.
func TestMemoryNow(t *testing.T) {
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Memory{Now: func() time.Time { return past }}
	if err := s.Consume(t.Context(), []byte("a"), past.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(t.Context(), []byte("a"), past.Add(time.Minute)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replay: err = %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopTimer()
}

// TestMemoryNowApart checks that IDs are removed when Now runs apart from
// the system clock of the timers: the timer waits at most maxTimerDelay,
// then checks again by Now, and Consume removes expired IDs too.
func TestMemoryNowApart(t *testing.T) {
	ft := newFakeTimers()
	appNow := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Memory{Now: func() time.Time { return appNow }, afterFunc: ft.afterFunc}
	if err := s.Consume(t.Context(), []byte("a"), appNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, timer := range ft.pending {
		if d := timer.at.Sub(ft.now); d > maxTimerDelay {
			t.Fatalf("timer set %v ahead", d)
		}
	}
	// Now does not move: the timer finds nothing expired, and is set again.
	ft.advance(maxTimerDelay)
	if s.Len() != 1 || len(ft.pending) != 1 {
		t.Fatalf("%d records, %d timers; want 1, 1", s.Len(), len(ft.pending))
	}
	// Now jumps past the expiry: the next timer removes the ID.
	appNow = appNow.Add(2 * time.Hour)
	ft.advance(maxTimerDelay)
	if s.Len() != 0 || len(ft.pending) != 0 {
		t.Fatalf("%d records, %d timers once expired; want 0, 0", s.Len(), len(ft.pending))
	}

	// Consume removes the expired IDs before the timer runs.
	if err := s.Consume(t.Context(), []byte("b"), appNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	appNow = appNow.Add(time.Hour)
	if err := s.Consume(t.Context(), []byte("c"), appNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Fatalf("%d records, want 1", s.Len())
	}
}
