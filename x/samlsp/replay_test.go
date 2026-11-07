package samlsp

import (
	"errors"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestMemoryReplayState(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := newMemoryReplayState(func() time.Time { return now })

	if err := s.Consume("a", now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := s.Consume("a", now.Add(90*time.Second)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replay: err = %v", err)
	}
	if err := s.Consume("b", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	// Once its expiry has passed, an ID is accepted again (the SP refuses
	// the expired message itself) and its record goes at the next sweep.
	now = now.Add(2 * time.Minute)
	if err := s.Consume("a", now.Add(90*time.Second)); err != nil {
		t.Fatalf("expired ID: %v", err)
	}
	if err := s.Consume("b", now); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("unexpired ID: err = %v", err)
	}

	now = now.Add(11 * time.Minute)
	if err := s.Consume("c", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if n := s.len(); n != 1 {
		t.Errorf("%d records after the sweep, want 1", n)
	}
}

// TestMemoryReplayStateBounded checks that a steady rate of logins keeps a
// steady number of records: there is no need for a size limit.
func TestMemoryReplayStateBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := newMemoryReplayState(func() time.Time { return now })
	lifetime := saml.MaxIssueDelay

	peak := 0
	for i := range 100_000 { // ten logins a second for nearly three hours
		now = now.Add(100 * time.Millisecond)
		if err := s.Consume(string(rune(i))+time.Duration(i).String(), now.Add(lifetime)); err != nil {
			t.Fatal(err)
		}
		peak = max(peak, s.len())
	}
	// At most the lifetime plus one sweep interval of logins is held.
	if limit := int((lifetime + replaySweepInterval) / (100 * time.Millisecond)); peak > limit+1 {
		t.Errorf("peak of %d records, want at most %d", peak, limit)
	}
}
