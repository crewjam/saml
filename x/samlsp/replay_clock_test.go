package samlsp

import (
	"errors"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp/replay"
)

// TestDefaultReplayStateClock checks that the default ReplayState judges
// expiry by the time source of package saml: the clock of WithClock, or
// else saml.TimeNow. A message valid for a minute by that time, which has
// long expired by the system clock, is refused the second time.
func TestDefaultReplayStateClock(t *testing.T) {
	const entityID = "https://sp.example.com/saml/metadata"
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	clocked, err := New(entityID, nil, WithClock(dsig.NewFakeClockAt(past)))
	if err != nil {
		t.Fatal(err)
	}
	restore := saml.TimeNow                         //nolint:staticcheck // the deprecated fallback is what is tested
	saml.TimeNow = func() time.Time { return past } //nolint:staticcheck // as above
	defer func() { saml.TimeNow = restore }()       //nolint:staticcheck // as above
	unclocked, err := New(entityID, nil)
	if err != nil {
		t.Fatal(err)
	}

	key := ReplayKey("https://idp.example.com/saml/metadata", "id-1")
	for name, c := range map[string]*Config{"WithClock": clocked, "saml.TimeNow": unclocked} {
		if err := c.replayState.Consume(t.Context(), key, past.Add(time.Minute)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.replayState.Consume(t.Context(), key, past.Add(time.Minute)); !errors.Is(err, saml.ErrAssertionReplayed) {
			t.Errorf("%s: replayed: got %v", name, err)
		}
	}
}

// TestSharedReplayStateClock checks that a replay.Memory passed to
// WithReplayState without a clock gets the Config's: otherwise, with a
// clock behind the system clock, every expiry would be past by the
// Memory's clock and nothing would be recorded.
func TestSharedReplayStateClock(t *testing.T) {
	const entityID = "https://sp.example.com/saml/metadata"
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	shared := replay.NewMemory()
	c, err := New(entityID, nil, WithClock(dsig.NewFakeClockAt(past)), WithReplayState(shared))
	if err != nil {
		t.Fatal(err)
	}
	key := ReplayKey("https://idp.example.com/saml/metadata", "id-1")
	if err := c.replayState.Consume(t.Context(), key, past.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.replayState.Consume(t.Context(), key, past.Add(time.Minute)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Errorf("replayed: got %v", err)
	}

	// A Memory with its own clock keeps it.
	own := func() time.Time { return past }
	kept := &replay.Memory{Now: own}
	if _, err := New(entityID, nil, WithReplayState(kept)); err != nil {
		t.Fatal(err)
	}
	if kept.Now == nil || !kept.Now().Equal(past) {
		t.Error("New replaced the Memory's own clock")
	}
}
