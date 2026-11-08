package samlidp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp/replay"
)

// A replay.Memory passed to WithReplayState without a clock gets the
// Config's: otherwise, with a clock behind the system clock, every expiry
// would be past by the Memory's clock and nothing would be recorded.
func TestSharedReplayStateClock(t *testing.T) {
	keys(t)
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	c, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert),
		samlidp.WithClock(dsig.NewFakeClockAt(past)), samlidp.WithReplayState(replay.NewMemory()))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.Consume(ctx, spEntityID, "id-1", past.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := c.Consume(ctx, spEntityID, "id-1", past.Add(time.Minute)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Errorf("replayed: got %v", err)
	}
}
