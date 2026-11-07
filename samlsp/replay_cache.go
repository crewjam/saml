package samlsp

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// ErrReplayCacheFull is returned by a MemoryReplayCache that holds its
// maximum number of unexpired assertion IDs. The assertion is refused.
var ErrReplayCacheFull = errors.New("samlsp: replay cache is full")

// MemoryReplayCache is a saml.AssertionReplayCache that keeps the IDs of
// accepted assertions in memory, each until the expiry it was recorded with.
// It is safe for concurrent use.
//
// It only protects a single process: an assertion accepted by one server is
// not known to another server, nor to this one after a restart. Deployments
// with more than one server must use a shared store instead.
//
// It holds at most maxEntries IDs. An ID is dropped once its expiry has
// passed, which is at most saml.MaxIssueDelay plus saml.MaxClockSkew after the
// assertion was issued, so maxEntries should exceed the number of logins
// expected in that period. When the cache is full of unexpired IDs, Consume
// refuses new assertions with ErrReplayCacheFull rather than dropping an
// unexpired ID, since dropping one would let that assertion be replayed.
// A full cache therefore blocks logins until its oldest IDs expire.
//
// Expiry is judged by saml.TimeNow, so it is meant for a ServiceProvider that
// uses the default clock.
type MemoryReplayCache struct {
	mu         sync.Mutex
	maxEntries int
	entries    map[string]time.Time
	// nextExpiry is the earliest expiry in entries, or zero when it may be
	// stale; no ID can be dropped before it.
	nextExpiry time.Time
}

var _ saml.AssertionReplayCache = (*MemoryReplayCache)(nil)

// NewMemoryReplayCache returns a MemoryReplayCache that holds at most
// maxEntries unexpired assertion IDs. It panics if maxEntries is not positive.
func NewMemoryReplayCache(maxEntries int) *MemoryReplayCache {
	if maxEntries <= 0 {
		panic(fmt.Sprintf("samlsp: NewMemoryReplayCache: maxEntries must be positive, got %d", maxEntries))
	}
	return &MemoryReplayCache{
		maxEntries: maxEntries,
		entries:    map[string]time.Time{},
	}
}

// Consume implements saml.AssertionReplayCache.
func (c *MemoryReplayCache) Consume(assertionID string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := saml.TimeNow()
	if prev, ok := c.entries[assertionID]; ok && !now.After(prev) {
		return saml.ErrAssertionReplayed
	}
	// An expired record for this ID is replaced below; the ServiceProvider
	// no longer accepts the assertion it was recorded for.
	delete(c.entries, assertionID)

	if len(c.entries) >= c.maxEntries {
		c.dropExpired(now)
		if len(c.entries) >= c.maxEntries {
			return ErrReplayCacheFull
		}
	}

	c.entries[assertionID] = expiresAt
	if c.nextExpiry.IsZero() || expiresAt.Before(c.nextExpiry) {
		c.nextExpiry = expiresAt
	}
	return nil
}

// dropExpired removes the IDs whose expiry is not after now. It does nothing
// before nextExpiry, so a cache full of unexpired IDs is not scanned on every
// call.
func (c *MemoryReplayCache) dropExpired(now time.Time) {
	if !c.nextExpiry.IsZero() && !now.After(c.nextExpiry) {
		return
	}
	c.nextExpiry = time.Time{}
	for id, expiresAt := range c.entries {
		if now.After(expiresAt) {
			delete(c.entries, id)
			continue
		}
		if c.nextExpiry.IsZero() || expiresAt.Before(c.nextExpiry) {
			c.nextExpiry = expiresAt
		}
	}
}
