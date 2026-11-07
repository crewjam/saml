package samlsp

import (
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// replaySweepInterval is how often memoryReplayState drops expired records.
const replaySweepInterval = time.Minute

// memoryReplayState is the default replay state of a Config: the IDs of the
// assertions (and LogoutRequests) it has accepted, in memory, each until
// the message could no longer be accepted anyway.
//
// It has no size limit, because it does not need one. Package saml records
// an ID only after the message is fully verified: signed by the IdP,
// addressed to this SP, answering a request of this SP (unless unsolicited
// responses are allowed), and fresh. The expiry it records is at most
// saml.MaxIssueDelay after the message's IssueInstant. So the state holds
// only messages the IdP really issued in the last few minutes, and grows
// with the rate of logins, not with anything an attacker can send.
//
// It protects one process only. Applications served by several processes
// need state that they share (see WithReplayState).
type memoryReplayState struct {
	now func() time.Time

	mu        sync.Mutex
	expiry    map[string]time.Time
	nextSweep time.Time
}

var _ saml.AssertionReplayCache = (*memoryReplayState)(nil)

func newMemoryReplayState(now func() time.Time) *memoryReplayState {
	return &memoryReplayState{now: now, expiry: map[string]time.Time{}}
}

// Consume implements saml.AssertionReplayCache.
func (s *memoryReplayState) Consume(id string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if !now.Before(s.nextSweep) {
		for k, exp := range s.expiry {
			if now.After(exp) {
				delete(s.expiry, k)
			}
		}
		s.nextSweep = now.Add(replaySweepInterval)
	}

	if exp, ok := s.expiry[id]; ok && !now.After(exp) {
		return saml.ErrAssertionReplayed
	}
	s.expiry[id] = expiresAt
	return nil
}

// len returns the number of records, expired or not.
func (s *memoryReplayState) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.expiry)
}
