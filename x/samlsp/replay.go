package samlsp

import (
	"container/heap"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

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
// Each record is removed when it expires, by a timer set for the earliest
// expiry. There is no timer while the state is empty.
//
// It protects one process only. Applications served by several processes
// need state that they share (see WithReplayState).
type memoryReplayState struct {
	now       func() time.Time
	afterFunc func(d time.Duration, f func()) (stop func() bool)

	mu      sync.Mutex
	expiry  map[string]time.Time
	queue   expiryQueue
	stop    func() bool // stops the pending timer, or nil if there is none
	timerAt time.Time   // when the pending timer fires
	gen     uint64      // identifies the pending timer
}

var _ saml.AssertionReplayCache = (*memoryReplayState)(nil)

func newMemoryReplayState(now func() time.Time) *memoryReplayState {
	return &memoryReplayState{
		now: now,
		afterFunc: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
		expiry: map[string]time.Time{},
	}
}

// Consume implements saml.AssertionReplayCache.
func (s *memoryReplayState) Consume(id string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if exp, ok := s.expiry[id]; ok && !now.After(exp) {
		return saml.ErrAssertionReplayed
	}
	if !now.Before(expiresAt) {
		// Already expired: package saml would refuse the message anyway.
		return nil
	}
	s.expiry[id] = expiresAt
	heap.Push(&s.queue, queued{id: id, expiresAt: expiresAt})
	s.schedule(now)
	return nil
}

// schedule sets the timer for the earliest expiry, unless it is already
// set for it. s.mu must be held.
func (s *memoryReplayState) schedule(now time.Time) {
	if len(s.queue) == 0 {
		s.stopTimer()
		return
	}
	next := s.queue[0].expiresAt
	if s.stop != nil && s.timerAt.Equal(next) {
		return
	}
	s.stopTimer()
	s.gen++
	gen := s.gen
	s.timerAt = next
	// A record is valid until its expiry inclusive, so fire just after.
	s.stop = s.afterFunc(next.Sub(now)+time.Nanosecond, func() { s.expire(gen) })
}

func (s *memoryReplayState) stopTimer() {
	if s.stop != nil {
		s.stop()
		s.stop = nil
	}
}

// expire removes the expired records and sets the timer for the next
// expiry. gen identifies the timer that calls it; a timer that has been
// replaced does nothing.
func (s *memoryReplayState) expire(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	s.stop = nil

	now := s.now()
	for len(s.queue) > 0 && now.After(s.queue[0].expiresAt) {
		q := heap.Pop(&s.queue).(queued)
		// The ID may have been recorded again, with a later expiry, after
		// this record expired; keep that one.
		if exp, ok := s.expiry[q.id]; ok && exp.Equal(q.expiresAt) {
			delete(s.expiry, q.id)
		}
	}
	s.schedule(now)
}

// len returns the number of records.
func (s *memoryReplayState) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.expiry)
}

type queued struct {
	id        string
	expiresAt time.Time
}

// expiryQueue is a min-heap of records by expiry.
type expiryQueue []queued

func (q expiryQueue) Len() int           { return len(q) }
func (q expiryQueue) Less(i, j int) bool { return q[i].expiresAt.Before(q[j].expiresAt) }
func (q expiryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *expiryQueue) Push(x any)        { *q = append(*q, x.(queued)) }
func (q *expiryQueue) Pop() any {
	old := *q
	x := old[len(old)-1]
	*q = old[:len(old)-1]
	return x
}
