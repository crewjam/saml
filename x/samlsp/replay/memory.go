// Package replay keeps the record that makes each SAML message accepted
// only once: the keys (see samlsp.ReplayKey) of the assertions, logout
// requests and artifacts a service provider has accepted, each until the
// message could no longer be accepted anyway. It is the replay state of
// github.com/crewjam/saml/x/samlsp; see samlsp.WithReplayState.
package replay

import (
	"container/heap"
	"context"
	"sync"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

// Memory records message keys in memory, which protects a single process.
// Applications served by several processes need a record that they share,
// such as a database table with a unique key on the ID.
//
// It has no size limit, because it does not need one. Package saml records
// an ID only after the message is fully verified: signed by the IdP,
// addressed to this SP, answering a request of this SP (unless unsolicited
// responses are allowed), and fresh. The expiry it records is at most
// saml.MaxIssueDelay after the message's IssueInstant. So the record holds
// only messages the IdP really issued in the last few minutes, and grows
// with the rate of logins, not with anything an attacker can send.
//
// Each ID is removed when it expires, by a timer set for the earliest
// expiry. There is no timer while the record is empty.
//
// A Memory is safe for concurrent use, and may be shared by several
// samlsp.Configs. The zero value is ready to use.
type Memory struct {
	// Clock is the time source by which IDs expire; nil means the system
	// clock. Use the clock passed to samlsp.WithClock. Set it before the
	// first Consume.
	Clock *dsig.Clock

	now       func() time.Time                                   // for tests; Clock.Now if nil
	afterFunc func(d time.Duration, f func()) (stop func() bool) // for tests; time.AfterFunc if nil

	mu      sync.Mutex
	expiry  map[string]time.Time
	queue   expiryQueue
	stop    func() bool // stops the pending timer, or nil if there is none
	timerAt time.Time   // when the pending timer fires
	gen     uint64      // identifies the pending timer
}

// NewMemory returns an empty Memory that uses the system clock.
func NewMemory() *Memory { return &Memory{} }

func (s *Memory) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return s.Clock.Now()
}

func (s *Memory) startTimer(d time.Duration, f func()) func() bool {
	if s.afterFunc != nil {
		return s.afterFunc(d, f)
	}
	return time.AfterFunc(d, f).Stop
}

// Consume records the message identified by key as accepted until
// expiresAt. It returns saml.ErrAssertionReplayed if key is recorded and
// has not expired. It implements samlsp.ReplayState; ctx is not used.
func (s *Memory) Consume(_ context.Context, key []byte, expiresAt time.Time) error {
	k := string(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.currentTime()
	if exp, ok := s.expiry[k]; ok && !now.After(exp) {
		return saml.ErrAssertionReplayed
	}
	if !now.Before(expiresAt) {
		// Already expired: package saml would refuse the message anyway.
		return nil
	}
	if s.expiry == nil {
		s.expiry = map[string]time.Time{}
	}
	s.expiry[k] = expiresAt
	heap.Push(&s.queue, queued{key: k, expiresAt: expiresAt})
	s.schedule(now)
	return nil
}

// schedule sets the timer for the earliest expiry, unless it is already
// set for it. s.mu must be held.
func (s *Memory) schedule(now time.Time) {
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
	s.stop = s.startTimer(next.Sub(now)+time.Nanosecond, func() { s.expire(gen) })
}

func (s *Memory) stopTimer() {
	if s.stop != nil {
		s.stop()
		s.stop = nil
	}
}

// expire removes the expired records and sets the timer for the next
// expiry. gen identifies the timer that calls it; a timer that has been
// replaced does nothing.
func (s *Memory) expire(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen != s.gen {
		return
	}
	s.stop = nil

	now := s.currentTime()
	for len(s.queue) > 0 && now.After(s.queue[0].expiresAt) {
		q := heap.Pop(&s.queue).(queued)
		// The ID may have been recorded again, with a later expiry, after
		// this record expired; keep that one.
		if exp, ok := s.expiry[q.key]; ok && exp.Equal(q.expiresAt) {
			delete(s.expiry, q.key)
		}
	}
	s.schedule(now)
}

// Len returns the number of IDs recorded.
func (s *Memory) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.expiry)
}

type queued struct {
	key       string
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
