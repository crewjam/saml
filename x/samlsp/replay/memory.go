// Package replay keeps the record that makes each SAML message accepted
// only once: the keys of the messages a service provider or identity
// provider has accepted, each until the message could no longer be
// accepted anyway. It is the default replay state of
// github.com/crewjam/saml/x/samlsp, which records assertions, resolved
// artifacts, LogoutRequests and LogoutResponses (see samlsp.ReplayKey and
// samlsp.WithReplayState), and of github.com/crewjam/saml/x/samlidp, which
// records signed AuthnRequests, LogoutRequests and LogoutResponses (see
// samlidp.ReplayKey and samlidp.WithReplayState).
//
// Memory keeps the record in memory, which protects a single process: a
// message replayed to another process of the same provider is accepted
// there. A provider served by several processes, behind a load balancer
// or across a restart, needs a record that they share. SQL keeps it in a
// table of a database reached through database/sql (PostgreSQL, MySQL or
// SQLite), whose primary key makes only one of the processes that record
// a message succeed; any other shared store can implement
// samlsp.ReplayState and samlidp.ReplayState the same way. A shared
// record compares each expiry with the clock of the process that reads
// it, so keep the clocks of the processes close together: see SQL for
// the one replay that clocks further apart than SQL.ClockSkew allow.
package replay

import (
	"container/heap"
	"context"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// Memory records message keys in memory, which protects a single process.
// Applications served by several processes need a record that they share,
// such as SQL.
//
// It has no size limit, because it does not need one. An ID is recorded
// only after the message is fully verified: signed by the peer, addressed
// to this provider, answering one of its requests where it should, and
// fresh. The expiry recorded is at most the issue delay
// (saml.MaxIssueDelay, unless the provider sets its own) after the
// message's IssueInstant. So the record holds only messages the peers
// really issued in the last few minutes, and grows with the rate of logins
// and logouts, not with anything an attacker can send.
//
// Each ID is removed once it has expired, by a timer set for the earliest
// expiry, but at most maxTimerDelay ahead, so that IDs are still removed
// when Now is not the system clock. Consume also removes the IDs that have
// expired. There is no timer while the record is empty.
//
// A Memory is safe for concurrent use, and may be shared by several
// samlsp.Configs and samlidp.Configs. The zero value is ready to use.
type Memory struct {
	// Now is the time source by which IDs expire; nil means time.Now. It
	// must be the clock by which the callers compute the expiries they
	// pass to Consume: an ID whose expiry is already past by Now is not
	// recorded at all. The default record of samlsp.New and samlidp.New
	// uses the time source of package saml: the clock of WithClock, or
	// else saml.TimeNow; and they set the Now of a Memory passed to
	// WithReplayState that has none to it too (see DefaultNow). Set it
	// before the first Consume.
	Now func() time.Time

	afterFunc func(d time.Duration, f func()) (stop func() bool) // for tests; time.AfterFunc if nil

	mu      sync.Mutex
	expiry  map[string]time.Time
	queue   expiryQueue
	stop    func() bool // stops the pending timer, or nil if there is none
	timerAt time.Time   // when the pending timer fires
	gen     uint64      // identifies the pending timer
}

// maxTimerDelay bounds how long the timer waits, by the system clock,
// before it checks again for expired IDs. Now may run apart from the
// system clock, so a timer set for an expiry by Now could otherwise fire
// long after it, or long before.
const maxTimerDelay = time.Minute

// NewMemory returns an empty Memory that uses the system clock.
func NewMemory() *Memory { return &Memory{} }

// DefaultNow sets Now to now if Now is nil, under the Memory's lock, so
// that it is safe while the Memory is in use. samlsp.New and samlidp.New
// call it with their clock, so that a Memory shared by Configs follows the
// clock of the first one built.
func (s *Memory) DefaultNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Now == nil {
		s.Now = now
	}
}

func (s *Memory) currentTime() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
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
	s.removeExpired(now)
	if !now.Before(expiresAt) {
		// Already expired: package saml would refuse the message anyway.
		s.schedule(now)
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
	d := min(next.Sub(now)+time.Nanosecond, maxTimerDelay)
	s.stop = s.startTimer(d, func() { s.expire(gen) })
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
	s.removeExpired(now)
	s.schedule(now)
}

// removeExpired removes the records that have expired at now. s.mu must be
// held.
func (s *Memory) removeExpired(now time.Time) {
	for len(s.queue) > 0 && now.After(s.queue[0].expiresAt) {
		q := heap.Pop(&s.queue).(queued)
		// The ID may have been recorded again, with a later expiry, after
		// this record expired; keep that one.
		if exp, ok := s.expiry[q.key]; ok && exp.Equal(q.expiresAt) {
			delete(s.expiry, q.key)
		}
	}
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
