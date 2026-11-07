package samlidp

import (
	"container/heap"
	"errors"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// expiredSessionRetention is how long an expired session is kept before it
// is deleted. An expired session no longer logs anyone in, but it is kept a
// while so that single logout can still reach the service providers it was
// used for, whose own sessions can outlive it.
var expiredSessionRetention = 24 * time.Hour

// expiryRetryDelay is how long to wait before trying again to delete a
// session whose deletion failed because the Store returned an error.
const expiryRetryDelay = time.Minute

// stopper is what sessionExpiry needs of a timer; *time.Timer satisfies it.
type stopper interface {
	Stop() bool
}

// expiryEntry is a session to delete once deleteAt has passed.
type expiryEntry struct {
	deleteAt  time.Time
	sessionID string
}

// expiryHeap is a min-heap of entries ordered by deleteAt.
type expiryHeap []expiryEntry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].deleteAt.Before(h[j].deleteAt) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

// sessionExpiry schedules the deletion of stored sessions: a heap of the
// sessions ordered by when they are due to be deleted, and one timer armed
// for the earliest of them.
type sessionExpiry struct {
	seedOnce sync.Once

	mu      sync.Mutex // protects the fields below
	entries expiryHeap
	timer   stopper   // armed for timerAt, or nil
	timerAt time.Time // when timer fires
}

// sessionDeleteAt returns when session is due to be deleted.
func sessionDeleteAt(session *saml.Session) time.Time {
	return session.ExpireTime.Add(expiredSessionRetention)
}

// scheduleSessionDeletion arranges for session to be deleted once it has
// been expired for expiredSessionRetention.
func (s *Server) scheduleSessionDeletion(session *saml.Session) {
	s.seedSessionExpiry(session.ID)
	s.pushSessionExpiry(expiryEntry{deleteAt: sessionDeleteAt(session), sessionID: session.ID})
}

// seedSessionExpiry schedules the deletion of the sessions already in the
// Store, other than skipID (which the caller schedules), the first time it
// is called: those stored before this process started, or by another
// server sharing the Store. The Store is read without holding the lock.
func (s *Server) seedSessionExpiry(skipID string) {
	s.expiry.seedOnce.Do(func() {
		ids, err := s.Store.List("/sessions/")
		if err != nil {
			s.logger.Printf("ERROR: cannot list sessions to schedule their deletion: %s", err)
			return
		}
		entries := make([]expiryEntry, 0, len(ids))
		for _, id := range ids {
			if id == skipID {
				continue
			}
			session := &saml.Session{}
			if err := s.Store.Get(sessionKey(id), session); err != nil {
				if !errors.Is(err, ErrNotFound) {
					s.logger.Printf("ERROR: cannot read session to schedule its deletion: %s", err)
				}
				continue
			}
			entries = append(entries, expiryEntry{deleteAt: sessionDeleteAt(session), sessionID: id})
		}
		s.pushSessionExpiry(entries...)
	})
}

// pushSessionExpiry adds entries to the heap and re-arms the timer if the
// earliest deadline changed.
func (s *Server) pushSessionExpiry(entries ...expiryEntry) {
	s.expiry.mu.Lock()
	defer s.expiry.mu.Unlock()
	for _, e := range entries {
		heap.Push(&s.expiry.entries, e)
	}
	s.armSessionExpiryLocked()
}

// armSessionExpiryLocked arms the timer for the earliest deadline in the
// heap, unless it is already armed for it. s.expiry.mu must be held.
func (s *Server) armSessionExpiryLocked() {
	e := &s.expiry
	if len(e.entries) == 0 {
		if e.timer != nil {
			e.timer.Stop()
			e.timer = nil
		}
		return
	}
	next := e.entries[0].deleteAt
	if e.timer != nil && e.timerAt.Equal(next) {
		return
	}
	if e.timer != nil {
		e.timer.Stop()
	}
	delay := max(next.Sub(s.now()), 0)
	afterFunc := s.afterFunc
	if afterFunc == nil {
		afterFunc = func(d time.Duration, f func()) stopper { return time.AfterFunc(d, f) }
	}
	e.timer = afterFunc(delay, s.deleteDueSessions)
	e.timerAt = next
}

// deleteDueSessions deletes the sessions whose deadline has passed. Each
// one is read again from the Store first: one deleted meanwhile is
// skipped, and one whose ExpireTime has moved later is scheduled again for
// its new deadline. The timer calls it; then it arms the timer for the
// next deadline.
func (s *Server) deleteDueSessions() {
	now := s.now()
	s.expiry.mu.Lock()
	var due []expiryEntry
	for len(s.expiry.entries) > 0 && !s.expiry.entries[0].deleteAt.After(now) {
		due = append(due, heap.Pop(&s.expiry.entries).(expiryEntry))
	}
	if s.expiry.timer != nil {
		s.expiry.timer.Stop() // it has fired, or is superseded below
		s.expiry.timer = nil
	}
	s.expiry.mu.Unlock()

	var again []expiryEntry
	for _, entry := range due {
		session := &saml.Session{}
		if err := s.Store.Get(sessionKey(entry.sessionID), session); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // deleted meanwhile
			}
			s.logger.Printf("ERROR: cannot read session to delete it: %s", err)
			again = append(again, expiryEntry{deleteAt: now.Add(expiryRetryDelay), sessionID: entry.sessionID})
			continue
		}
		if deleteAt := sessionDeleteAt(session); deleteAt.After(now) {
			again = append(again, expiryEntry{deleteAt: deleteAt, sessionID: entry.sessionID})
			continue
		}
		if err := s.deleteSession(entry.sessionID); err != nil && !errors.Is(err, ErrNotFound) {
			s.logger.Printf("ERROR: cannot delete expired session: %s", err)
			again = append(again, expiryEntry{deleteAt: now.Add(expiryRetryDelay), sessionID: entry.sessionID})
		}
	}
	s.pushSessionExpiry(again...)
}
