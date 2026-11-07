package samlidp

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

func putSessionExpiringAt(t *testing.T, s *Server, id string, expire time.Time) {
	t.Helper()
	assert.NilError(t, s.Store.Put(sessionKey(id), &saml.Session{ID: id, NameID: id + "@example.com", ExpireTime: expire}))
	assert.NilError(t, s.AddSessionParticipant(nil, &saml.Session{ID: id}, saml.SessionParticipant{ServiceProviderID: "https://sp.example.com/metadata"}))
}

func storedSessionIDs(t *testing.T, s *Server) []string {
	t.Helper()
	ids, err := s.Store.List("/sessions/")
	assert.NilError(t, err)
	sort.Strings(ids)
	return ids
}

// Sessions that expired more than expiredSessionRetention ago are deleted
// with their participants; live and recently expired ones are kept.
func TestDeleteExpiredSessions(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	now := saml.TimeNow()
	putSessionExpiringAt(t, s, "live", now.Add(time.Hour))
	putSessionExpiringAt(t, s, "recent", now.Add(-time.Hour))
	putSessionExpiringAt(t, s, "old", now.Add(-expiredSessionRetention-time.Minute))

	assert.NilError(t, s.DeleteExpiredSessions())
	assert.Check(t, is.DeepEqual([]string{"live", "recent"}, storedSessionIDs(t, s)))
	participants, err := s.storedSessionParticipants("old")
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, 0))
	participants, err = s.storedSessionParticipants("recent")
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, 1))
}

// fakeTimers stands in for time.AfterFunc: it records the delay of each
// timer armed and whether it was stopped, and never fires.
type fakeTimers struct {
	delays  []time.Duration
	stopped int
}

type fakeTimer struct{ timers *fakeTimers }

func (t fakeTimer) Stop() bool { t.timers.stopped++; return true }

func (f *fakeTimers) afterFunc(d time.Duration, _ func()) stopper {
	f.delays = append(f.delays, d)
	return fakeTimer{f}
}

// last returns the delay of the timer armed last.
func (f *fakeTimers) last(t *testing.T) time.Duration {
	t.Helper()
	assert.Assert(t, len(f.delays) > 0, "no timer armed")
	return f.delays[len(f.delays)-1]
}

// newExpiryServer returns a server whose timers are faked and whose clock
// is *clock.
func newExpiryServer(t *testing.T) (*Server, *fakeTimers, *time.Time) {
	t.Helper()
	s := covNewServer(t, &MemoryStore{})
	timers := &fakeTimers{}
	s.afterFunc = timers.afterFunc
	clock := saml.TimeNow()
	saml.TimeNow = func() time.Time { return clock }
	return s, timers, &clock
}

// storeAndSchedule stores a session expiring at expire and schedules its
// deletion, as a login does.
func storeAndSchedule(t *testing.T, s *Server, id string, expire time.Time) {
	t.Helper()
	putSessionExpiringAt(t, s, id, expire)
	s.scheduleSessionDeletion(&saml.Session{ID: id, ExpireTime: expire})
}

// Sessions are deleted in the order they fall due, and the timer is armed
// for the earliest deadline each time.
func TestSessionExpiryOrder(t *testing.T) {
	s, timers, clock := newExpiryServer(t)
	start := *clock
	storeAndSchedule(t, s, "later", start.Add(2*time.Hour))
	assert.Check(t, is.Equal(2*time.Hour+expiredSessionRetention, timers.last(t)))
	storeAndSchedule(t, s, "sooner", start.Add(time.Hour))
	assert.Check(t, is.Equal(time.Hour+expiredSessionRetention, timers.last(t)), "re-armed for the earlier session")

	*clock = start.Add(time.Hour + expiredSessionRetention + time.Second)
	s.deleteDueSessions()
	assert.Check(t, is.DeepEqual([]string{"later"}, storedSessionIDs(t, s)))
	participants, err := s.storedSessionParticipants("sooner")
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, 0), "participants are deleted with the session")
	assert.Check(t, is.Equal(time.Hour-time.Second, timers.last(t)), "re-armed for the next session")

	*clock = start.Add(2*time.Hour + expiredSessionRetention)
	s.deleteDueSessions()
	assert.Check(t, is.Len(storedSessionIDs(t, s), 0))
	assert.Check(t, is.Len(s.expiry.entries, 0))
	assert.Check(t, s.expiry.timer == nil, "no timer once nothing is scheduled")
}

// Sessions already in the Store when the server first schedules a deletion
// are scheduled too, and one already due arms the timer to fire at once.
func TestSessionExpirySeedsStoredSessions(t *testing.T) {
	s, timers, clock := newExpiryServer(t)
	putSessionExpiringAt(t, s, "old", clock.Add(-expiredSessionRetention-time.Minute))
	putSessionExpiringAt(t, s, "live", clock.Add(time.Hour))

	storeAndSchedule(t, s, "new", clock.Add(time.Hour))
	assert.Check(t, is.Equal(time.Duration(0), timers.last(t)))
	s.deleteDueSessions()
	assert.Check(t, is.DeepEqual([]string{"live", "new"}, storedSessionIDs(t, s)))
	assert.Check(t, is.Equal(time.Hour+expiredSessionRetention, timers.last(t)))
}

// A session deleted before it falls due is skipped.
func TestSessionExpirySkipsDeletedSession(t *testing.T) {
	s, _, clock := newExpiryServer(t)
	storeAndSchedule(t, s, "gone", clock.Add(time.Hour))
	assert.NilError(t, s.deleteSession("gone"))

	*clock = clock.Add(time.Hour + expiredSessionRetention)
	s.deleteDueSessions()
	assert.Check(t, is.Len(storedSessionIDs(t, s), 0))
	assert.Check(t, is.Len(s.expiry.entries, 0))
}

// A session whose ExpireTime moved later is scheduled again for its new
// deadline instead of being deleted.
func TestSessionExpiryReschedulesExtendedSession(t *testing.T) {
	s, timers, clock := newExpiryServer(t)
	start := *clock
	storeAndSchedule(t, s, "extended", start.Add(time.Hour))
	putSessionExpiringAt(t, s, "extended", start.Add(5*time.Hour))

	*clock = start.Add(time.Hour + expiredSessionRetention)
	s.deleteDueSessions()
	assert.Check(t, is.DeepEqual([]string{"extended"}, storedSessionIDs(t, s)))
	assert.Check(t, is.Equal(4*time.Hour, timers.last(t)))

	*clock = start.Add(5*time.Hour + expiredSessionRetention)
	s.deleteDueSessions()
	assert.Check(t, is.Len(storedSessionIDs(t, s), 0))
}

// A login schedules the deletion of the session it stores.
func TestLoginSchedulesSessionDeletion(t *testing.T) {
	s, timers, _ := newExpiryServer(t)
	covPutUser(t, s)

	w := httptest.NewRecorder()
	s.ServeHTTP(w, covLoginRequest("user=alice&password=hunter2"))
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	ids := storedSessionIDs(t, s)
	assert.Assert(t, is.Len(ids, 1))
	assert.Check(t, is.Len(s.expiry.entries, 1))
	assert.Check(t, is.Equal(ids[0], s.expiry.entries[0].sessionID))
	assert.Check(t, is.Equal(sessionMaxAge+expiredSessionRetention, timers.last(t)))
}

// Looking up a session that expired long ago deletes it.
func TestLookupDeletesOldExpiredSession(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	putSessionExpiringAt(t, s, "old", saml.TimeNow().Add(-expiredSessionRetention-time.Minute))
	putSessionExpiringAt(t, s, "recent", saml.TimeNow().Add(-time.Minute))

	for _, id := range []string{"old", "recent"} {
		r := covLoginRequest("")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id}) //nolint:gosec // G124: a request cookie carries no attributes
		session, err := s.lookupSession(r)
		assert.NilError(t, err)
		assert.Check(t, session == nil)
	}
	assert.Check(t, is.DeepEqual([]string{"recent"}, storedSessionIDs(t, s)))
}
