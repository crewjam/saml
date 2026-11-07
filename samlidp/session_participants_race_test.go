package samlidp

import (
	"fmt"
	"sync"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// Service providers logging in on the same session at the same time are
// all recorded as participants.
func TestAddSessionParticipantConcurrently(t *testing.T) {
	test := NewServerTest(t)
	session := &saml.Session{ID: "session-1"}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := test.Server.AddSessionParticipant(nil, session, saml.SessionParticipant{
				ServiceProviderID: fmt.Sprintf("https://sp%d.example.com/metadata", i),
			})
			assert.Check(t, err)
		}(i)
	}
	wg.Wait()

	participants, err := test.Server.storedSessionParticipants(session.ID)
	assert.NilError(t, err)
	assert.Check(t, is.Len(participants, n))
}

// Recording the same participant again stores it once.
func TestAddSessionParticipantTwice(t *testing.T) {
	test := NewServerTest(t)
	session := &saml.Session{ID: "session-1"}
	participant := saml.SessionParticipant{ServiceProviderID: "https://sp.example.com/metadata", SessionIndex: "1"}
	assert.NilError(t, test.Server.AddSessionParticipant(nil, session, participant))
	assert.NilError(t, test.Server.AddSessionParticipant(nil, session, participant))

	participants, err := test.Server.storedSessionParticipants(session.ID)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual([]saml.SessionParticipant{participant}, participants))
}

// Participants stored by an older version, as one list per session, are
// still read alongside new ones, and deleted with the session.
func TestSessionParticipantsLegacyList(t *testing.T) {
	test := NewServerTest(t)
	session := &saml.Session{ID: "session-1"}
	legacy := saml.SessionParticipant{ServiceProviderID: "https://old.example.com/metadata"}
	recorded := saml.SessionParticipant{ServiceProviderID: "https://new.example.com/metadata"}
	assert.NilError(t, test.Server.Store.Put(legacySessionParticipantsKey(session.ID), []saml.SessionParticipant{legacy}))
	assert.NilError(t, test.Server.AddSessionParticipant(nil, session, legacy))
	assert.NilError(t, test.Server.AddSessionParticipant(nil, session, recorded))

	participants, err := test.Server.storedSessionParticipants(session.ID)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual([]saml.SessionParticipant{legacy, recorded}, participants))

	assert.NilError(t, test.Server.Store.Put(sessionKey(session.ID), session))
	assert.NilError(t, test.Server.deleteSession(session.ID))
	keys, err := test.Server.Store.List("/session-participants/")
	assert.NilError(t, err)
	assert.Check(t, is.Len(keys, 0))
}
