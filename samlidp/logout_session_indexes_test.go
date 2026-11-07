package samlidp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/crewjam/saml"
)

func TestSLOSeveralSessionIndexes(t *testing.T) {
	test := newSLOServerTest(t)
	session, _ := test.login(t, "alice", "alice@example.com")
	otherSession, _ := test.login(t, "alice", "alice@example.com")
	// The test random reader repeats every 256 bytes, which two logins use
	// up; skip a byte so that the third session gets an ID and an index of
	// its own.
	_, err := io.ReadFull(saml.RandReader, make([]byte, 1))
	assert.NilError(t, err)
	thirdSession, _ := test.login(t, "alice", "alice@example.com")
	assert.Assert(t, thirdSession.ID != session.ID && thirdSession.Index != session.Index)

	// Without a session cookie, every stored session of the NameID with one
	// of the request's SessionIndexes is ended.
	logoutRequest, err := test.SP.MakeLogoutRequest(test.Server.IDP.LogoutURL.String(), session.NameID,
		saml.WithSessionIndexes(session.Index, otherSession.Index))
	assert.NilError(t, err)
	u, err := test.SP.RedirectLogoutRequestURL(logoutRequest, "")
	assert.NilError(t, err)
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.Equal(t, http.StatusFound, w.Code, w.Body.String())
	assert.Check(t, !test.sessionExists(t, session.ID))
	assert.Check(t, !test.sessionExists(t, otherSession.ID))
	assert.Check(t, test.sessionExists(t, thirdSession.ID))
}
