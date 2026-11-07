package samlidp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// TestGetSessionEmailNameIDFormat checks that a session whose NameID is the
// user's email address says so, instead of letting the assertion claim the
// transient format for a stable value (saml-core §8.3.8, issue #784).
func TestGetSessionEmailNameIDFormat(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	covPutUser(t, s)

	r := covLoginRequest("user=alice&password=hunter2")
	assert.NilError(t, r.ParseForm())
	session := s.GetSession(httptest.NewRecorder(), r, &saml.IdpAuthnRequest{IDP: &s.IDP})
	assert.Assert(t, session != nil)
	assert.Check(t, is.Equal("alice@example.com", session.NameID))
	assert.Check(t, is.Equal(string(saml.EmailAddressNameIDFormat), session.NameIDFormat))
}

// TestGetSessionNoEmailKeepsDefaultNameIDFormat checks that a user with no
// email address keeps the default format.
func TestGetSessionNoEmailKeepsDefaultNameIDFormat(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	w := covServe(s, "PUT", "/users/alice", `{"password": "hunter2"}`)
	assert.Assert(t, is.Equal(http.StatusNoContent, w.Code))

	r := covLoginRequest("user=alice&password=hunter2")
	assert.NilError(t, r.ParseForm())
	session := s.GetSession(httptest.NewRecorder(), r, &saml.IdpAuthnRequest{IDP: &s.IDP})
	assert.Assert(t, session != nil)
	assert.Check(t, is.Equal("", session.NameID))
	assert.Check(t, is.Equal("", session.NameIDFormat))
}
