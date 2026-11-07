package samlidp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// TestOptionsClock checks that Options.Clock is used for the
// IdentityProvider and for login sessions instead of the deprecated
// package-level saml.TimeNow and saml.Clock.
func TestOptionsClock(t *testing.T) {
	oldTimeNow, oldClock := saml.TimeNow, saml.Clock
	t.Cleanup(func() { saml.TimeNow, saml.Clock = oldTimeNow, oldClock })
	wrong := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	saml.TimeNow = func() time.Time { return wrong }
	saml.Clock = dsig.NewFakeClockAt(wrong)

	test := NewServerTest(t) // sets saml.TimeNow; restore the wrong time
	saml.TimeNow = func() time.Time { return wrong }

	now := time.Date(2020, 6, 1, 12, 0, 0, 0, time.UTC)
	clock := dsig.NewFakeClockAt(now)
	server, err := New(Options{
		Certificate: test.Certificate,
		Key:         test.Key,
		Logger:      logger.DefaultLogger,
		Store:       &MemoryStore{},
		URL:         url.URL{Scheme: "https", Host: "idp.example.com"},
		Clock:       clock,
	})
	assert.NilError(t, err)
	assert.Check(t, server.IDP.Clock == clock)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "https://idp.example.com/users/alice",
		strings.NewReader(`{"name": "alice", "password": "hunter2"}`))
	server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "https://idp.example.com/login",
		strings.NewReader("user=alice&password=hunter2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code))
	cookies := w.Result().Cookies()
	assert.Assert(t, is.Len(cookies, 1))

	session := saml.Session{}
	assert.NilError(t, server.Store.Get("/sessions/"+cookies[0].Value, &session))
	assert.Check(t, is.Equal(now, session.CreateTime.UTC()))
	assert.Check(t, is.Equal(now.Add(sessionMaxAge), session.ExpireTime.UTC()))

	lookup := func() *saml.Session {
		r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/login", nil)
		r.AddCookie(cookies[0])
		s, err := server.lookupSession(r)
		assert.NilError(t, err)
		return s
	}
	assert.Check(t, lookup() != nil)

	server.IDP.Clock = dsig.NewFakeClockAt(now.Add(sessionMaxAge + time.Second))
	assert.Check(t, lookup() == nil)
}
