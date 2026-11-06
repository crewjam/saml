package samlidp

import (
	"crypto/tls"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/crewjam/saml"
)

const covLoginForm = `<html><p></p><form method="post" action="https://idp.example.com/login">`

func covLoginRequest(body string) *http.Request {
	r := httptest.NewRequest("POST", "https://idp.example.com/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func covPutUser(t *testing.T, s *Server) {
	t.Helper()
	w := covServe(s, "PUT", "/users/alice", `{"password": "hunter2", "email": "alice@example.com", "groups": ["admins"]}`)
	assert.Assert(t, is.Equal(http.StatusNoContent, w.Code))
}

func TestCovHandleLoginBadForm(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, covLoginRequest("user=%zz"))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
}

func TestCovHandleLoginNoCredentials(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	w := covServe(s, "GET", "/login", "")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, strings.HasPrefix(w.Body.String(), covLoginForm), w.Body.String())
}

func TestCovHandleLoginEncodeError(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	covPutUser(t, s)
	w := &covFailWriter{}
	s.ServeHTTP(w, covLoginRequest("user=alice&password=hunter2"))
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.code))
}

func TestCovGetSessionPutError(t *testing.T) {
	store := &covStore{}
	s := covNewServer(t, store)
	covPutUser(t, s)
	store.putErr = covAlways

	w := httptest.NewRecorder()
	s.ServeHTTP(w, covLoginRequest("user=alice&password=hunter2"))
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	assert.Check(t, is.Equal("", w.Header().Get("Set-Cookie")))
}

func TestCovGetSessionPopulatesUserFields(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	covPutUser(t, s)

	w := httptest.NewRecorder()
	r := covLoginRequest("user=alice&password=hunter2")
	assert.NilError(t, r.ParseForm())
	session := s.GetSession(w, r, &saml.IdpAuthnRequest{IDP: &s.IDP})
	assert.Assert(t, session != nil)
	assert.Check(t, is.Equal("alice@example.com", session.NameID))
	assert.Check(t, is.Equal("alice@example.com", session.UserEmail))
	assert.Check(t, is.DeepEqual([]string{"admins"}, session.Groups))
	assert.Check(t, is.Equal(saml.TimeNow().Add(time.Hour), session.ExpireTime))
}

func TestCovGetSessionSecureCookieOverTLS(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	covPutUser(t, s)

	// A server-side request carries no scheme in r.URL; the cookie must still
	// be marked Secure when the request arrived over TLS.
	r := covLoginRequest("user=alice&password=hunter2")
	r.URL.Scheme = ""
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, strings.Contains(w.Header().Get("Set-Cookie"), "Secure"), w.Header().Get("Set-Cookie"))

	// plain http: not Secure
	r = httptest.NewRequest("POST", "http://idp.example.com/login", strings.NewReader("user=alice&password=hunter2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, !strings.Contains(w.Header().Get("Set-Cookie"), "Secure"), w.Header().Get("Set-Cookie"))
}

func TestCovGetSessionCookieStoreError(t *testing.T) {
	store := &covStore{getErr: covAlways}
	s := covNewServer(t, store)
	r := httptest.NewRequest("GET", "https://idp.example.com/login", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestCovGetSessionUnknownCookie(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	r := httptest.NewRequest("GET", "https://idp.example.com/login", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, strings.HasPrefix(w.Body.String(), covLoginForm), w.Body.String())
}

func TestCovGetSessionExpired(t *testing.T) {
	store := &MemoryStore{}
	s := covNewServer(t, store)
	assert.NilError(t, store.Put("/sessions/old", &saml.Session{
		ID:         "old",
		ExpireTime: saml.TimeNow().Add(-time.Second),
	}))
	r := httptest.NewRequest("GET", "https://idp.example.com/login", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "old"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, strings.HasPrefix(w.Body.String(), covLoginForm), w.Body.String())
}

func TestCovSendLoginFormCustomTemplate(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	s.LoginFormTemplate = template.Must(template.New("x").Parse(
		`toast={{.Toast}} url={{.URL}} req={{.SAMLRequest}} rs={{.RelayState}}`))
	w := httptest.NewRecorder()
	s.sendLoginForm(w, &saml.IdpAuthnRequest{
		IDP:           &s.IDP,
		RequestBuffer: []byte("hi"),
		RelayState:    "state",
	}, "oops")
	assert.Check(t, is.Equal("toast=oops url=https://idp.example.com/login req=aGk= rs=state", w.Body.String()))
}

func TestCovSendLoginFormTemplateErrorPanics(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	s.LoginFormTemplate = template.Must(template.New("x").Parse(`{{.NoSuchField}}`))
	defer func() {
		r := recover()
		err, ok := r.(error)
		assert.Check(t, ok, "expected error panic, got %v", r)
		assert.Check(t, err != nil && strings.Contains(err.Error(), "NoSuchField"))
	}()
	s.sendLoginForm(httptest.NewRecorder(), &saml.IdpAuthnRequest{IDP: &s.IDP}, "")
	t.Fatal("expected panic")
}

func TestCovIDPInitiatedRelayState(t *testing.T) {
	store := &MemoryStore{}
	s := covNewServer(t, store)
	w := covServe(s, "PUT", "/services/sp", string(golden.Get(t, "sp_metadata.xml")))
	assert.Assert(t, is.Equal(http.StatusNoContent, w.Code))
	var spID string
	for k := range s.serviceProviders {
		spID = k
	}
	assert.NilError(t, store.Put("/sessions/sess", &saml.Session{
		ID:         "sess",
		NameID:     "alice@example.com",
		CreateTime: saml.TimeNow(),
		ExpireTime: saml.TimeNow().Add(time.Hour),
		Index:      "1",
	}))
	fixed := "fixed-state"
	assert.NilError(t, store.Put("/shortcuts/fixed", &Shortcut{ServiceProviderID: spID, RelayState: &fixed, URISuffixAsRelayState: true}))
	assert.NilError(t, store.Put("/shortcuts/suffix", &Shortcut{ServiceProviderID: spID, URISuffixAsRelayState: true}))
	assert.NilError(t, store.Put("/shortcuts/none", &Shortcut{ServiceProviderID: spID}))

	relayState := func(target string) string {
		t.Helper()
		r := httptest.NewRequest("GET", target, nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: "sess"})
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
		body := w.Body.String()
		const marker = `name="RelayState" value="`
		i := strings.Index(body, marker)
		assert.Assert(t, i >= 0, body)
		value, _, found := strings.Cut(body[i+len(marker):], `"`)
		assert.Assert(t, found, body)
		return value
	}

	assert.Check(t, is.Equal("fixed-state", relayState("https://idp.example.com/login/fixed/ignored")))
	assert.Check(t, is.Equal("/whoami", relayState("https://idp.example.com/login/suffix/whoami")))
	assert.Check(t, is.Equal("", relayState("https://idp.example.com/login/suffix")))
	assert.Check(t, is.Equal("", relayState("https://idp.example.com/login/none/whoami")))
}
