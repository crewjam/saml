package samlidp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// covServe runs a request through the server's mux and returns the status code.
func covServe(s *Server, method, target, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	s.ServeHTTP(w, r)
	return w
}

// covServeFailWriter runs a request through the server's mux with a response
// writer that fails all body writes, and returns the status code.
func covServeFailWriter(s *Server, method, target, body string) int {
	w := &covFailWriter{}
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	s.ServeHTTP(w, r)
	return w.code
}

func TestCovListHandlersStoreErrors(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	s.Store = &covStore{listErr: covAlways}
	for _, target := range []string{"/services/", "/users/", "/sessions/", "/shortcuts/"} {
		w := covServe(s, "GET", target, "")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code), target)
	}
}

func TestCovListHandlersWriteErrors(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	for _, target := range []string{"/services/", "/users/", "/sessions/", "/shortcuts/"} {
		assert.Check(t, is.Equal(http.StatusInternalServerError,
			covServeFailWriter(s, "GET", target, "")), target)
	}
}

func TestCovGetHandlersStoreErrors(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	s.Store = &covStore{getErr: covAlways}
	for _, target := range []string{"/services/x", "/users/x", "/sessions/x", "/shortcuts/x", "/login/x"} {
		w := covServe(s, "GET", target, "")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code), target)
	}
	// delete service looks up the service first
	w := covServe(s, "DELETE", "/services/x", "")
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestCovGetHandlersWriteErrors(t *testing.T) {
	store := &MemoryStore{}
	s := covNewServer(t, store)
	assert.NilError(t, store.Put("/services/x", &Service{Name: "x"}))
	assert.NilError(t, store.Put("/users/x", &User{Name: "x"}))
	assert.NilError(t, store.Put("/sessions/x", map[string]string{"ID": "x"}))
	assert.NilError(t, store.Put("/shortcuts/x", &Shortcut{Name: "x"}))
	for _, target := range []string{"/services/x", "/users/x", "/sessions/x", "/shortcuts/x"} {
		assert.Check(t, is.Equal(http.StatusInternalServerError,
			covServeFailWriter(s, "GET", target, "")), target)
	}
}

func TestCovDeleteHandlersStoreErrors(t *testing.T) {
	store := &covStore{}
	s := covNewServer(t, store)
	assert.NilError(t, store.Put("/services/x", &Service{Name: "x"}))
	store.deleteErr = covAlways
	for _, target := range []string{"/services/x", "/users/x", "/sessions/x", "/shortcuts/x"} {
		w := covServe(s, "DELETE", target, "")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code), target)
	}
}

func TestCovPutHandlersStoreErrors(t *testing.T) {
	store := &covStore{putErr: covAlways}
	s := covNewServer(t, store)

	w := covServe(s, "PUT", "/services/sp", string(golden.Get(t, "sp_metadata.xml")))
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	assert.Check(t, is.Len(s.serviceProviders, 0))

	w = covServe(s, "PUT", "/users/alice", `{"password": "hunter2"}`)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))

	w = covServe(s, "PUT", "/shortcuts/bob", `{"service_provider": "https://sp.example.com/saml2/metadata"}`)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestCovPutHandlersBadRequest(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})

	w := covServe(s, "PUT", "/services/sp", "<EntityDescriptor")
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))

	w = covServe(s, "POST", "/services/sp", "not xml")
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))

	w = covServe(s, "PUT", "/users/alice", "{")
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))

	w = covServe(s, "PUT", "/shortcuts/bob", "{")
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
}

func TestCovPutServiceViaPOST(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/services/sp", bytes.NewReader(golden.Get(t, "sp_metadata.xml")))
	s.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	assert.Check(t, is.Len(s.serviceProviders, 1))
}

func TestCovPutUserPasswordHandling(t *testing.T) {
	store := &covStore{}
	s := covNewServer(t, store)

	// password too long for bcrypt
	w := covServe(s, "PUT", "/users/alice", `{"password": "`+strings.Repeat("x", 73)+`"}`)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))

	// new user without a password
	w = covServe(s, "PUT", "/users/carol", `{"email": "carol@example.com"}`)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	carol := User{}
	assert.NilError(t, store.Get("/users/carol", &carol))
	assert.Check(t, is.Equal("carol", carol.Name))
	assert.Check(t, is.Len(carol.HashedPassword, 0))

	// set a password, then update without one: the hash is retained
	w = covServe(s, "PUT", "/users/alice", `{"password": "hunter2"}`)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	before := User{}
	assert.NilError(t, store.Get("/users/alice", &before))
	assert.Check(t, len(before.HashedPassword) > 0)
	assert.Check(t, before.PlaintextPassword == nil)

	w = covServe(s, "PUT", "/users/alice", `{"email": "alice@example.com"}`)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	after := User{}
	assert.NilError(t, store.Get("/users/alice", &after))
	assert.Check(t, is.DeepEqual(before.HashedPassword, after.HashedPassword))
	assert.Check(t, is.Equal("alice@example.com", after.Email))

	// GET never exposes the hash
	w = covServe(s, "GET", "/users/alice", "")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, !strings.Contains(w.Body.String(), "hashed_password"), w.Body.String())

	// lookup of the existing user fails
	store.getErr = covAlways
	w = covServe(s, "PUT", "/users/alice", `{"email": "alice@example.com"}`)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestCovDeleteServiceRemovesProvider(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	w := covServe(s, "PUT", "/services/sp", string(golden.Get(t, "sp_metadata.xml")))
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	assert.Check(t, is.Len(s.serviceProviders, 1))

	w = covServe(s, "DELETE", "/services/sp", "")
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	assert.Check(t, is.Len(s.serviceProviders, 0))

	// deleting a service that does not exist is reported as not found
	w = covServe(s, "DELETE", "/services/sp", "")
	assert.Check(t, is.Equal(http.StatusNotFound, w.Code))
}
