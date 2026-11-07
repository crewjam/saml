package samlidp

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/logger"
)

// requireAdminToken is an example AdminMiddleware that also records which
// requests it saw.
func requireAdminToken(seen *[]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*seen = append(*seen, r.Method+" "+r.URL.Path)
			if r.Header.Get("Authorization") != "Bearer admin-token" {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func TestAdminMiddlewareWrapsAdminEndpoints(t *testing.T) {
	test := NewServerTest(t)
	var seen []string
	test.Server.AdminMiddleware = requireAdminToken(&seen)
	test.Server.InitializeHTTP()

	serve := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://idp.example.com"+path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		test.Server.ServeHTTP(w, r)
		return w
	}

	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/services/", ""},
		{http.MethodGet, "/services/sp", ""},
		{http.MethodPut, "/services/sp", "<x/>"},
		{http.MethodPost, "/services/sp", "<x/>"},
		{http.MethodDelete, "/services/sp", ""},
		{http.MethodGet, "/users/", ""},
		{http.MethodGet, "/users/alice", ""},
		{http.MethodPut, "/users/mallory", `{"name": "mallory", "password": "x"}`},
		{http.MethodDelete, "/users/alice", ""},
		{http.MethodGet, "/sessions/", ""},
		{http.MethodGet, "/sessions/abc", ""},
		{http.MethodDelete, "/sessions/abc", ""},
		{http.MethodGet, "/shortcuts/", ""},
		{http.MethodGet, "/shortcuts/bob", ""},
		{http.MethodPut, "/shortcuts/bob", `{"name": "bob"}`},
		{http.MethodDelete, "/shortcuts/bob", ""},
	} {
		w := serve(tc.method, tc.path, tc.body, "")
		assert.Check(t, is.Equal(http.StatusUnauthorized, w.Code), "%s %s", tc.method, tc.path)
	}
	assert.Check(t, is.Len(seen, 16))

	// The rejected PUT did not create a user.
	var user User
	assert.Check(t, is.Equal(ErrNotFound, test.Server.Store.Get("/users/mallory", &user)))

	// With the token, the request reaches the handler.
	w := serve(http.MethodPut, "/users/alice", `{"name": "alice", "password": "hunter2"}`, "admin-token")
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))
	w = serve(http.MethodGet, "/users/", "", "admin-token")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Contains(w.Body.String(), "alice"))

	// The SAML and login endpoints are not wrapped.
	seen = nil
	w = serve(http.MethodGet, "/metadata", "", "")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	serve(http.MethodGet, "/sso", "", "")
	serve(http.MethodGet, "/login", "", "")
	serve(http.MethodGet, "/login/bob", "", "")
	assert.Check(t, is.Len(seen, 0))
}

func TestNewPassesAdminMiddleware(t *testing.T) {
	test := NewServerTest(t)
	var seen []string
	s, err := New(Options{
		Certificate:     test.Certificate,
		Key:             test.Key,
		Logger:          logger.DefaultLogger,
		Store:           &MemoryStore{},
		URL:             url.URL{Scheme: "https", Host: "idp.example.com"},
		AdminMiddleware: requireAdminToken(&seen),
	})
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/users/", nil))
	assert.Check(t, is.Equal(http.StatusUnauthorized, w.Code))
	assert.Check(t, is.DeepEqual([]string{"GET /users/"}, seen))
}

func TestAdminEndpointsUnauthenticatedByDefault(t *testing.T) {
	test := NewServerTest(t)
	w := httptest.NewRecorder()
	test.Server.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/users/", nil))
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
}
