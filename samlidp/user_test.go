package samlidp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsersCrud(t *testing.T) {
	test := NewServerTest()
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/users/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"users\":[]}\n", string(w.Body.Bytes()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/users/alice",
		strings.NewReader(`{"name": "alice", "password": "hunter2"}`+"\n"))
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/users/alice", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"name\":\"alice\"}\n", string(w.Body.Bytes()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/users/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"users\":[\"alice\"]}\n", string(w.Body.Bytes()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("DELETE", "https://idp.example.com/users/alice", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/users/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"users\":[]}\n", string(w.Body.Bytes()))
}
