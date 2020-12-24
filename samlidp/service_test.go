package samlidp

import (
	"bytes"
	"gotest.tools/golden"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServicesCrud(t *testing.T) {
	test := NewServerTest(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"services\":[]}\n", string(w.Body.Bytes()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/services/sp",
		bytes.NewReader(golden.Get(t, "sp_metadata.xml")))
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/sp", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, w.Body.String(), string(golden.Get(t, "sp_metadata.xml")))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"services\":[\"sp\"]}\n", string(w.Body.Bytes()))

	assert.Len(t, test.Server.serviceProviders, 2)

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("DELETE", "https://idp.example.com/services/sp", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusNoContent, w.Code)

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "{\"services\":[]}\n", string(w.Body.Bytes()))
	assert.Len(t, test.Server.serviceProviders, 1)
}
