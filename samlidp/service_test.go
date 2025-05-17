package samlidp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

func TestServicesCrud(t *testing.T) {
	test := NewServerTest(t)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"services\":[]}\n", w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/services/sp",
		bytes.NewReader(golden.Get(t, "sp_metadata.xml")))
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/sp", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	golden.Assert(t, w.Body.String(), "sp_metadata.xml")

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"services\":[\"sp\"]}\n", w.Body.String()))

	assert.Check(t, is.Len(test.Server.serviceProviders, 2))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("DELETE", "https://idp.example.com/services/sp", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/services/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"services\":[]}\n", w.Body.String()))
	assert.Check(t, is.Len(test.Server.serviceProviders, 1))
}
