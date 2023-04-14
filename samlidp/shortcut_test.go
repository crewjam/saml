package samlidp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestShortcutsCrud(t *testing.T) {
	test := NewServerTest(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/shortcuts/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"shortcuts\":[]}\n",
		w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/shortcuts/bob",
		strings.NewReader("{\"url_suffix_as_relay_state\": true, \"service_provider\": \"https://example.com/saml2/metadata\"}"))
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/shortcuts/bob", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"name\":\"bob\",\"service_provider\":\"https://example.com/saml2/metadata\",\"url_suffix_as_relay_state\":true}\n",
		w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/shortcuts/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"shortcuts\":[\"bob\"]}\n",
		w.Body.String()))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("DELETE", "https://idp.example.com/shortcuts/bob", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/shortcuts/", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("{\"shortcuts\":[]}\n",
		w.Body.String()))
}

func TestShortcut(t *testing.T) {
	test := NewServerTest(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("PUT", "https://idp.example.com/shortcuts/bob",
		strings.NewReader("{\"url_suffix_as_relay_state\": true, \"service_provider\": \"https://sp.example.com/saml2/metadata\"}"))
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("PUT", "https://idp.example.com/users/alice",
		strings.NewReader(`{"name": "alice", "password": "hunter2"}`+"\n"))
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusNoContent, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "https://idp.example.com/login",
		strings.NewReader("user=alice&password=hunter2"))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/login/bob/whoami", nil)
	r.Header.Set("Cookie", "session=AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD4=")
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	body := w.Body.String()

	assert.Check(t, strings.Contains(body,
		"<input type=\"hidden\" name=\"RelayState\" value=\"/whoami\" />"),
		body)
	assert.Check(t, strings.Contains(body,
		"<script>document.getElementById('SAMLResponseForm').submit();</script>"),
		body)
}
