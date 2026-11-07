package samlidp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Credentials posted by a browser from another site are refused, so that a
// page elsewhere cannot log the victim's browser in as the attacker.
func TestLoginRefusesCrossOriginCredentials(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	covPutUser(t, s)

	tests := []struct {
		name    string
		host    string
		headers map[string]string
		want    int
	}{
		{"cross-site Sec-Fetch-Site", "idp.example.com", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site Sec-Fetch-Site", "idp.example.com", map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"foreign Origin", "idp.example.com", map[string]string{"Origin": "https://evil.example.com"}, http.StatusForbidden},
		{"same-origin Sec-Fetch-Site", "idp.example.com", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"own Origin", "idp.example.com", map[string]string{"Origin": "https://idp.example.com"}, http.StatusOK},
		{"own Origin behind a proxy", "10.0.0.1:8080", map[string]string{"Origin": "https://idp.example.com"}, http.StatusOK},
		{"no browser headers", "idp.example.com", nil, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://"+tt.host+"/login", strings.NewReader("user=alice&password=hunter2"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			assert.Check(t, is.Equal(tt.want, w.Code), w.Body.String())
			if tt.want == http.StatusForbidden {
				assert.Check(t, is.Equal("", w.Header().Get("Set-Cookie")))
			}
		})
	}
}

// A cross-site POST that carries no credentials, such as an AuthnRequest
// with the HTTP-POST binding, is not refused.
func TestLoginAllowsCrossOriginPostWithoutCredentials(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	r := httptest.NewRequest(http.MethodPost, "https://idp.example.com/login", strings.NewReader("RelayState=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Contains(w.Body.String(), `name="password"`))
}
