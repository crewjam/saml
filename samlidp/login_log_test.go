package samlidp

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A username with a newline cannot forge a log line.
func TestLoginLogsUsernameQuoted(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	var logged bytes.Buffer
	s.logger = log.New(&logged, "", 0)

	form := url.Values{"user": {"mallory\nUser 'admin' authenticated successfully"}, "password": {"x"}}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, covLoginRequest(form.Encode()))
	assert.Check(t, is.Equal(http.StatusOK, w.Code))

	lines := strings.Split(strings.TrimSpace(logged.String()), "\n")
	assert.Check(t, is.Len(lines, 1), logged.String())
	assert.Check(t, is.Contains(lines[0], `"mallory\nUser 'admin' authenticated successfully"`))
}
