package samlidp

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Requests for items that do not exist are answered with 404 Not Found,
// without logging an error.
func TestUnknownItemsAreNotFound(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	var logged bytes.Buffer
	s.logger = log.New(&logged, "", 0)

	for _, target := range []string{
		"/users/nobody",
		"/shortcuts/nothing",
		"/services/nothing",
		"/sessions/nothing",
		"/login/nothing",
		"/login/nothing/suffix",
	} {
		w := covServe(s, http.MethodGet, target, "")
		assert.Check(t, is.Equal(http.StatusNotFound, w.Code), target)
	}
	w := covServe(s, http.MethodDelete, "/services/nothing", "")
	assert.Check(t, is.Equal(http.StatusNotFound, w.Code))
	assert.Check(t, !strings.Contains(logged.String(), "ERROR"), logged.String())
}
