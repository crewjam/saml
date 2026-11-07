package samlsp

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

func captureDefaultOnError(t *testing.T, err error) (string, *httptest.ResponseRecorder) {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	DefaultOnError(w, r, err)
	return buf.String(), w
}

func TestDefaultOnErrorLogsInvalidResponseError(t *testing.T) {
	invalid := &saml.InvalidResponseError{
		PrivateErr: errors.New("the private reason"),
		Response:   "<Response/>",
		Now:        time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	for name, err := range map[string]error{
		"direct":  invalid,
		"wrapped": fmt.Errorf("handling ACS request: %w", invalid),
	} {
		t.Run(name, func(t *testing.T) {
			logged, w := captureDefaultOnError(t, err)
			assert.Check(t, is.Contains(logged, "WARNING: received invalid saml response"))
			assert.Check(t, is.Contains(logged, "the private reason"))
			assert.Check(t, is.Contains(logged, "<Response/>"))
			assert.Check(t, is.Equal(http.StatusForbidden, w.Code))
			assert.Check(t, !bytes.Contains(w.Body.Bytes(), []byte("the private reason")))
		})
	}
}

func TestDefaultOnErrorLogsOtherErrors(t *testing.T) {
	logged, w := captureDefaultOnError(t, errors.New("something else"))
	assert.Check(t, is.Contains(logged, "ERROR: something else"))
	assert.Check(t, is.Equal(http.StatusForbidden, w.Code))
}
