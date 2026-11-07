package saml

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

type responseWriterFunc func(w http.ResponseWriter, req *IdpAuthnRequest) error

func (f responseWriterFunc) WriteResponse(w http.ResponseWriter, req *IdpAuthnRequest) error {
	return f(w, req)
}

func newExistingSessionIDPTest(t *testing.T) *IdentityProviderTest {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}
	return test
}

// customFormWriter writes the form values as plain text, so tests can tell
// its output from the default HTML form.
func customFormWriter(calls *int) ResponseWriter {
	return responseWriterFunc(func(w http.ResponseWriter, req *IdpAuthnRequest) error {
		*calls++
		form, err := req.PostBinding()
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusAccepted)
		_, err = fmt.Fprintf(w, "url=%s relay=%s has_response=%t", form.URL, form.RelayState, form.SAMLResponse != "")
		return err
	})
}

func TestIDPResponseWriterServeSSO(t *testing.T) {
	test := newExistingSessionIDPTest(t)
	calls := 0
	test.IDP.ResponseWriter = customFormWriter(&calls)

	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	assert.NilError(t, err)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	test.IDP.ServeSSO(w, r)

	assert.Check(t, is.Equal(1, calls))
	assert.Check(t, is.Equal(http.StatusAccepted, w.Code))
	assert.Check(t, is.Equal("text/plain", w.Header().Get("Content-Type")))
	assert.Check(t, is.Equal("url=https://sp.example.com/saml2/acs relay=ThisIsTheRelayState has_response=true", w.Body.String()))
}

func TestIDPResponseWriterServeIDPInitiated(t *testing.T) {
	test := newExistingSessionIDPTest(t)
	calls := 0
	test.IDP.ResponseWriter = customFormWriter(&calls)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "ThisIsTheRelayState")

	assert.Check(t, is.Equal(1, calls))
	assert.Check(t, is.Equal(http.StatusAccepted, w.Code))
	assert.Check(t, is.Equal("url=https://sp.example.com/saml2/acs relay=ThisIsTheRelayState has_response=true", w.Body.String()))
}

func TestIDPResponseWriterError(t *testing.T) {
	failing := responseWriterFunc(func(_ http.ResponseWriter, _ *IdpAuthnRequest) error {
		return errors.New("cannot write")
	})

	t.Run("ServeSSO", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		test.IDP.ResponseWriter = failing
		requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
		assert.NilError(t, err)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", requestURL.String(), nil)
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	})

	t.Run("ServeIDPInitiated", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		test.IDP.ResponseWriter = failing
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "ThisIsTheRelayState")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	})
}

// TestIDPDefaultResponseWriter checks that setting DefaultResponseWriter
// explicitly produces the same output as leaving ResponseWriter nil, which
// TestIDPCanHandleRequestWithExistingSession and
// TestIDPIDPInitiatedExistingSession pin with golden files.
func TestIDPDefaultResponseWriter(t *testing.T) {
	t.Run("ServeSSO", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		test.IDP.ResponseWriter = DefaultResponseWriter{}
		requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
		assert.NilError(t, err)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", requestURL.String(), nil)
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
		golden.Assert(t, w.Body.String(), "TestIDPCanHandleRequestWithExistingSession_http_response_body")
	})

	t.Run("ServeIDPInitiated", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		test.IDP.ResponseWriter = DefaultResponseWriter{}
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "ThisIsTheRelayState")
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
		golden.Assert(t, w.Body.String(), "TestIDPIDPInitiatedExistingSession_response")
	})
}
