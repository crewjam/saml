package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A signed AuthnRequest is answered with an assertion once; a replay of
// it is refused. The ID is recorded only when a session is returned.
func TestIDPServeSSORefusesReplayedSignedAuthnRequest(t *testing.T) {
	test := newSignedAuthnRequestTest(t)
	cache := memoryReplayCache{}
	test.IDP.ReplayCache = cache
	sessions := 0
	var session *Session
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
			sessions++
			if session == nil {
				http.Error(w, "log in", http.StatusUnauthorized)
			}
			return session
		},
	}
	var lastErr error
	test.IDP.OnError = func(w http.ResponseWriter, _ *http.Request, status int, err error) {
		lastErr = err
		http.Error(w, http.StatusText(status), status)
	}

	redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	serve := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, redirectURL.String(), nil))
		return w
	}

	// A login form is shown: nothing is recorded.
	assert.Check(t, is.Equal(http.StatusUnauthorized, serve().Code))
	assert.Check(t, is.Len(cache, 0))

	session = &Session{ID: "s", UserName: "alice"}
	assert.Check(t, is.Equal(http.StatusOK, serve().Code))
	assert.Check(t, is.Len(cache, 1))

	assert.Check(t, is.Equal(http.StatusBadRequest, serve().Code))
	assert.Check(t, errors.Is(lastErr, ErrAssertionReplayed), "%v", lastErr)
	assert.Check(t, is.Equal(3, sessions))
}

// Unsigned AuthnRequests are not recorded.
func TestIDPServeSSODoesNotRecordUnsignedAuthnRequests(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	cache := memoryReplayCache{}
	test.IDP.ReplayCache = cache
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{ID: "s", UserName: "alice"}
		},
	}
	redirectURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, redirectURL.String(), nil))
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
	}
	assert.Check(t, is.Len(cache, 0))
}
