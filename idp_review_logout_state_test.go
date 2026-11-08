package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	assert.NilError(t, err)
	return hex.EncodeToString(buf)
}

// logoutStateWith returns a logout state with n pending participants, each
// with its own entity ID and transient NameID.
func logoutStateWith(t *testing.T, n int, random bool) *logoutState {
	t.Helper()
	state := &logoutState{Expires: TimeNow().Add(LogoutStateLifetime), ReturnURL: "https://idp.example.com/done"}
	for i := 0; i < n; i++ {
		entityID := fmt.Sprintf("https://sp%d.example.com/saml2/metadata", i)
		nameID := "alice@example.com"
		if random {
			entityID = "https://" + randomHex(t, 12) + ".example.com/saml2/metadata"
			nameID = randomHex(t, 20)
		}
		state.Pending = append(state.Pending, SessionParticipant{
			ServiceProviderID: entityID,
			NameID: NameID{
				Format:          string(TransientNameIDFormat),
				NameQualifier:   "https://idp.example.com/saml/metadata",
				SPNameQualifier: entityID,
				Value:           nameID,
			},
			SessionIndex: "idp-session-index-" + randomHex(t, 8),
		})
	}
	return state
}

func setStateCookie(t *testing.T, idp *IdentityProvider, state *logoutState) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	assert.NilError(t, idp.setLogoutStateCookie(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil), state))
	cookies := w.Result().Cookies()
	assert.Assert(t, is.Len(cookies, 1))
	return cookies[0]
}

// A dozen participants used to make a cookie of over 6 KB, which browsers
// drop. The state is now deflated.
func TestLogoutStateCookieIsCompact(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	state := logoutStateWith(t, 12, false)
	cookie := setStateCookie(t, &test.IDP, state)
	assert.Check(t, len(cookie.Value) <= maxLogoutStateCookieValue, "%d bytes", len(cookie.Value))
	assert.Check(t, is.Len(state.Pending, 12))
	assert.Check(t, !state.partial())

	decoded, err := test.IDP.decodeLogoutState(cookie.Value)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(state.Pending, decoded.Pending))
	assert.Check(t, is.Equal(state.ReturnURL, decoded.ReturnURL))
}

// When the state still does not fit, the last participants are given up on
// and reported as failed, rather than setting a cookie the browser drops.
func TestLogoutStateCookieGivesUpOnParticipantsThatDoNotFit(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	state := logoutStateWith(t, 200, true)
	cookie := setStateCookie(t, &test.IDP, state)
	assert.Check(t, len(cookie.Value) <= maxLogoutStateCookieValue, "%d bytes", len(cookie.Value))
	assert.Check(t, len(state.Pending) > 0 && len(state.Pending) < 200, "%d pending", len(state.Pending))
	assert.Check(t, is.Equal(200, len(state.Pending)+state.Dropped))

	decoded, err := test.IDP.decodeLogoutState(cookie.Value)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(state.Dropped, decoded.Dropped))
	assert.Check(t, decoded.partial())
}

// A state written before it was deflated (plain base64 JSON, no prefix) is
// still read, so a logout in progress during an upgrade carries on.
func TestLogoutStateUndeflatedIsRead(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	state := &logoutState{Expires: TimeNow().Add(time.Minute), ReturnURL: "https://idp.example.com/done"}
	payload, err := json.Marshal(state)
	assert.NilError(t, err)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signer, err := test.IDP.logoutStateSigner()
	assert.NilError(t, err)
	digest := sha256.Sum256([]byte(logoutStateSignaturePrefix + encoded))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	assert.NilError(t, err)

	decoded, err := test.IDP.decodeLogoutState(encoded + "." + base64.RawURLEncoding.EncodeToString(signature))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(state.ReturnURL, decoded.ReturnURL))
}
