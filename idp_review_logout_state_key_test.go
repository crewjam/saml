package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func testLogoutStateKey(b byte) []byte {
	return bytes.Repeat([]byte{b}, 32)
}

// nameIDsOf returns the NameID values of the pending participants of state.
func nameIDsOf(state *logoutState) []string {
	values := make([]string, 0, len(state.Pending))
	for _, p := range state.Pending {
		if p.NameID != nil {
			values = append(values, p.NameID.Value)
		}
	}
	return values
}

// With LogoutStateKey the whole logout state cookie is encrypted: it holds
// no NameID in the clear, and has room for as many participants as an
// unencrypted one, also with EncryptLogoutNameID.
func TestLogoutStateCookieEncryptedWithKey(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.LogoutStateKey = testLogoutStateKey(1)
	test.IDP.EncryptLogoutNameID = true
	state := logoutStateWith(t, 40, true)
	nameIDs := nameIDsOf(state)
	cookie := setStateCookie(t, &test.IDP, state)
	assert.Check(t, len(cookie.Value) <= maxLogoutStateCookieValue, "%d bytes", len(cookie.Value))
	assert.Check(t, is.Len(state.Pending, 40))
	assert.Check(t, is.Equal(0, state.Dropped))
	assert.Assert(t, strings.HasPrefix(cookie.Value, logoutStateEncryptedPrefix))

	// Neither the cookie nor what its body would inflate to holds a NameID.
	encoded, _, _ := strings.Cut(strings.TrimPrefix(cookie.Value, logoutStateEncryptedPrefix), ".")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	assert.NilError(t, err)
	inflated, _ := io.ReadAll(newSaferFlateReader(bytes.NewReader(raw)))
	for _, nameID := range nameIDs {
		assert.Check(t, !strings.Contains(cookie.Value, nameID))
		assert.Check(t, !bytes.Contains(raw, []byte(nameID)))
		assert.Check(t, !bytes.Contains(inflated, []byte(nameID)))
	}

	decoded, err := test.IDP.decodeLogoutState(cookie.Value)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(state.Pending, decoded.Pending))
	assert.Check(t, is.DeepEqual(nameIDs, nameIDsOf(decoded)))

	// Another key, or none, cannot read it.
	test.IDP.LogoutStateKey = testLogoutStateKey(2)
	_, err = test.IDP.decodeLogoutState(cookie.Value)
	assert.Check(t, is.ErrorContains(err, "another LogoutStateKey"))
	test.IDP.LogoutStateKey = nil
	_, err = test.IDP.decodeLogoutState(cookie.Value)
	assert.Check(t, is.ErrorContains(err, "LogoutStateKey is not set"))
}

// The encrypted state is still signed, and its ciphertext authenticated.
func TestLogoutStateEncryptedIsAuthenticated(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.LogoutStateKey = testLogoutStateKey(1)
	state := logoutStateWith(t, 2, false)
	sealed, err := test.IDP.sealLogoutState([]byte("state"))
	assert.NilError(t, err)
	opened, err := test.IDP.openLogoutState(sealed)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("state", string(opened)))
	sealed[len(sealed)-1] ^= 1
	_, err = test.IDP.openLogoutState(sealed)
	assert.Check(t, is.ErrorContains(err, "cannot decrypt"))
	sealed[len(sealed)-1] ^= 1
	sealed[0] = 2
	_, err = test.IDP.openLogoutState(sealed)
	assert.Check(t, is.ErrorContains(err, "unknown version"))

	cookie := setStateCookie(t, &test.IDP, state)
	tampered := strings.Replace(cookie.Value, logoutStateEncryptedPrefix+"A", logoutStateEncryptedPrefix+"B", 1)
	if tampered == cookie.Value {
		tampered = strings.Replace(cookie.Value, logoutStateEncryptedPrefix, logoutStateEncryptedPrefix+"A", 1)
	}
	_, err = test.IDP.decodeLogoutState(tampered)
	assert.Check(t, is.ErrorContains(err, "signature"))
}

// A key that is not 32 bytes long is refused rather than used.
func TestLogoutStateKeyLength(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.LogoutStateKey = make([]byte, 16)
	w := httptest.NewRecorder()
	err := test.IDP.setLogoutStateCookie(w, httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/slo", nil), logoutStateWith(t, 1, false))
	assert.Check(t, is.ErrorContains(err, "not 32"))
	assert.Check(t, is.Len(w.Result().Cookies(), 0))
}

// A state written while no key was set is still read once one is, so a
// logout in progress when the key is first set carries on.
func TestLogoutStateUnencryptedReadWithKey(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	state := logoutStateWith(t, 2, false)
	cookie := setStateCookie(t, &test.IDP, state)
	test.IDP.LogoutStateKey = testLogoutStateKey(1)
	decoded, err := test.IDP.decodeLogoutState(cookie.Value)
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(state.Pending, decoded.Pending))
}

// Without LogoutStateKey, EncryptLogoutNameID keeps the NameIDs out of the
// cookie by holding EncryptedIDs, of which far fewer fit: the others are
// given up on and counted, as for any state too large for the cookie.
func TestLogoutStateCookieSealedNameIDCapacity(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.EncryptLogoutNameID = true
	pt.idp.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
			return pt.sps[0].Metadata(), nil
		},
	}
	state := logoutStateWith(t, 40, true)
	nameIDs := nameIDsOf(state)
	cookie := setStateCookie(t, pt.idp, state)
	assert.Check(t, len(cookie.Value) <= maxLogoutStateCookieValue, "%d bytes", len(cookie.Value))
	assert.Check(t, len(state.Pending) >= 2 && len(state.Pending) < 40, "%d pending", len(state.Pending))
	assert.Check(t, is.Equal(40, len(state.Pending)+state.Dropped))

	decoded, err := pt.idp.decodeLogoutState(cookie.Value)
	assert.NilError(t, err)
	payload, err := json.Marshal(decoded)
	assert.NilError(t, err)
	for _, nameID := range nameIDs {
		assert.Check(t, !strings.Contains(string(payload), nameID))
	}
	for _, p := range decoded.Pending {
		assert.Check(t, p.NameID == nil && p.EncryptedID != "", p.ServiceProviderID)
	}
}

// With LogoutStateKey and EncryptLogoutNameID, a logout through the browser
// sends every service provider an EncryptedID, and the cookie holds the
// NameIDs only encrypted.
func TestIDPInitiatedLogoutWithLogoutStateKey(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.EncryptLogoutNameID = true
	pt.idp.LogoutStateKey = testLogoutStateKey(7)
	pt.login(t, pt.sps...)

	w := pt.startLogout(propagationReturnURL)
	cookie := pt.cookieFrom(t, w)
	assert.Check(t, strings.HasPrefix(cookie.Value, logoutStateEncryptedPrefix))
	state, err := pt.idp.decodeLogoutState(cookie.Value)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(state.Pending, len(pt.sps)-1))
	for _, p := range state.Pending {
		// Not sealed one by one: the whole state is encrypted.
		assert.Check(t, p.NameID != nil && p.EncryptedID == "", p.ServiceProviderID)
	}

	w = pt.run(t, w)
	assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
	for _, sp := range pt.sps {
		id := sp.MetadataURL.String()
		reqs := pt.received[id]
		assert.Assert(t, is.Len(reqs, 1), id)
		assert.Check(t, reqs[0].EncryptedID != nil, id)
		assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value), id)
	}
}
