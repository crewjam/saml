package samlidp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestDummyPasswordHashIsValid(t *testing.T) {
	cost, err := bcrypt.Cost(dummyPasswordHash)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(bcrypt.DefaultCost, cost))
}

// TestLoginAlwaysRunsBcrypt checks that every login attempt performs exactly
// one bcrypt comparison against a real hash, whether or not the user exists,
// so that response timing does not reveal which usernames are valid.
func TestLoginAlwaysRunsBcrypt(t *testing.T) {
	test := NewServerTest(t)

	putUser := func(name, body string) {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("PUT", "https://idp.example.com/users/"+name, strings.NewReader(body))
		test.Server.ServeHTTP(w, r)
		assert.Assert(t, is.Equal(http.StatusNoContent, w.Code))
	}
	putUser("alice", `{"password": "hunter2"}`)
	putUser("nopass", `{}`) // a user with no password hash

	var calls [][]byte
	orig := compareHashAndPassword
	compareHashAndPassword = func(hash, password []byte) error {
		calls = append(calls, hash)
		return orig(hash, password)
	}
	defer func() { compareHashAndPassword = orig }()

	login := func(user, password string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("POST", "https://idp.example.com/login",
			strings.NewReader("user="+user+"&password="+password))
		r.Header.Set("Content-type", "application/x-www-form-urlencoded")
		test.Server.ServeHTTP(w, r)
		return w
	}

	for _, tc := range []struct {
		name, user, password string
		wantDummy, wantOK    bool
	}{
		{name: "unknown user", user: "ghost", password: "wrong", wantDummy: true},
		{name: "existing user, wrong password", user: "alice", password: "wrong"},
		{name: "existing user, no password", user: "nopass", password: "wrong", wantDummy: true},
		{name: "existing user, no password, empty password", user: "nopass", password: "", wantDummy: true},
		{name: "existing user, correct password", user: "alice", password: "hunter2", wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls = nil
			w := login(tc.user, tc.password)

			assert.Assert(t, is.Len(calls, 1))
			_, err := bcrypt.Cost(calls[0])
			assert.Check(t, err, "bcrypt must do real work on every attempt")
			assert.Check(t, is.Equal(tc.wantDummy, bytes.Equal(calls[0], dummyPasswordHash)))

			if tc.wantOK {
				assert.Check(t, w.Header().Get("Set-Cookie") != "")
			} else {
				assert.Check(t, is.Equal("", w.Header().Get("Set-Cookie")))
				assert.Check(t, is.Contains(w.Body.String(), "Invalid username or password"))
			}
		})
	}
}
