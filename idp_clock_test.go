package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// TestIDPClockIsScopedPerIdentityProvider checks that IdentityProvider.Clock,
// when set, is used instead of the deprecated package-level TimeNow and Clock.
func TestIDPClockIsScopedPerIdentityProvider(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	// The SP's request is issued at the test's TimeNow.
	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	assert.NilError(t, err)
	requestedAt := TimeNow()

	// Point the package-level clocks at a time when the request has
	// expired, to show that IdentityProvider.Clock takes precedence.
	oldTimeNow, oldClock := TimeNow, Clock
	t.Cleanup(func() { TimeNow, Clock = oldTimeNow, oldClock })
	wrong := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	TimeNow = func() time.Time { return wrong }
	Clock = dsig.NewFakeClockAt(wrong)

	idpNow := requestedAt.Add(30 * time.Second)
	test.IDP.Clock = dsig.NewFakeClockAt(idpNow)

	t.Run("metadata", func(t *testing.T) {
		validDuration := 2 * time.Hour
		test.IDP.ValidDuration = &validDuration
		t.Cleanup(func() { test.IDP.ValidDuration = nil })
		assert.Check(t, is.Equal(idpNow.Add(validDuration), test.IDP.Metadata().ValidUntil))
	})

	t.Run("authn request and assertion", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, requestURL.String(), nil)
		req, err := NewIdpAuthnRequest(&test.IDP, r)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(idpNow, req.Now))
		assert.NilError(t, req.Validate())

		err = DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "f00df00df00d", UserName: "alice"})
		assert.NilError(t, err)
		assert.Check(t, is.Equal(idpNow, req.Assertion.IssueInstant))
	})
}
