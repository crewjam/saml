package saml

import (
	"errors"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// An AuthnStatement SessionNotOnOrAfter is when the session the assertion
// establishes must end (saml-core §2.7.2). An assertion whose session has
// already ended, allowing MaxClockSkew, is refused rather than starting a
// session that is over; the earliest of several statements counts.
func TestSessionNotOnOrAfterInPastRefused(t *testing.T) {
	e := spcovSetup(t)
	skew := e.sp.maxClockSkew()
	parse := func(t *testing.T, ends ...time.Time) (*Assertion, error) {
		t.Helper()
		a := e.assertion()
		a.AuthnStatements = nil
		for i := range ends {
			end := ends[i]
			a.AuthnStatements = append(a.AuthnStatements, AuthnStatement{AuthnInstant: spcovNow, SessionNotOnOrAfter: &end})
		}
		r := e.response()
		r.Assertion = a
		return e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
	}

	for _, end := range []time.Time{spcovNow.Add(-time.Hour), spcovNow.Add(-skew), spcovNow.Add(-skew - time.Millisecond)} {
		_, err := parse(t, end)
		assert.Check(t, errors.Is(err, ErrExpired), "%s: %v", end, err)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "SessionNotOnOrAfter"))
	}

	// Within the allowed skew, or in the future, it is accepted.
	for _, end := range []time.Time{spcovNow.Add(-skew + time.Second), spcovNow.Add(time.Hour)} {
		assertion, err := parse(t, end)
		assert.Check(t, err, end.String())
		if err == nil {
			assert.Check(t, assertion.AuthnStatements[0].SessionNotOnOrAfter.Equal(end))
		}
	}

	// The earliest of several statements decides.
	_, err := parse(t, spcovNow.Add(time.Hour), spcovNow.Add(-time.Hour))
	assert.Check(t, errors.Is(err, ErrExpired), "%v", err)
}

// The replay cache keeps an assertion no longer than validateAssertion
// would accept it, which a SessionNotOnOrAfter can shorten.
func TestAcceptableUntilHonorsSessionNotOnOrAfter(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	l := e.sp.limits()
	without := l.acceptableUntil(a)

	end := spcovNow.Add(-l.skew() + 10*time.Second)
	a.AuthnStatements[0].SessionNotOnOrAfter = &end
	assert.Check(t, l.acceptableUntil(a).Equal(l.skewedDeadline(end)))
	assert.Check(t, l.acceptableUntil(a).Before(without))

	later := without.Add(time.Hour)
	a.AuthnStatements[0].SessionNotOnOrAfter = &later
	assert.Check(t, l.acceptableUntil(a).Equal(without))
}
