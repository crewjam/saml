package saml

import (
	"crypto/rand"
	"io"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// TimeNow is a function that returns the current time. The default
// value is time.Now, but it can be replaced for testing.
//
// It is used only where no clock is configured: by a ServiceProvider or
// IdentityProvider whose Clock field is nil, and by the samlsp and samlidp
// types whose Clock field is nil.
//
// Deprecated: set the Clock field of ServiceProvider, IdentityProvider,
// samlsp.Options or samlidp.Options instead. Replacing this global changes
// the time for every user of the package in the process, so it cannot be
// done safely by concurrent tests or by programs that need different
// clocks.
//
// TimeNow, Clock and RandReader are process-wide and read without
// synchronization: replace them only before any ServiceProvider or
// IdentityProvider is used (for example in TestMain or an init function),
// never while requests are being handled.
var TimeNow = func() time.Time { return time.Now().UTC() }

// Clock is assigned to dsig validation contexts if it is not nil,
// otherwise the default clock is used. Like TimeNow, it is used only
// where no Clock field is set.
//
// Deprecated: set the Clock field of ServiceProvider, IdentityProvider,
// samlsp.Options or samlidp.Options instead.
var Clock *dsig.Clock

// clockNow returns the current time from clock or, if it is nil, from the
// deprecated package-level TimeNow.
func clockNow(clock *dsig.Clock) time.Time {
	if clock != nil {
		return clock.Now().UTC()
	}
	return TimeNow()
}

// dsigClockOrDefault returns clock or, if it is nil, the deprecated
// package-level Clock (which may also be nil).
func dsigClockOrDefault(clock *dsig.Clock) *dsig.Clock {
	if clock != nil {
		return clock
	}
	return Clock
}

// RandReader is the io.Reader that produces cryptographically random
// bytes when they are need by the library. The default value is
// rand.Reader, but it can be replaced for testing. See TimeNow for when it
// may be replaced. Replacing it outside tests weakens every ID and key the
// library generates.
var RandReader = rand.Reader

//nolint:unparam // This always receives 20, but we want the option to do more or less if needed.
func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}
