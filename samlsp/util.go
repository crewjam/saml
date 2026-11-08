package samlsp

import (
	"io"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

// clockNow returns the current time from clock or, if it is nil, from the
// deprecated saml.TimeNow, which callers that have not set a Clock may
// still replace.
func clockNow(clock *dsig.Clock) time.Time {
	if clock != nil {
		return clock.Now().UTC()
	}
	return saml.TimeNow() //nolint:staticcheck // the fallback when no Clock is set
}

func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(saml.RandReader, rv); err != nil { //nolint:staticcheck // samlsp and samlidp still read the deprecated global
		panic(err)
	}
	return rv
}
