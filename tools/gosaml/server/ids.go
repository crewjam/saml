package server

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/sqids/sqids-go"
)

// IDs other than instance names (see names.go) are Sqids: short, URL-safe
// strings, such as "86Rf07xd4z", that encode a random number. They name
// logins and logouts in progress, sessions, default RelayStates, session
// indexes and transient NameIDs. SAML message IDs are the library's, and
// the profiles' product-shaped IDs their own (see profiles.go).
//
// gosaml.dev is for testing, so they are not meant to be secrets, but
// with 64 random bits two are not going to be the same.

// idEncoder makes the Sqids. Its default blocklist keeps rude words out.
var idEncoder = func() *sqids.Sqids {
	s, err := sqids.New(sqids.Options{MinLength: 10})
	if err != nil {
		panic(err)
	}
	return s
}()

// newID returns a new Sqid.
func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	// Clear the top bit: Sqids' default alphabet encodes up to MaxInt64.
	n := binary.BigEndian.Uint64(b[:]) &^ (1 << 63)
	id, err := idEncoder.Encode([]uint64{n})
	if err != nil {
		// Only if every encoding of n were blocklisted: try another.
		return newID()
	}
	return id
}
