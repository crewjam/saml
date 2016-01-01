package saml

import (
	"crypto/rand"
	"time"
)

var timeNow = time.Now       // thunk for testing
var randReader = rand.Reader // thunk for testing

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := randReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}
