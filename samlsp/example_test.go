package samlsp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlsp"
)

// This example shows how to change how long a session lasts. It replaces the
// CookieMaxAge option that was removed from Options.
//
// The session lifetime is set in two places: the MaxAge of the cookie
// (CookieSessionProvider.MaxAge) and the expiry of the JWT stored in that
// cookie (JWTSessionCodec.MaxAge). Set both. If only the cookie's MaxAge is
// raised, the browser keeps the cookie but the token in it is rejected once
// the JWT expires, after the default one hour.
func Example_sessionMaxAge() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	rootURL, _ := url.Parse("https://sp.example.com/")

	opts := samlsp.Options{
		URL: *rootURL,
		Key: key,
		// ... and the rest of your options, e.g. Certificate and IDPMetadata
	}

	sessionMaxAge := 12 * time.Hour

	codec := samlsp.DefaultSessionCodec(opts)
	codec.MaxAge = sessionMaxAge

	sessionProvider := samlsp.DefaultSessionProvider(opts)
	sessionProvider.MaxAge = sessionMaxAge
	sessionProvider.Codec = codec

	middleware, err := samlsp.New(opts)
	if err != nil {
		panic(err)
	}
	middleware.Session = sessionProvider

	fmt.Println(middleware.Session.(samlsp.CookieSessionProvider).MaxAge)
	// Output: 12h0m0s
}
