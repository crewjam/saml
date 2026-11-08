package samlsp_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
)

func Example() {
	var (
		key  *rsa.PrivateKey   // the SP's key
		cert *x509.Certificate // and certificate
	)

	config, err := samlsp.New(
		"https://sp.example.com/saml/metadata",
		samlsp.RemoteMetadata("https://idp.example.com/metadata"), // the ACS is at https://sp.example.com/saml/acs
		samlsp.WithSigningKey(key, cert),
	)
	if err != nil {
		log.Fatal(err)
	}
	// Remembers each login in progress in a cookie. The key is 32 or
	// more random bytes, the same on every server.
	tracker, err := pending.New(config, cookieKey)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		req, err := config.AuthnRequest(r.Context(), rand.Text())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tracker.Remember(w, req, ""); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Write(w)
	})

	http.HandleFunc(config.ACSPath(), func(w http.ResponseWriter, r *http.Request) {
		login, err := tracker.Find(w, r)
		if err != nil {
			http.Error(w, "no login in progress", http.StatusBadRequest)
			return
		}
		assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID))
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		tracker.Forget(w, login) // only once the Response is verified

		var user struct {
			Email  string   `saml:"urn:oid:0.9.2342.19200300.100.1.3"`
			Groups []string `saml:"memberOf"`
		}
		if err := assertion.DecodeAttributes(&user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Start the application's own session here.
		_, _ = fmt.Fprintf(w, "hello %s (%s)", assertion.Subject, strings.Join(user.Groups, ", "))
	})
}

var cookieKey []byte // loaded from the application's secrets
