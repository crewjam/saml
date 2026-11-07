// Package main contains an example service provider implementation.
//
// The IdP metadata names the certificates trusted to sign assertions, so it
// is loaded from a file you downloaded and checked once, not fetched from
// the network at every start:
//
//	curl -o idp-metadata.xml https://www.samltest.dev/apps/<APP_ID>/metadata
//	go run ./example/trivial -idp-metadata idp-metadata.xml
//
// To fetch it at start-up instead, use samlsp.FetchSignedMetadata with the
// IdP's metadata signing certificate.
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml/samlsp"
)

var samlMiddleware *samlsp.Middleware

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "displayName"))
}

func main() {
	idpMetadataPath := flag.String("idp-metadata", "",
		"file holding the IDP metadata, downloaded e.g. from https://www.samltest.dev/apps/<APP_ID>/metadata")
	flag.Parse()
	if *idpMetadataPath == "" {
		log.Fatal("-idp-metadata is required")
	}

	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		log.Fatal(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	key, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("myservice.key must hold an RSA private key")
	}

	idpMetadataXML, err := os.ReadFile(*idpMetadataPath)
	if err != nil {
		log.Fatal(err)
	}
	idpMetadata, err := samlsp.ParseMetadata(idpMetadataXML)
	if err != nil {
		log.Fatal(err)
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		log.Fatal(err)
	}

	samlMiddleware, err = samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         key,
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true, // some IdP require the SLO request to be signed
	})
	if err != nil {
		log.Fatal(err)
	}
	app := http.HandlerFunc(hello)

	http.Handle("/hello", samlMiddleware.RequireAccount(app))
	// samlMiddleware serves /saml/metadata, /saml/acs and the single logout
	// endpoint /saml/slo.
	http.Handle("/saml/", samlMiddleware)
	// Visiting /logout ends the local session and sends the user to the IDP
	// to log out there too (SP initiated single logout).
	http.HandleFunc("/logout", samlMiddleware.HandleStartLogout)

	server := &http.Server{
		Addr:              "localhost:8000",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(server.ListenAndServe())
}
