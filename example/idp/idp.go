// Package main contains an example identity provider implementation.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

func main() {
	logr := logger.DefaultLogger
	baseURLstr := flag.String("idp", "http://localhost:8080", "The URL to the IDP")
	certFile := flag.String("cert", "idp.cert", "The certificate file path")
	keyFile := flag.String("key", "idp.key", "The private key file path")
	flag.Parse()

	baseURL, err := url.Parse(*baseURLstr)
	if err != nil {
		logr.Fatalf("cannot parse base URL: %v", err)
	}

	keyPair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		logr.Fatalf("cannot load key pair: %v", err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		logr.Fatalf("cannot parse certificate: %v", err)
	}

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         keyPair.PrivateKey,
		Logger:      logr,
		Certificate: keyPair.Leaf,
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	err = idpServer.Store.Put("/users/alice", samlidp.User{Name: "alice",
		HashedPassword: hashedPassword,
		Groups:         []string{"Administrators", "Users"},
		Email:          "alice@example.com",
		CommonName:     "Alice Smith",
		Surname:        "Smith",
		GivenName:      "Alice",
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	err = idpServer.Store.Put("/users/bob", samlidp.User{
		Name:           "bob",
		HashedPassword: hashedPassword,
		Groups:         []string{"Users"},
		Email:          "bob@example.com",
		CommonName:     "Bob Smith",
		Surname:        "Smith",
		GivenName:      "Bob",
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	http.ListenAndServe(":8080", idpServer)
}
