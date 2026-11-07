// Package main contains an example identity provider implementation.
//
// It is meant for local development only. Its administrative endpoints
// (/services, /users, /sessions and /shortcuts) are unauthenticated, so
// anyone who can reach the server can register service providers and read
// or change users. For that reason it listens on localhost by default; pass
// -listen to change that only on a network you trust, or set
// samlidp.Options.AdminMiddleware to protect those endpoints.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
)

// newKeyPair returns a freshly generated RSA key and a matching self-signed
// certificate. The example uses a throwaway key so that it never ships a
// private key or a certificate that can expire.
func newKeyPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

func main() {
	logr := logger.DefaultLogger
	baseURLstr := flag.String("idp", "http://localhost:8080", "The URL to the IDP")
	listenAddr := flag.String("listen", "localhost:8080", "The address to listen on (the admin endpoints are unauthenticated)")
	certOut := flag.String("cert-out", "idp-cert.pem", "Where to write the certificate the IDP signs its metadata with")
	flag.Parse()

	baseURL, err := url.Parse(*baseURLstr)
	if err != nil {
		logr.Fatalf("cannot parse base URL: %v", err)
	}

	key, cert, err := newKeyPair()
	if err != nil {
		logr.Fatalf("cannot generate key pair: %v", err)
	}

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         key,
		Logger:      logr,
		Certificate: cert,
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		logr.Fatalf("%s", err)
	}

	// Sign the metadata, and publish the certificate that signs it for
	// service providers to pin (see example/service.go).
	idpServer.IDP.SignMetadata = true
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(*certOut, certPEM, 0o600); err != nil {
		logr.Fatalf("cannot write certificate: %v", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	if err != nil {
		logr.Fatalf("cannot hash password: %v", err)
	}
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

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           idpServer,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if err := server.ListenAndServe(); err != nil {
		logr.Fatalf("%s", err)
	}
}
