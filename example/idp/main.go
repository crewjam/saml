// Package main is an example identity provider built with
// github.com/crewjam/saml/x/samlidp: it logs users in with its own login
// page and sessions, answers service providers' AuthnRequests, offers a
// portal for IdP-initiated login, and does single logout with
// github.com/crewjam/saml/x/samlidp/idpslo.
//
// x/samlidp handles only the SAML protocol. Everything else here is the
// application's, kept as simple as an example allows: users are a fixed
// list, sessions are kept in memory, logins waiting for the user to log in
// in an encrypted cookie (with x/samlidp/idppending), and the service
// providers it trusts are those named with -sp, whose metadata it fetches
// from their entity IDs.
//
// To try it with the example service provider:
//
//	go run ./example/idp
//	go run ./example
//
// The IdP signs its metadata and writes the certificate it signs with to
// idp-cert.pem, which the service provider uses to check the metadata.
// Browse to http://localhost:8000/ and log in as alice or bob, with the
// password hunter2. Browse to http://localhost:8080/ for the IdP's portal,
// from which you can log in to the service provider, or log out of
// everything.
//
// example/trivial, which does single logout, works with it too:
//
//	curl -o idp-metadata.xml http://localhost:8080/metadata
//	go run ./example/trivial -idp-metadata idp-metadata.xml
//
// It is meant for local development only: it listens on localhost, and
// serves plain HTTP unless -url is https and a proxy terminates TLS.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// stringList is a flag that can be given more than once.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(s string) error { *l = append(*l, s); return nil }

func main() {
	baseURL := flag.String("url", "http://localhost:8080", "The base URL of the IdP")
	listenAddr := flag.String("listen", "localhost:8080", "The address to listen on")
	certOut := flag.String("cert-out", "idp-cert.pem", "Where to write the certificate the IdP signs its metadata with")
	var sps stringList
	flag.Var(&sps, "sp", "The entity ID of a service provider to trust, which must be the URL of its metadata (may be repeated; default http://localhost:8000/saml/metadata)")
	flag.Parse()
	if len(sps) == 0 {
		sps = stringList{"http://localhost:8000/saml/metadata"}
	}

	key, cert, err := newKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(*certOut, certPEM, 0o600); err != nil {
		log.Fatalf("cannot write certificate: %v", err)
	}

	idp, err := newIdentityProvider(*baseURL, key, cert, newRemoteServiceProviders(sps, nil), exampleUsers())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("IdP metadata at %s; trusting %s", idp.config.EntityID(), strings.Join(sps, ", "))

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           idp.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(server.ListenAndServe())
}

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
		KeyUsage:     x509.KeyUsageDigitalSignature,
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
