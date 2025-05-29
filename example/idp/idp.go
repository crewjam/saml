// Package main contains an example identity provider implementation.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net/http"
	"net/url"

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

	http.ListenAndServe(":8080", idpServer)
}
