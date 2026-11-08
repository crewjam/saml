// Package main is a multi-tenant service provider built with
// github.com/crewjam/saml/x/samlsp, in the manner of Supabase Auth: each
// tenant registers its own IdP by uploading its metadata, users log in
// through the IdP of their email domain, and logins in progress, the
// replay record and sessions live in a (here pretend) database, so that
// any server can handle any step. It supports SP- and IdP-initiated login
// and single logout.
//
//	go run ./example/multitenant -provider example.com=idp-metadata.xml
//
// Register the SP with each IdP with its entity ID,
// http://localhost:8000/saml/metadata, ACS URL,
// http://localhost:8000/saml/acs, and SLO URL,
// http://localhost:8000/saml/slo, then browse to http://localhost:8000/.
// More tenants can be added with
//
//	curl -d domain=example.org --data-urlencode metadata@other-idp.xml http://localhost:8000/admin/providers
package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
)

// providerFlags collects -provider domain=metadata-file flags.
type providerFlags []string

func (p *providerFlags) String() string     { return strings.Join(*p, ",") }
func (p *providerFlags) Set(v string) error { *p = append(*p, v); return nil }

func main() {
	baseURL := flag.String("base-url", "http://localhost:8000", "the URL the SP is served at")
	var providers providerFlags
	flag.Var(&providers, "provider", "domain=metadata-file: a tenant's IdP (repeatable)")
	flag.Parse()

	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	key, ok := keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("myservice.key must hold an RSA private key")
	}

	db := NewDB()
	for _, p := range providers {
		domain, path, ok := strings.Cut(p, "=")
		if !ok {
			log.Fatalf("-provider %q: want domain=metadata-file", p)
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: the path is a command-line flag chosen by the operator
		if err != nil {
			log.Fatal(err)
		}
		md, err := samlsp.ParseMetadata(data)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		if err := db.AddProvider(&Provider{Domain: domain, EntityID: md.EntityID, MetadataXML: data, AllowIDPInitiated: true}); err != nil {
			log.Fatalf("%s: %v", path, err)
		}
	}

	app, err := NewApp(db, *baseURL, key, cert)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              mustParseURL(*baseURL).Host,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(server.ListenAndServe())
}

// NewApp returns the SP served at baseURL, with its state in db. The SP
// has no IdP of its own (a nil MetadataFunc): every call names the
// tenant's.
func NewApp(db *DB, baseURL string, key *rsa.PrivateKey, cert *x509.Certificate) (*App, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	entityID := baseURL + "/saml/metadata"   // the ACS is beside it, at /saml/acs
	config, err := samlsp.New(entityID, nil, // each call names its tenant's IdP
		samlsp.WithSigningKey(key, cert),
		samlsp.WithEncryptionKey(key, cert), // for IdPs that encrypt assertions
		samlsp.WithReplayState(db),
		slo.Endpoint(baseURL+"/saml/slo"))
	if err != nil {
		return nil, err
	}
	logout, err := slo.New(config)
	if err != nil {
		return nil, err
	}
	return &App{db: db, config: config, logout: logout, secure: strings.HasPrefix(baseURL, "https:")}, nil
}
