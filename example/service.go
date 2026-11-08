// This is an example that implements a bitly-esque short link service.
//
// To try it locally, start the example identity provider first and then this
// service:
//
//	go run ./example/idp
//	go run ./example
//
// The identity provider signs its metadata and writes the certificate it
// signs with to idp-cert.pem. The service trusts the metadata only if that
// certificate signed it: the metadata names the certificates trusted to sign
// assertions, so it must not be taken from the network unchecked. The
// identity provider trusts this service by its entity ID,
// http://localhost:8000/saml/metadata, and fetches its metadata from there.
//
// Then browse to http://localhost:8000/ and log in as alice / hunter2.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml/x/samlsp"
)

// linkStore holds the short links. Handlers run concurrently, so every
// access goes through mu.
type linkStore struct {
	mu    sync.Mutex
	links map[string]Link
}

var links = &linkStore{links: map[string]Link{}}

// Link represents a short link
type Link struct {
	ShortLink string
	Target    string
	Owner     string
}

// currentAccount returns the SAML NameID of the signed-in user, which
// identifies the owner of a link. It is taken from the session that login
// established, never from a request header a client could set itself.
func currentAccount(r *http.Request) (string, bool) {
	s := sessionFromContext(r.Context())
	if s == nil || s.assertion.Subject == "" {
		return "", false
	}
	return s.assertion.Subject, true
}

// newShortLink returns a random, URL-safe short link name.
func newShortLink() (string, error) {
	randomness := make([]byte, 8)
	if _, err := rand.Read(randomness); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomness), nil
}

// CreateLink handles requests to create links. The target is the form value
// "t", for example:
//
//	curl -d t=https://example.com/ ...
func CreateLink(w http.ResponseWriter, r *http.Request) {
	account, ok := currentAccount(r)
	if !ok {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	target, err := url.Parse(r.FormValue("t"))
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		http.Error(w, "t must be an absolute http or https URL", http.StatusBadRequest)
		return
	}

	shortLink, err := newShortLink()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	l := Link{
		ShortLink: shortLink,
		Target:    target.String(),
		Owner:     account,
	}

	links.mu.Lock()
	links.links[l.ShortLink] = l
	links.mu.Unlock()

	writeText(w, "%s\n", l.ShortLink)
}

// ServeLink handles requests to redirect to a link
func ServeLink(w http.ResponseWriter, r *http.Request) {
	links.mu.Lock()
	l, ok := links.links[r.PathValue("link")]
	links.mu.Unlock()
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, l.Target, http.StatusFound)
}

// ListLinks returns a list of the current user's links
func ListLinks(w http.ResponseWriter, r *http.Request) {
	account, ok := currentAccount(r)
	if !ok {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	links.mu.Lock()
	var mine []string
	for _, l := range links.links {
		if l.Owner == account {
			mine = append(mine, l.ShortLink)
		}
	}
	links.mu.Unlock()

	sort.Strings(mine)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, shortLink := range mine {
		writeText(w, "%s\n", shortLink)
	}
}

// ServeWhoami serves the basic whoami endpoint
func ServeWhoami(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")

	s := sessionFromContext(r.Context())
	if s == nil {
		writeText(w, "not signed in\n")
		return
	}
	writeText(w, "signed in as %s\n", s.assertion.Subject)
	writeText(w, "attributes:\n")
	for _, attribute := range s.assertion.Attributes {
		for _, value := range attribute.Values {
			writeText(w, "%s: %v\n", attribute.Name, value)
		}
	}
}

// writeText writes a formatted line of the response. An error writing to the
// client cannot be reported back to it, so it is deliberately ignored.
func writeText(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// readCertificate reads a PEM encoded certificate from path.
func readCertificate(path string) (*x509.Certificate, error) {
	buf, err := os.ReadFile(path) //nolint:gosec // G304: the path is a command-line flag chosen by the operator
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate in " + path)
	}
	return x509.ParseCertificate(block.Bytes)
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
		Subject:      pkix.Name{CommonName: "example service"},
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

var config *samlsp.Config

func main() {
	rootURLstr := flag.String("url", "http://localhost:8000", "The base URL of this service")
	idpMetadataURL := flag.String("idp", "http://localhost:8080/metadata", "The metadata URL for the IDP")
	idpCertPath := flag.String("idp-cert", "idp-cert.pem", "The certificate the IDP signs its metadata with")
	listenAddr := flag.String("listen", "localhost:8000", "The address to listen on")
	flag.Parse()

	key, cert, err := newKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	idpCert, err := readCertificate(*idpCertPath)
	if err != nil {
		log.Fatal(err)
	}

	entityID := strings.TrimSuffix(*rootURLstr, "/") + "/saml/metadata"
	// Metadata is accepted only if the IdP's certificate signed it. The
	// URL is the operator's own, and often on localhost, which the
	// library's default client refuses to reach (it connects only to
	// public addresses), so give a client of our own.
	idpClient := &http.Client{Timeout: time.Minute}
	idp := samlsp.RemoteMetadata(*idpMetadataURL, samlsp.WithMetadataSigners(idpCert), samlsp.WithHTTPClient(idpClient))
	config, err = samlsp.New(entityID, idp,
		samlsp.WithSigningKey(key, cert),
		samlsp.WithEncryptionKey(key, cert))
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+config.MetadataPath(), config.ServeMetadata)
	mux.HandleFunc("POST "+config.ACSPath(), acs)
	mux.HandleFunc("GET /{link}", ServeLink)
	mux.Handle("GET /whoami", requireLogin(http.HandlerFunc(ServeWhoami)))
	mux.Handle("POST /", requireLogin(http.HandlerFunc(CreateLink)))
	mux.Handle("GET /", requireLogin(http.HandlerFunc(ListLinks)))

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(server.ListenAndServe())
}
