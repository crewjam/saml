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
// assertions, so it must not be taken from the network unchecked.
//
// Then browse to http://localhost:8000/ and log in as alice / hunter2.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
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

	"github.com/crewjam/saml/samlsp"
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
// identifies the owner of a link. It is taken from the session samlsp
// established, never from a request header a client could set itself.
func currentAccount(r *http.Request) (string, bool) {
	switch session := samlsp.SessionFromContext(r.Context()).(type) {
	case samlsp.JWTSessionClaims:
		// The default session codec stores the NameID value as the subject.
		return session.Subject, session.Subject != ""
	case samlsp.SessionWithSAMLNameID:
		nameID, ok := session.GetSAMLNameID()
		return nameID.Value, ok && nameID.Value != ""
	default:
		return "", false
	}
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

	fmt.Fprintf(w, "%s\n", l.ShortLink)
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
		fmt.Fprintf(w, "%s\n", shortLink)
	}
}

// ServeWhoami serves the basic whoami endpoint
func ServeWhoami(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")

	session := samlsp.SessionFromContext(r.Context())
	if session == nil {
		fmt.Fprintln(w, "not signed in")
		return
	}
	fmt.Fprintln(w, "signed in")
	sessionWithAttrs, ok := session.(samlsp.SessionWithAttributes)
	if ok {
		fmt.Fprintln(w, "attributes:")
		for name, values := range sessionWithAttrs.GetAttributes() {
			for _, value := range values {
				fmt.Fprintf(w, "%s: %v\n", name, value)
			}
		}
	}
}

// readCertificate reads a PEM encoded certificate from path.
func readCertificate(path string) (*x509.Certificate, error) {
	buf, err := os.ReadFile(path)
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

func main() {
	rootURLstr := flag.String("url", "http://localhost:8000", "The base URL of this service")
	idpMetadataURLstr := flag.String("idp", "http://localhost:8080/metadata", "The metadata URL for the IDP")
	idpCertPath := flag.String("idp-cert", "idp-cert.pem", "The certificate the IDP signs its metadata with")
	listenAddr := flag.String("listen", "localhost:8000", "The address to listen on")
	flag.Parse()

	key, cert, err := newKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	idpMetadataURL, err := url.Parse(*idpMetadataURLstr)
	if err != nil {
		log.Fatal(err)
	}

	idpCert, err := readCertificate(*idpCertPath)
	if err != nil {
		log.Fatal(err)
	}
	idpMetadata, err := samlsp.FetchSignedMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL, []*x509.Certificate{idpCert})
	if err != nil {
		log.Fatal(err)
	}

	rootURL, err := url.Parse(*rootURLstr)
	if err != nil {
		log.Fatal(err)
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               key,
		Certificate:       cert,
		AllowIDPInitiated: true,
		IDPMetadata:       idpMetadata,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Register with the identity provider. The example IdP accepts this
	// unauthenticated request because its admin API is meant only for local
	// development; see example/idp.
	if err := registerWithIDP(*idpMetadataURL, samlSP); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	// The SAML endpoints need both GET (metadata) and POST (the assertion
	// consumer service). They are registered per method because a bare "/saml/"
	// pattern would conflict with "GET /" below.
	mux.Handle("GET /saml/", samlSP)
	mux.Handle("POST /saml/", samlSP)
	mux.HandleFunc("GET /{link}", ServeLink)
	mux.Handle("GET /whoami", samlSP.RequireAccount(http.HandlerFunc(ServeWhoami)))
	mux.Handle("POST /", samlSP.RequireAccount(http.HandlerFunc(CreateLink)))
	mux.Handle("GET /", samlSP.RequireAccount(http.HandlerFunc(ListLinks)))

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

// registerWithIDP uploads the service provider's metadata to the example
// identity provider's /services API.
func registerWithIDP(idpMetadataURL url.URL, samlSP *samlsp.Middleware) error {
	spMetadataBuf, err := xml.MarshalIndent(samlSP.ServiceProvider.Metadata(), "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal SP metadata: %w", err)
	}
	spURL := idpMetadataURL
	spURL.Path = "/services/sp"
	spURL.RawQuery = ""

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, spURL.String(), bytes.NewReader(spMetadataBuf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/xml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot register with the IDP: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing useful to do with a close error here
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("cannot register with the IDP: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
