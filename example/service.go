// This is an example that implements a bitly-esque short link service.
package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/crewjam/saml/samlsp"
)

var links = map[string]Link{}

// Link represents a short link
type Link struct {
	ShortLink string
	Target    string
	Owner     string
}

// CreateLink handles requests to create links
func CreateLink(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Remote-User")

	randomness := make([]byte, 8)
	if _, err := r.Body.Read(randomness); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	l := Link{
		ShortLink: base64.RawURLEncoding.EncodeToString(randomness),
		Target:    r.FormValue("t"),
		Owner:     account,
	}
	links[l.ShortLink] = l

	fmt.Fprintf(w, "%s\n", l.ShortLink)
}

// ServeLink handles requests to redirect to a link
func ServeLink(w http.ResponseWriter, r *http.Request) {
	l, ok := links[strings.TrimPrefix(r.URL.Path, "/")]
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, l.Target, http.StatusFound)
}

// ListLinks returns a list of the current user's links
func ListLinks(w http.ResponseWriter, r *http.Request) {
	account := r.Header.Get("X-Remote-User")
	for _, l := range links {
		if l.Owner == account {
			fmt.Fprintf(w, "%s\n", l.ShortLink)
		}
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

func main() {
	rootURLstr := flag.String("url", "http://localhost:8090", "The base URL of this service")
	idpMetadataURLstr := flag.String("idp", "http://localhost:8080/metadata", "The metadata URL for the IDP")
	certFile := flag.String("cert", "service.cert", "The certificate file path")
	keyFile := flag.String("key", "service.key", "The private key file path")
	flag.Parse()

	keyPair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		panic(err) // TODO handle error
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadataURL, err := url.Parse(*idpMetadataURLstr)
	if err != nil {
		panic(err) // TODO handle error
	}

	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		panic(err) // TODO handle error
	}

	rootURL, err := url.Parse(*rootURLstr)
	if err != nil {
		panic(err) // TODO handle error
	}

	samlSP, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:       keyPair.Leaf,
		AllowIDPInitiated: true,
		IDPMetadata:       idpMetadata,
	})
	if err != nil {
		panic(err) // TODO handle error
	}

	// register with the service provider
	spMetadataBuf, _ := xml.MarshalIndent(samlSP.ServiceProvider.Metadata(), "", "  ")
	spURL := *idpMetadataURL
	spURL.Path = "/services/sp"
	resp, err := http.Post(spURL.String(), "text/xml", bytes.NewReader(spMetadataBuf))
	if err != nil {
		panic(err)
	}

	if err := resp.Body.Close(); err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/saml/", samlSP)
	mux.HandleFunc("GET /links/{link}", ServeLink)
	mux.Handle("GET /whoami", samlSP.RequireAccount(http.HandlerFunc(ServeWhoami)))
	mux.Handle("POST /links", samlSP.RequireAccount(http.HandlerFunc(CreateLink)))
	mux.Handle("GET /links", samlSP.RequireAccount(http.HandlerFunc(ListLinks)))

	http.ListenAndServe(":8090", mux)
}
