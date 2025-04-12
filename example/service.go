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

var (
	key = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDU8wdiaFmPfTyRYuFlVPi866WrH/2JubkHzp89bBQopDaLXYxi
3PTu3O6Q/KaKxMOFBqrInwqpv/omOGZ4ycQ51O9I+Yc7ybVlW94lTo2gpGf+Y/8E
PsVbnZaFutRctJ4dVIp9aQ2TpLiGT0xX1OzBO/JEgq9GzDRf+B+eqSuglwIDAQAB
AoGBAMuy1eN6cgFiCOgBsB3gVDdTKpww87Qk5ivjqEt28SmXO13A1KNVPS6oQ8SJ
CT5Azc6X/BIAoJCURVL+LHdqebogKljhH/3yIel1kH19vr4E2kTM/tYH+qj8afUS
JEmArUzsmmK8ccuNqBcllqdwCZjxL4CHDUmyRudFcHVX9oyhAkEA/OV1OkjM3CLU
N3sqELdMmHq5QZCUihBmk3/N5OvGdqAFGBlEeewlepEVxkh7JnaNXAXrKHRVu/f/
fbCQxH+qrwJBANeQERF97b9Sibp9xgolb749UWNlAdqmEpmlvmS202TdcaaT1msU
4rRLiQN3X9O9mq4LZMSVethrQAdX1whawpkCQQDk1yGf7xZpMJ8F4U5sN+F4rLyM
Rq8Sy8p2OBTwzCUXXK+fYeXjybsUUMr6VMYTRP2fQr/LKJIX+E5ZxvcIyFmDAkEA
yfjNVUNVaIbQTzEbRlRvT6MqR+PTCefC072NF9aJWR93JimspGZMR7viY6IM4lrr
vBkm0F5yXKaYtoiiDMzlOQJADqmEwXl0D72ZG/2KDg8b4QZEmC9i5gidpQwJXUc6
hU+IVQoLxRq0fBib/36K9tcrrO5Ba4iEvDcNY+D8yGbUtA==
-----END RSA PRIVATE KEY-----
`)
	cert = []byte(`-----BEGIN CERTIFICATE-----
MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJV
UzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0
MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCB
nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9
ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmH
O8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKv
Rsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgk
akpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeT
QLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvn
OwJlNCASPZRH/JmF8tX0hoHuAQ==
-----END CERTIFICATE-----
`)
)

func main() {
	rootURLstr := flag.String("url", "https://962766ce.ngrok.io", "The base URL of this service")
	idpMetadataURLstr := flag.String("idp", "https://516becc2.ngrok.io/metadata", "The metadata URL for the IDP")
	flag.Parse()

	keyPair, err := tls.X509KeyPair(cert, key)
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
	mux.Handle("GET /saml/", samlSP)
	mux.HandleFunc("GET /{link}", ServeLink)
	mux.Handle("GET /whoami", samlSP.RequireAccount(http.HandlerFunc(ServeWhoami)))
	mux.Handle("POST /", samlSP.RequireAccount(http.HandlerFunc(CreateLink)))
	mux.Handle("GET /", samlSP.RequireAccount(http.HandlerFunc(ListLinks)))

	http.ListenAndServe(":8080", mux)
}
