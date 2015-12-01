// This is an example that implements a bitly-esque short link service.
package main

import (
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/metadata"
	"github.com/dchest/uniuri"
	"github.com/dgrijalva/jwt-go"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
)

var secret []byte
var links = map[string]Link{}
var samlsp *saml.ServiceProvider
var timeNow = time.Now
var maxAge = time.Minute * 5

type Link struct {
	ShortLink string
	Target    string
	Owner     string
}

func GetAccountFromCookie(r *http.Request) *string {
	cookieStr, err := r.Cookie("token")
	if err != nil {
		return nil
	}
	token, err := jwt.Parse(cookieStr.Value, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil
	}
	if !token.Valid {
		return nil
	}
	rv := token.Claims["u"].(string)
	return &rv
}

func GetMetadata(c web.C, w http.ResponseWriter, r *http.Request) {
	metadata := samlsp.Metadata()
	buf, _ := xml.MarshalIndent(metadata, "", "\t")
	w.Write(buf)
}

// PostACS handles the SAML ACS responses
func PostACS(c web.C, w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	requestID := "" // XXX
	assertionAttributes, err := samlsp.ParseResponse(r, requestID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	log.Printf("assertionAttributes: %#v", assertionAttributes)
	relayState, err := jwt.Parse(r.Form.Get("RelayState"), func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil || !relayState.Valid {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	redirectURI := relayState.Claims["uri"].(string)

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	token.Claims["u"] = assertionAttributes.Get("uid").Value
	token.Claims["exp"] = timeNow().Add(maxAge).Unix()
	signedToken, err := token.SignedString(secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    signedToken,
		MaxAge:   90000,
		Secure:   true,
		HttpOnly: false,
		Path:     "/",
	})

	//http.Redirect(w, r, redirectURI, http.StatusTemporaryRedirect)
	fmt.Fprintf(w, "<a href=\"%s\">Continue</a>", redirectURI)
}

var samlBinding = "post"

// RequireAccount is middleware that requires the request contain a valid token
func RequireAccount(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("RequireAccount(r=%#v)", r)
		account := GetAccountFromCookie(r)
		if account != nil {
			log.Printf("cookie is valid")
			c.Env["Account"] = *account
			h.ServeHTTP(w, r)
			return
		}

		relayState := jwt.New(jwt.GetSigningMethod("HS256"))
		relayState.Claims["uri"] = r.RequestURI
		signedRelayState, err := relayState.SignedString(secret)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		switch samlBinding {
		case "redirect":
			u, err := samlsp.MakeRedirectAuthenticationRequest(signedRelayState)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// redirect to the SAML login URL
			http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
			return
		case "post":
			formBuf, err := samlsp.MakePostAuthenticationRequest(signedRelayState)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "<!DOCTYPE html><html><body>%s</body></html>", formBuf)
			return

		default:
			log.Panicf("unknown saml binding %s", samlBinding)
		}
	}
	return http.HandlerFunc(fn)
}

// GetAccount returns the account associated with the request, so long as the
// request is wrapped with RequireAccount middleware
func GetAccount(c web.C) string {
	return c.Env["Account"].(string)
}

// CreateLink handles requests to create links
func CreateLink(c web.C, w http.ResponseWriter, r *http.Request) {
	account := GetAccount(c)
	l := Link{
		ShortLink: uniuri.New(),
		Target:    r.FormValue("t"),
		Owner:     account,
	}
	links[l.ShortLink] = l

	fmt.Fprintf(w, "%s\n", l.ShortLink)
	return
}

// ServeLink handles requests to redirect to a link
func ServeLink(c web.C, w http.ResponseWriter, r *http.Request) {
	l, ok := links[strings.TrimPrefix(r.URL.Path, "/")]
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	http.Redirect(w, r, l.Target, http.StatusFound)
	return
}

// ListLinks returns a list of the current user's links
func ListLinks(c web.C, w http.ResponseWriter, r *http.Request) {
	account := GetAccount(c)
	for _, l := range links {
		if l.Owner == account {
			fmt.Fprintf(w, "%s\n", l.ShortLink)
		}
	}
}

func main() {
	secret = make([]byte, 32)
	rand.Read(secret)

	baseURL := "https://15661444.ngrok.io"

	samlsp = &saml.ServiceProvider{
		MetadataURL: baseURL + "/saml2/metadata",
		AcsURL:      baseURL + "/saml2/acs",
		LogoutURL:   baseURL + "/saml2/logout",
	}
	samlsp.Key = `-----BEGIN RSA PRIVATE KEY-----
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
`
	samlsp.Certificate = `-----BEGIN CERTIFICATE-----
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
`

	buf, err := ioutil.ReadFile("doc/idp-metadata.xml")
	if err != nil {
		panic(err)
	}

	r := metadata.EntitiesDescriptor{}
	if err := xml.Unmarshal(buf, &r); err != nil {
		panic(err)
	}
	for _, e := range r.EntityDescriptor {
		if e.IDPSSODescriptor != nil {
			samlsp.IDPMetadata = e
			break
		}
	}
	if samlsp.IDPMetadata == nil {
		panic("cannot find idp in metadata")
	}

	goji.Get("/saml2/metadata", GetMetadata)
	goji.Post("/saml2/acs", PostACS)

	goji.Get("/:link", ServeLink)

	authMux := web.New()
	authMux.Use(RequireAccount)
	authMux.Post("/", CreateLink)
	authMux.Get("/", ListLinks)
	goji.Handle("/", authMux)

	goji.Serve()
}
