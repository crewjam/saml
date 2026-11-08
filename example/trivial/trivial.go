// Package main is a minimal service provider built with
// github.com/crewjam/saml/x/samlsp: it logs users in with SAML, keeps a
// session for them, and logs them out with single logout.
//
// The IdP metadata names the certificates trusted to sign assertions, so it
// is loaded from a file you downloaded and checked once, not fetched from
// the network at every start:
//
//	curl -o idp-metadata.xml https://www.samltest.dev/apps/<APP_ID>/metadata
//	go run ./example/trivial -idp-metadata idp-metadata.xml
//
// Register the SP with the IdP with its entity ID,
// http://localhost:8000/saml/metadata, and ACS URL,
// http://localhost:8000/saml/acs, then browse to http://localhost:8000/hello.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/pending"
	"github.com/crewjam/saml/x/samlsp/slo"
)

var (
	config  *samlsp.Config
	logout  *slo.Service
	tracker *pending.Tracker
)

func main() {
	idpMetadataPath := flag.String("idp-metadata", "",
		"file holding the IDP metadata, downloaded e.g. from https://www.samltest.dev/apps/<APP_ID>/metadata")
	flag.Parse()
	if *idpMetadataPath == "" {
		log.Fatal("-idp-metadata is required")
	}

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

	idpMetadata, err := os.ReadFile(*idpMetadataPath)
	if err != nil {
		log.Fatal(err)
	}

	entityID := "http://localhost:8000/saml/metadata" // the ACS is beside it, at /saml/acs
	config, err = samlsp.New(entityID, samlsp.StaticMetadataBytes(idpMetadata),
		samlsp.WithSigningKey(key, cert),
		samlsp.WithEncryptionKey(key, cert), // for IdPs that encrypt assertions
		slo.Endpoint("http://localhost:8000/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}
	if logout, err = slo.New(config); err != nil {
		log.Fatal(err)
	}
	// The key authenticates the cookies of logins in progress. A real
	// deployment loads it from its secrets, so that every server shares
	// it and logins in progress survive a restart.
	if tracker, err = pending.New(config, []byte(rand.Text()+rand.Text())); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc(config.MetadataPath(), config.ServeMetadata)
	http.HandleFunc(config.ACSPath(), acs)
	http.HandleFunc(logout.Path(), sloHandler)
	http.HandleFunc("POST /logout", startLogout)
	http.Handle("/hello", requireLogin(http.HandlerFunc(hello)))
	http.HandleFunc("GET /{$}", home)

	server := &http.Server{
		Addr:              "localhost:8000",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(server.ListenAndServe())
}

func hello(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<p>Hello, %s!</p><form method="post" action="/logout"><button>Log out</button></form>`,
		html.EscapeString(s.assertion.Subject))
}

func home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprint(w, `<p><a href="/hello">Log in</a></p>`)
}

// requireLogin serves next to users with a session, and sends the others
// to the IdP to log in.
func requireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sessionFrom(r) == nil {
			startLogin(w, r, r.URL.RequestURI())
			return
		}
		next.ServeHTTP(w, r)
	})
}

// startLogin sends the browser to the IdP with an AuthnRequest. The
// request's ID, and where to go after login, wait in a cookie (see
// x/samlsp/pending), so that the Response is accepted only in the browser
// that asked for it.
func startLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	// The return path comes from the URL, which anyone can make long: keep
	// it short, so that the cookie stays within its share of the Cookie
	// header (see pending.WithMaxCookiesSize).
	if len(returnTo) > 100 {
		returnTo = "/"
	}
	msg, err := config.AuthnRequest(r.Context(), rand.Text())
	if err == nil {
		err = tracker.Remember(w, msg, returnTo)
	}
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	msg.Write(w)
}

// acs is the assertion consumer service: it verifies the IdP's Response
// and starts a session.
func acs(w http.ResponseWriter, r *http.Request) {
	login, err := tracker.Find(w, r)
	if err != nil {
		http.Error(w, "no login in progress", http.StatusForbidden)
		return
	}

	assertion, err := config.ParseResponse(r.Context(), r, samlsp.WithRequestID(login.ID))
	if err != nil {
		log.Printf("login failed: %v", errors.Unwrap(err))
		http.Error(w, "login failed", http.StatusForbidden)
		return
	}
	// Forget the login only once its Response is verified, so that a junk
	// Response posted with this browser's RelayState cannot cancel it.
	tracker.Forget(w, login)
	startSession(w, assertion)

	returnTo, ok := samlsp.SafeRedirectPath(login.Data)
	if !ok {
		returnTo = "/hello"
	}
	http.Redirect(w, r, returnTo, http.StatusFound) //nolint:gosec // G710: returnTo passed SafeRedirectPath
}

// startLogout ends the local session, then sends the browser to the IdP to
// log out there too.
func startLogout(w http.ResponseWriter, r *http.Request) {
	s := sessionFrom(r)
	endSession(w, r)
	if s == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	msg, err := logout.Request(r.Context(), s.assertion.NameID, rand.Text(),
		slo.WithSessionIndex(s.assertion.SessionIndexes...))
	if err != nil {
		// For example samlsp.ErrNoEndpoint: the IdP has no single logout.
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	setTempCookie(w, "saml_logout", logout.Path(), msg.ID)
	msg.Write(w)
}

// sloHandler receives the IdP's answer to startLogout, and logout requests
// that the IdP starts.
func sloHandler(w http.ResponseWriter, r *http.Request) {
	switch {
	case slo.IsRequest(r):
		req, err := logout.ParseRequest(r.Context(), r)
		if err != nil {
			slo.WriteRequestError(w, r)
			return
		}
		endSessionsOf(req.NameID, req.SessionIndexes)
		msg, err := logout.Response(r.Context(), req)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		msg.Write(w)

	case slo.IsResponse(r):
		var requestID string
		if c, err := r.Cookie("saml_logout"); err == nil {
			requestID = c.Value
		}
		deleteCookie(w, "saml_logout", logout.Path())
		if _, err := logout.ParseResponse(r.Context(), r, requestID); err != nil {
			log.Printf("single logout: %v", err)
		}
		// The local session ended when logout started.
		http.Redirect(w, r, "/", http.StatusFound)

	default:
		http.Error(w, "not a SAML message", http.StatusBadRequest)
	}
}

// Sessions are kept in memory, under a random ID in a cookie. A real
// application would use its own session store.

type session struct {
	assertion *samlsp.Assertion
	expires   time.Time
}

var sessions = struct {
	sync.Mutex
	m map[string]*session
}{m: map[string]*session{}}

const sessionCookie = "session"

func startSession(w http.ResponseWriter, a *samlsp.Assertion) {
	expires := time.Now().Add(8 * time.Hour)
	if !a.SessionNotOnOrAfter.IsZero() && a.SessionNotOnOrAfter.Before(expires) {
		expires = a.SessionNotOnOrAfter
	}
	id := rand.Text()
	sessions.Lock()
	sessions.m[id] = &session{assertion: a, expires: expires}
	sessions.Unlock()
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure whenever the SP is served over https
		Name: sessionCookie, Value: id, Path: "/", Expires: expires,
		HttpOnly: true, Secure: secure(), SameSite: http.SameSiteLaxMode,
	})
}

func sessionFrom(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	sessions.Lock()
	defer sessions.Unlock()
	s := sessions.m[c.Value]
	if s != nil && time.Now().After(s.expires) {
		delete(sessions.m, c.Value)
		return nil
	}
	return s
}

func endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		sessions.Lock()
		delete(sessions.m, c.Value)
		sessions.Unlock()
	}
	deleteCookie(w, sessionCookie, "/")
}

// endSessionsOf ends the sessions of the user nameID, in every browser:
// those with one of sessionIndexes, or all of them if it is empty.
func endSessionsOf(nameID saml.NameID, sessionIndexes []string) {
	sessions.Lock()
	defer sessions.Unlock()
	for id, s := range sessions.m {
		if s.assertion.NameID.Value != nameID.Value {
			continue
		}
		if len(sessionIndexes) == 0 || overlap(s.assertion.SessionIndexes, sessionIndexes) {
			delete(sessions.m, id)
		}
	}
}

func overlap(a, b []string) bool {
	return slices.ContainsFunc(a, func(x string) bool { return slices.Contains(b, x) })
}

// secure reports whether the SP is served over https, so that its cookies
// can be Secure.
func secure() bool { return strings.HasPrefix(config.ACSURL(), "https:") }

// setTempCookie sets a cookie that lasts for one exchange with the IdP. The
// IdP's answer is a cross-site request, so over https the cookie is
// SameSite=None; over plain http, which is for development, browsers send
// a cookie without SameSite on a cross-site POST shortly after it was set.
func setTempCookie(w http.ResponseWriter, name, path, value string) {
	c := &http.Cookie{Name: name, Value: value, Path: path, MaxAge: 300, HttpOnly: true} //nolint:gosec // G124: Secure and SameSite=None over https, below
	if secure() {
		c.Secure, c.SameSite = true, http.SameSiteNoneMode
	}
	http.SetCookie(w, c)
}

func deleteCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{Name: name, Path: path, MaxAge: -1, HttpOnly: true, Secure: secure()}) //nolint:gosec // G124: deletes the cookie
}
