package idppending_test

import (
	"crypto"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idppending"
)

// The SSO handler keeps the AuthnRequest in a cookie while the user logs
// in, and passes its handle to the login page, which takes it once the
// user is authenticated, and answers it.
func Example() {
	var (
		key  crypto.Signer
		cert *x509.Certificate
		sps  samlidp.ServiceProviderFunc
		// authenticate checks the login form, and returns the user's ID,
		// or "" if the password is wrong.
		authenticate func(form url.Values) string
	)
	config, err := samlidp.New("https://idp.example.com/saml/metadata", sps, samlidp.WithSigningKey(key, cert))
	if err != nil {
		log.Print(err)
		return
	}
	// 32 or more random bytes, the same on every server.
	tracker, err := idppending.New(config, []byte(os.Getenv("SAML_PENDING_KEY")),
		idppending.WithCookiePrefix("__Host-saml_pending_"),
		idppending.RecordTaken)
	if err != nil {
		log.Print(err)
		return
	}

	http.HandleFunc(config.SSOPath(), func(w http.ResponseWriter, r *http.Request) {
		req, err := config.ParseAuthnRequest(r.Context(), r)
		var status *saml.StatusError
		if errors.As(err, &status) && req != nil {
			if msg, err := config.ErrorResponse(r.Context(), req, status); err == nil {
				msg.Write(w)
			}
			return
		}
		if err != nil {
			http.Error(w, "invalid login request", http.StatusBadRequest)
			return
		}
		handle, err := tracker.Remember(w, r, req)
		if err != nil {
			http.Error(w, "cannot log in to this service", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "/login?"+url.Values{"p": {handle}}.Encode(), http.StatusFound)
	})

	http.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil { // not ParseMultipartForm
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		userID := authenticate(r.PostForm)
		if userID == "" {
			// Show the form again, with the same handle; the request
			// stays in its cookie.
			http.Redirect(w, r, "/login?"+url.Values{"p": {r.PostForm.Get("p")}}.Encode(), http.StatusSeeOther)
			return
		}
		req, err := tracker.Take(w, r, r.PostForm.Get("p"))
		if err != nil {
			// Expired, already answered, or started in another browser.
			http.Error(w, "the login request has expired; go back to the service and try again", http.StatusBadRequest)
			return
		}
		msg, err := config.Response(r.Context(), req, samlidp.Subject{
			NameID:       userID,
			NameIDFormat: saml.PersistentNameIDFormat,
			AuthnInstant: time.Now(),
		})
		var status *saml.StatusError
		if errors.As(err, &status) {
			msg, err = config.ErrorResponse(r.Context(), req, status)
		}
		if err != nil {
			http.Error(w, "cannot log in to this service", http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	})
}
