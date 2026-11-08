package idpartifact_test

import (
	"crypto"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpartifact"
)

// This example answers SPs that ask for the HTTP-Artifact binding by
// artifact, and the others with HTTP-POST.
func Example() {
	var (
		key  crypto.Signer
		cert *x509.Certificate
		sps  samlidp.ServiceProviderFunc
		// loggedIn returns the ID of the user of r, if they are logged in.
		loggedIn func(r *http.Request) (string, bool)
	)

	config, err := samlidp.New("https://idp.example.com/saml/metadata", sps,
		samlidp.WithSigningKey(key, cert),
		idpartifact.ResolutionService("https://idp.example.com/saml/artifact", 1))
	if err != nil {
		log.Print(err)
		return
	}
	binding := idpartifact.New(config, idpartifact.NewMemoryStore(), 1)
	binding.Form = true // keep the artifact out of URLs
	http.Handle(binding.Path(), binding)

	artifacts := samlidp.WithCustomBinding(binding)
	http.HandleFunc(config.SSOPath(), func(w http.ResponseWriter, r *http.Request) {
		req, err := config.ParseAuthnRequest(r.Context(), r, artifacts)
		var status *saml.StatusError
		if errors.As(err, &status) && req != nil {
			if msg, err := config.ErrorResponse(r.Context(), req, status, artifacts); err == nil {
				msg.Write(w)
			}
			return
		}
		if err != nil {
			http.Error(w, "invalid login request", http.StatusBadRequest)
			return
		}
		user, ok := loggedIn(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound) // and keep req; see samlidp
			return
		}
		msg, err := config.Response(r.Context(), req, samlidp.Subject{
			NameID: user, NameIDFormat: saml.PersistentNameIDFormat, AuthnInstant: time.Now(),
		}, artifacts)
		if err != nil {
			http.Error(w, "cannot answer the login request", http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	})
}
