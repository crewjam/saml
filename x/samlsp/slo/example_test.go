package slo_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
)

// exampleIDP returns the metadata of an IdP with HTTP-Redirect and
// HTTP-POST single sign-on and single logout endpoints.
func exampleIDP() samlsp.MetadataFunc {
	endpoints := func(location string) []saml.Endpoint {
		return []saml.Endpoint{
			{Binding: saml.HTTPRedirectBinding, Location: location},
			{Binding: saml.HTTPPostBinding, Location: location},
		}
	}
	return samlsp.StaticMetadata(&saml.EntityDescriptor{
		EntityID: "https://idp.example.com/metadata",
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor:       saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol"},
				SingleLogoutServices: endpoints("https://idp.example.com/slo"),
			},
			SingleSignOnServices: endpoints("https://idp.example.com/sso"),
		}},
	})
}

// spKey and spCert are the SP's key pair in the examples.
var spKey, spCert = func() (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp.example.com"},
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return key, cert
}()

// The application's own session storage, which these packages leave to it.

func takePendingRequest(*http.Request) string       { return "" }
func endSession(http.ResponseWriter, *http.Request) {}

// endSessionsOf ends the sessions of the user nameID of the IdP issuer: a
// NameID is unique only within the IdP that issued it.
func endSessionsOf(_ context.Context, issuer string, nameID saml.NameID, sessionIndexes []string) {}

// currentSession returns what the application kept from the user's login.
func currentSession(*http.Request) (nameID saml.NameID, sessionIndexes []string, ok bool) {
	return saml.NameID{}, nil, false
}

// Endpoint adds the SP's single logout service to the Config, and New
// makes the Service that sends and receives logout messages.
func Example() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithSigningKey(spKey, spCert), // logout messages are signed
		slo.Endpoint("https://sp.example.com/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}
	logout, err := slo.New(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(logout.URL())
	fmt.Println(logout.Path()) // to serve it at: http.HandleFunc(logout.Path(), ...)
	// Output:
	// https://sp.example.com/saml/slo
	// /saml/slo
}

// Request starts single logout at the IdP. End the local session first, so
// the user is logged out of this SP even if the IdP never answers.
func ExampleService_Request() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithSigningKey(spKey, spCert), slo.Endpoint("https://sp.example.com/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}
	logout, err := slo.New(config)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		nameID, sessionIndexes, ok := currentSession(r)
		endSession(w, r)
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		msg, err := logout.Request(r.Context(), nameID, rand.Text(), slo.WithSessionIndex(sessionIndexes...))
		if errors.Is(err, samlsp.ErrNoEndpoint) {
			// The IdP does not support single logout.
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// remember msg.ID, to pass to ParseResponse
		msg.Write(w)
	})
}

// The SLO URL receives two kinds of message: the IdP's LogoutResponse to a
// logout the SP started, and a LogoutRequest when the IdP starts logout
// (for example, because the user logged out of another SP).
func ExampleService_ParseRequest() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithSigningKey(spKey, spCert), slo.Endpoint("https://sp.example.com/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}
	logout, err := slo.New(config)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc(logout.Path(), func(w http.ResponseWriter, r *http.Request) {
		switch {
		case slo.IsRequest(r):
			req, err := logout.ParseRequest(r.Context(), r)
			if err != nil {
				slo.WriteRequestError(w, r)
				return
			}
			// End the sessions it names, in this browser and elsewhere.
			endSession(w, r)
			endSessionsOf(r.Context(), req.Issuer, req.NameID, req.SessionIndexes)

			msg, err := logout.Response(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			msg.Write(w)

		case slo.IsResponse(r):
			_, err := logout.ParseResponse(r.Context(), r, takePendingRequest(r))
			var status saml.ErrBadStatus
			if errors.Is(err, slo.ErrPartialLogout) {
				log.Print("the IdP could not log the user out of every SP")
			} else if errors.As(err, &status) {
				log.Printf("the IdP could not log the user out: %s", status.Status)
			} else if err != nil {
				log.Printf("bad logout response: %v", errors.Unwrap(err))
			}
			// The local session already ended when logout started.
			http.Redirect(w, r, "/", http.StatusFound)

		default:
			http.Error(w, "not a SAML message", http.StatusBadRequest)
		}
	})
}

// WithStatus answers a LogoutRequest with another status: here, success
// with the second-level status PartialLogout, because not every session
// could be ended. Logout options mix with those of samlsp, such as
// samlsp.WithBinding.
func ExampleWithStatus() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithSigningKey(spKey, spCert), slo.Endpoint("https://sp.example.com/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}
	logout, err := slo.New(config)
	if err != nil {
		log.Fatal(err)
	}

	req := &slo.Request{ID: "id-123", RelayState: "abc"} // from ParseRequest
	msg, err := logout.Response(context.Background(), req,
		samlsp.WithBinding(saml.HTTPRedirectBinding),
		slo.WithStatus(saml.Status{StatusCode: saml.StatusCode{
			Value:      saml.StatusSuccess,
			StatusCode: &saml.StatusCode{Value: saml.StatusPartialLogout},
		}}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(msg.Destination, msg.RedirectURL().Query().Get("RelayState"))
	// Output:
	// https://idp.example.com/slo abc
}

// With BackChannel, the SP can end a user's sessions at the IdP without the
// browser, for example when an administrator disables the account. The IdP
// can do the same to the SP: ParseRequest accepts its SOAP LogoutRequests
// at the SLO URL, and Response answers them.
func ExampleService_SendRequest() {
	entityID := "https://sp.example.com/saml/metadata"
	config, err := samlsp.New(entityID, exampleIDP(),
		samlsp.WithSigningKey(spKey, spCert),
		slo.Endpoint("https://sp.example.com/saml/slo", slo.BackChannel))
	if err != nil {
		log.Fatal(err)
	}
	logout, err := slo.New(config)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /admin/users/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		nameID, sessionIndexes, _ := currentSession(r) // the disabled user's, from the application's store
		endSessionsOf(r.Context(), "https://idp.example.com/metadata", nameID, sessionIndexes)

		_, err := logout.SendRequest(r.Context(), nameID,
			slo.WithSessionIndex(sessionIndexes...), slo.WithReason(saml.LogoutReasonAdmin))
		switch {
		case errors.Is(err, samlsp.ErrNoEndpoint):
			log.Print("the IdP does not support back-channel logout")
		case err != nil:
			log.Printf("the IdP did not end the user's sessions: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
