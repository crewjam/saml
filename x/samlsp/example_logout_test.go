package samlsp_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// LogoutRequest starts single logout at the IdP. End the local session
// first, so the user is logged out of this SP even if the IdP never
// answers.
func ExampleConfig_LogoutRequest() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithKey(spKey, spCert), // logout messages are signed
		samlsp.WithSLOURL("https://sp.example.com/saml/slo"))
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

		msg, err := config.LogoutRequest(r.Context(), nameID, rand.Text(),
			samlsp.WithSessionIndex(sessionIndexes...))
		if errors.Is(err, samlsp.ErrNoEndpoint) {
			// The IdP does not support single logout.
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// remember msg.ID, to pass to ParseLogoutResponse
		msg.Write(w)
	})
}

// The SLO URL receives two kinds of message: the IdP's LogoutResponse to a
// logout the SP started, and a LogoutRequest when the IdP starts logout
// (for example, because the user logged out of another SP).
func ExampleConfig_ParseLogoutRequest() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithKey(spKey, spCert),
		samlsp.WithSLOURL("https://sp.example.com/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/saml/slo", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case samlsp.IsLogoutRequest(r):
			req, err := config.ParseLogoutRequest(r.Context(), r)
			if err != nil {
				samlsp.WriteLogoutRequestError(w, r)
				return
			}
			// End the sessions it names, in this browser and elsewhere.
			endSession(w, r)
			endSessionsOf(r.Context(), req.NameID, req.SessionIndexes)

			msg, err := config.LogoutResponse(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			msg.Write(w)

		case samlsp.IsLogoutResponse(r):
			requestID := takePendingRequest(r)
			_, err := config.ParseLogoutResponse(r.Context(), r, samlsp.WithRequestID(requestID))
			var status saml.ErrBadStatus
			if errors.As(err, &status) {
				log.Printf("IdP could not log the user out everywhere: %s", status.Status)
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
// could be ended.
func ExampleWithStatus() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithKey(spKey, spCert),
		samlsp.WithSLOURL("https://sp.example.com/saml/slo"))
	if err != nil {
		log.Fatal(err)
	}

	req := &samlsp.LogoutRequest{ID: "id-123", RelayState: "abc"} // from ParseLogoutRequest
	msg, err := config.LogoutResponse(t0(), req, samlsp.WithStatus(saml.Status{
		StatusCode: saml.StatusCode{
			Value:      saml.StatusSuccess,
			StatusCode: &saml.StatusCode{Value: saml.StatusPartialLogout},
		},
	}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(msg.Destination, msg.RedirectURL().Query().Get("RelayState"))
	// Output:
	// https://idp.example.com/slo abc
}

// With BackChannelLogout, the SP can end a user's sessions at the IdP
// without the browser, for example when an administrator disables the
// account. The IdP can do the same to the SP: ParseLogoutRequest accepts
// its SOAP LogoutRequests at the SLO URL, and LogoutResponse answers them.
func ExampleConfig_SendLogoutRequest() {
	config, err := samlsp.New(exampleIDP(), "https://sp.example.com/saml/metadata",
		samlsp.WithKey(spKey, spCert),
		samlsp.WithSLOURL("https://sp.example.com/saml/slo"),
		samlsp.BackChannelLogout)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /admin/users/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		nameID, sessionIndexes, _ := currentSession(r) // the disabled user's, from the application's store
		endSessionsOf(r.Context(), nameID, sessionIndexes)

		_, err := config.SendLogoutRequest(r.Context(), nameID, samlsp.WithSessionIndex(sessionIndexes...))
		switch {
		case errors.Is(err, samlsp.ErrNoEndpoint):
			log.Print("the IdP does not support back-channel logout")
		case err != nil:
			log.Printf("the IdP did not end the user's sessions: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
