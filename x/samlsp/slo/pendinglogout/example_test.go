package pendinglogout_test

import (
	"crypto/rand"
	"errors"
	"log"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
	"github.com/crewjam/saml/x/samlsp/slo/pendinglogout"
)

// The application's own session storage, which these packages leave to it.

func endSession(http.ResponseWriter, *http.Request) {}

func currentSession(*http.Request) (nameID saml.NameID, sessionIndexes []string, ok bool) {
	return saml.NameID{}, nil, false
}

// The SP remembers each LogoutRequest it sends, and finds it again when the
// IdP's LogoutResponse arrives at the SLO URL.
func Example() {
	var (
		logout    *slo.Service // from slo.New
		cookieKey []byte       // 32 random bytes, shared by every server
	)
	tracker, err := pendinglogout.New(logout, cookieKey)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		nameID, sessionIndexes, ok := currentSession(r)
		endSession(w, r) // first, so the user is logged out even if the IdP never answers
		if !ok {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		msg, err := logout.Request(r.Context(), nameID, rand.Text(), slo.WithSessionIndex(sessionIndexes...))
		if err == nil {
			err = tracker.Remember(w, msg, "")
		}
		if errors.Is(err, samlsp.ErrNoEndpoint) {
			http.Redirect(w, r, "/", http.StatusFound) // the IdP does not do single logout
			return
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	})

	http.HandleFunc(logout.Path(), func(w http.ResponseWriter, r *http.Request) {
		if !slo.IsResponse(r) {
			return // a LogoutRequest from the IdP: see slo.Service.ParseRequest
		}
		l, err := tracker.Find(w, r)
		if err != nil {
			http.Error(w, "no logout in progress", http.StatusBadRequest)
			return
		}
		_, err = logout.ParseResponse(r.Context(), r, l.RequestIDs()...)
		if pendinglogout.Answered(err) {
			// Verified, whatever the IdP's status: the logout is over.
			tracker.Forget(w, l)
		}
		if err != nil {
			log.Printf("single logout: %v", err)
		}
		http.Redirect(w, r, "/", http.StatusFound)
	})
}
