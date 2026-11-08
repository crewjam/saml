package idpslo_test

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"sync"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpslo"
)

// logoutState is where a logout is: the SP request it will answer, if an
// SP started it, the participants still to visit, and the request sent to
// the one being visited. A real application keeps it in its session
// store.
type logoutState struct {
	request   *idpslo.Request // nil for a logout started at the IdP
	remaining []saml.SessionParticipant
	partial   bool

	current   string // the SP being visited
	requestID string // the LogoutRequest sent to it
}

// This example serves the IdP's single logout service. The application
// records each user's session participants (samlidp.Message.Participant)
// at login; participants(r) returns those of the user of r, and
// endSession(w, r) ends the IdP session.
func Example() {
	var (
		key              crypto.Signer
		cert             *x509.Certificate
		sps              samlidp.ServiceProviderFunc
		participantsOf   func(r *http.Request) []saml.SessionParticipant
		endSession       func(w http.ResponseWriter, r *http.Request)
		mu               sync.Mutex
		logoutsInProcess = map[string]*logoutState{}
	)

	config, err := samlidp.New("https://idp.example.com/saml/metadata", sps,
		samlidp.WithSigningKey(key, cert),
		idpslo.Endpoint("https://idp.example.com/saml/slo"))
	if err != nil {
		log.Print(err)
		return
	}
	logout, err := idpslo.New(config)
	if err != nil {
		log.Print(err)
		return
	}

	// next visits the next participant, or ends the logout.
	next := func(w http.ResponseWriter, r *http.Request, key string, state *logoutState) {
		for len(state.remaining) > 0 {
			p := state.remaining[0]
			state.remaining = state.remaining[1:]
			msg, err := logout.Request(r.Context(), p, key)
			if err != nil {
				state.partial = true // this SP cannot be logged out
				continue
			}
			state.current, state.requestID = p.ServiceProviderID, msg.ID
			msg.Write(w)
			return
		}
		mu.Lock()
		delete(logoutsInProcess, key)
		mu.Unlock()
		if state.request == nil {
			http.Redirect(w, r, "/logged-out", http.StatusFound)
			return
		}
		var opts []idpslo.ResponseOption
		if state.partial {
			opts = append(opts, idpslo.PartialLogout)
		}
		msg, err := logout.Response(r.Context(), state.request, opts...)
		if err != nil {
			http.Error(w, "cannot answer the logout request", http.StatusInternalServerError)
			return
		}
		msg.Write(w)
	}

	http.HandleFunc(logout.Path(), func(w http.ResponseWriter, r *http.Request) {
		switch {
		case idpslo.IsRequest(r):
			// An SP starts a logout.
			req, err := logout.ParseRequest(r.Context(), r)
			if err != nil {
				idpslo.WriteRequestError(w, r)
				return
			}
			state := &logoutState{request: req}
			found := false
			for _, p := range participantsOf(r) {
				if req.Matches(p) {
					found = true
				} else {
					state.remaining = append(state.remaining, p)
				}
			}
			if !found {
				// Not a participant of this user's session: end nothing.
				msg, err := logout.Response(r.Context(), req, idpslo.WithStatus(saml.Status{
					StatusCode: saml.StatusCode{Value: saml.StatusRequester},
				}))
				if err == nil {
					msg.Write(w)
				}
				return
			}
			endSession(w, r)
			key := rand.Text()
			mu.Lock()
			logoutsInProcess[key] = state
			mu.Unlock()
			next(w, r, key, state)

		case idpslo.IsResponse(r):
			// A participant answers; the RelayState is the key.
			key := r.FormValue("RelayState")
			mu.Lock()
			state := logoutsInProcess[key]
			mu.Unlock()
			if state == nil {
				http.Error(w, "no logout in progress", http.StatusBadRequest)
				return
			}
			_, err := logout.ParseResponse(r.Context(), r, state.current, state.requestID)
			var bad saml.ErrBadStatus
			if errors.As(err, &bad) || errors.Is(err, idpslo.ErrPartialLogout) {
				// This SP kept some or all of its sessions.
				state.partial = true
			} else if err != nil {
				http.Error(w, "invalid logout response", http.StatusBadRequest)
				return
			}
			next(w, r, key, state)

		default:
			http.Error(w, "not a logout message", http.StatusBadRequest)
		}
	})
}
