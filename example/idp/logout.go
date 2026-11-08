package main

import (
	"crypto/rand"
	"errors"
	"log"
	"net/http"
	"slices"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp/idpslo"
)

// logoutProgress is where a single logout is: the SP request it will
// answer, if an SP started it, the participants still to visit, whether
// some could not be logged out, and the LogoutRequest sent to the one
// being visited.
type logoutProgress struct {
	request   *idpslo.Request // nil for a logout started on the portal
	remaining []saml.SessionParticipant
	partial   bool

	current   string // the SP being visited
	requestID string // the LogoutRequest sent to it
}

// slo is the single logout service. It receives the LogoutRequest of an
// SP that starts a logout, and the LogoutResponses of the SPs the IdP
// visits to propagate one.
func (p *identityProvider) slo(w http.ResponseWriter, r *http.Request) {
	switch {
	case idpslo.IsRequest(r):
		p.sloRequest(w, r)
	case idpslo.IsResponse(r):
		p.sloResponse(w, r)
	default:
		http.Error(w, "not a logout message", http.StatusBadRequest)
	}
}

// sloRequest handles an SP's LogoutRequest: it ends the IdP session the
// request names, logs the user out of its other participants, then
// answers the SP.
func (p *identityProvider) sloRequest(w http.ResponseWriter, r *http.Request) {
	req, err := p.logout.ParseRequest(r.Context(), r)
	if err != nil {
		log.Printf("refused a LogoutRequest: %v", err)
		idpslo.WriteRequestError(w, r)
		return
	}
	// Find the session by the NameID and SessionIndex the IdP gave the SP,
	// not by the cookie, which a cross-site POST does not carry.
	progress := &logoutProgress{request: req}
	if s, participants := p.sessionOf(req); s != nil {
		p.endSession(w, s)
		for _, participant := range participants {
			if !req.Matches(participant) {
				progress.remaining = append(progress.remaining, participant)
			}
		}
	}
	// With no session, the user is already logged out of the IdP.
	p.continueLogout(w, r, rand.Text(), progress)
}

// sessionOf returns the session that req, a verified LogoutRequest, names,
// and its participants, or nil.
func (p *identityProvider) sessionOf(req *idpslo.Request) (*session, []saml.SessionParticipant) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		for _, participant := range s.participants {
			if req.Matches(participant) {
				return s, slices.Clone(s.participants)
			}
		}
	}
	return nil, nil
}

// startLogout logs the user out of the IdP and of every SP they used it
// for, from the portal.
func (p *identityProvider) startLogout(w http.ResponseWriter, r *http.Request) {
	s := p.currentSession(r)
	if s == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	p.mu.Lock()
	participants := slices.Clone(s.participants)
	p.mu.Unlock()
	p.endSession(w, s)
	p.continueLogout(w, r, rand.Text(), &logoutProgress{remaining: participants})
}

// sloResponse handles the LogoutResponse of an SP the IdP visited, and
// goes on to the next one. The RelayState names the logout.
func (p *identityProvider) sloResponse(w http.ResponseWriter, r *http.Request) {
	key := r.FormValue("RelayState")
	p.mu.Lock()
	progress := p.logouts[key]
	p.mu.Unlock()
	if progress == nil {
		http.Error(w, "no logout in progress", http.StatusBadRequest)
		return
	}
	_, err := p.logout.ParseResponse(r.Context(), r, progress.current, progress.requestID)
	var bad saml.ErrBadStatus
	switch {
	case errors.As(err, &bad):
		log.Printf("%q could not log the user out: %q", progress.current, bad.Status)
		progress.partial = true
	case err != nil:
		log.Printf("refused a LogoutResponse: %v", err)
		http.Error(w, "invalid logout response", http.StatusBadRequest)
		return
	}
	p.continueLogout(w, r, key, progress)
}

// continueLogout sends the browser to the next participant to log out,
// and, when there are none left, answers the SP that started the logout,
// or goes back to the portal.
func (p *identityProvider) continueLogout(w http.ResponseWriter, r *http.Request, key string, progress *logoutProgress) {
	for len(progress.remaining) > 0 {
		participant := progress.remaining[0]
		progress.remaining = progress.remaining[1:]
		msg, err := p.logout.Request(r.Context(), participant, key)
		if err != nil {
			// For example idpslo.ErrNoEndpoint: the SP has no single logout.
			log.Printf("cannot log the user out of %q: %v", participant.ServiceProviderID, err)
			progress.partial = true
			continue
		}
		progress.current, progress.requestID = participant.ServiceProviderID, msg.ID
		p.mu.Lock()
		p.logouts[key] = progress
		p.mu.Unlock()
		msg.Write(w)
		return
	}

	p.mu.Lock()
	delete(p.logouts, key)
	p.mu.Unlock()
	if progress.request == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	var opts []idpslo.ResponseOption
	if progress.partial {
		opts = append(opts, idpslo.PartialLogout)
	}
	msg, err := p.logout.Response(r.Context(), progress.request, opts...)
	if err != nil {
		log.Printf("cannot answer the LogoutRequest of %q: %v", progress.request.ServiceProvider, err)
		http.Error(w, "cannot answer the logout request", http.StatusInternalServerError)
		return
	}
	msg.Write(w)
}
