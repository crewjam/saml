package samlidp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
)

var _ saml.SessionParticipantTracker = (*Server)(nil)

func sessionParticipantsKey(sessionID string) string {
	return fmt.Sprintf("/session-participants/%s", sessionID)
}

// AddSessionParticipant implements saml.SessionParticipantTracker. It
// records participant under the session's ID, unless it is already
// recorded.
func (s *Server) AddSessionParticipant(_ *http.Request, session *saml.Session, participant saml.SessionParticipant) error {
	if session == nil || session.ID == "" {
		return nil
	}
	participants, err := s.storedSessionParticipants(session.ID)
	if err != nil {
		return err
	}
	for _, p := range participants {
		if p == participant {
			return nil
		}
	}
	return s.Store.Put(sessionParticipantsKey(session.ID), append(participants, participant))
}

// SessionParticipants implements saml.SessionParticipantTracker. It returns
// the participants recorded for every stored session that match selects.
func (s *Server) SessionParticipants(_ *http.Request, match func(*saml.Session) bool) ([]saml.SessionParticipant, error) {
	ids, err := s.Store.List("/sessions/")
	if err != nil {
		return nil, err
	}
	var rv []saml.SessionParticipant
	for _, id := range ids {
		session := &saml.Session{}
		if err := s.Store.Get(sessionKey(id), session); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		if !match(session) {
			continue
		}
		participants, err := s.storedSessionParticipants(id)
		if err != nil {
			return nil, err
		}
		rv = append(rv, participants...)
	}
	return rv, nil
}

func (s *Server) storedSessionParticipants(sessionID string) ([]saml.SessionParticipant, error) {
	var participants []saml.SessionParticipant
	err := s.Store.Get(sessionParticipantsKey(sessionID), &participants)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	return participants, err
}

// deleteSession deletes the stored session id and its participants.
func (s *Server) deleteSession(id string) error {
	if err := s.Store.Delete(sessionKey(id)); err != nil {
		return err
	}
	if err := s.Store.Delete(sessionParticipantsKey(id)); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

const logoutPageTemplate = `<html><p>You are not logged in.</p></html>`

// HandleLogout handles `GET /logout` and `POST /logout`: IdP-initiated single
// logout of the browser's session. The session cookie is expired, the
// session is logged out of every service provider it was used for (see
// saml.IdentityProvider.StartLogout), and then the session is deleted. When
// the logout is done, a page tells the user they are logged out.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(logoutPageTemplate))
		return
	}

	session := &saml.Session{}
	switch err := s.Store.Get(sessionKey(cookie.Value), session); {
	case errors.Is(err, ErrNotFound):
		session = nil
	case err != nil:
		s.logger.Printf("ERROR: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	expireSessionCookie(w, r)
	s.IDP.StartLogout(w, r, session, "")
	if session != nil {
		if err := s.deleteSession(session.ID); err != nil {
			s.logger.Printf("ERROR: cannot delete session: %s", err)
		}
	}
}
