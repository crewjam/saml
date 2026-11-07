package samlidp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"

	"github.com/crewjam/saml"
)

var _ saml.SessionParticipantTracker = (*Server)(nil)

// legacySessionParticipantsKey is where participants were stored before
// each had its own key: one list per session. It is still read and deleted,
// so participants recorded by an older version are not lost.
func legacySessionParticipantsKey(sessionID string) string {
	return fmt.Sprintf("/session-participants/%s", sessionID)
}

// sessionParticipantsPrefix is the prefix of the keys of the participants
// recorded for a session.
func sessionParticipantsPrefix(sessionID string) string {
	return fmt.Sprintf("/session-participants/%s/", sessionID)
}

// sessionParticipantKey is the key participant is recorded under: the same
// participant always has the same key, so recording it again changes
// nothing.
func sessionParticipantKey(sessionID string, participant saml.SessionParticipant) (string, error) {
	buf, err := json.Marshal(participant)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(buf)
	return sessionParticipantsPrefix(sessionID) + hex.EncodeToString(digest[:]), nil
}

// AddSessionParticipant implements saml.SessionParticipantTracker. It
// records participant for the session, unless it is already recorded.
//
// Each participant is stored under its own key, derived from its value, so
// recording one is a single Put: there is no read-modify-write to lose a
// participant recorded at the same time, and no lock is held while the
// Store is called, even by servers that share a Store.
func (s *Server) AddSessionParticipant(_ *http.Request, session *saml.Session, participant saml.SessionParticipant) error {
	if session == nil || session.ID == "" {
		return nil
	}
	key, err := sessionParticipantKey(session.ID, participant)
	if err != nil {
		return err
	}
	return s.Store.Put(key, participant)
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

// storedSessionParticipants returns the participants recorded for the
// session sessionID, in a stable order.
func (s *Server) storedSessionParticipants(sessionID string) ([]saml.SessionParticipant, error) {
	var participants []saml.SessionParticipant
	err := s.Store.Get(legacySessionParticipantsKey(sessionID), &participants)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	names, err := s.Store.List(sessionParticipantsPrefix(sessionID))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	for _, name := range names {
		var participant saml.SessionParticipant
		if err := s.Store.Get(sessionParticipantsPrefix(sessionID)+name, &participant); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // deleted since it was listed
			}
			return nil, err
		}
		if !slices.Contains(participants, participant) {
			participants = append(participants, participant)
		}
	}
	return participants, nil
}

// deleteSession deletes the stored session id and its participants.
func (s *Server) deleteSession(id string) error {
	if err := s.Store.Delete(sessionKey(id)); err != nil {
		return err
	}
	names, err := s.Store.List(sessionParticipantsPrefix(id))
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := s.Store.Delete(sessionParticipantsPrefix(id) + name); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	if err := s.Store.Delete(legacySessionParticipantsKey(id)); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

const logoutPageTemplate = `<html xmlns="http://www.w3.org/1999/xhtml">` +
	`<head><title>Logged out</title></head>` +
	`<body><p>You are not logged in.</p></body>` +
	`</html>`

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

	s.expireSessionCookie(w, r)
	s.IDP.StartLogout(w, r, session, "")
	if session != nil {
		if err := s.deleteSession(session.ID); err != nil {
			s.logger.Printf("ERROR: cannot delete session: %s", err)
		}
	}
}
