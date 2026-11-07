package samlidp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
)

// sessionCookieName is the name of the cookie that holds the ID of the
// user's IdP session.
const sessionCookieName = "session"

var _ saml.SessionInvalidator = (*Server)(nil)

// InvalidateSession implements saml.SessionInvalidator. It is called by the
// IdP's ServeSLO for a valid LogoutRequest from a service provider and
// deletes the sessions the request refers to (see
// saml.IdpLogoutRequest.MatchesSession):
//
//   - the browser's session, named by its session cookie, if it matches the
//     request. The session cookie is then expired.
//   - if the request carries a SessionIndex, any stored session with that
//     index and the request's NameID. This ends the session when the browser
//     did not send the session cookie, for example because the LogoutRequest
//     arrived in a cross-site POST. The SessionIndex is a random value the
//     IdP only discloses in the assertions it issues, so a service provider
//     can only end sessions it took part in this way.
//
// Without a SessionIndex, only the browser's own session is ended.
func (s *Server) InvalidateSession(w http.ResponseWriter, r *http.Request, req *saml.IdpLogoutRequest) error {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		session := &saml.Session{}
		err := s.Store.Get(sessionKey(cookie.Value), session)
		switch {
		case err == nil && req.MatchesSession(session):
			if err := s.deleteSession(cookie.Value); err != nil {
				return err
			}
			expireSessionCookie(w, r)
			return nil
		case errors.Is(err, ErrNotFound):
			// The session is already gone; drop the stale cookie.
			expireSessionCookie(w, r)
		case err != nil:
			return err
		}
	}

	if req.Request.SessionIndex == nil || req.Request.SessionIndex.Value == "" {
		return nil
	}
	return s.deleteSessionsMatching(req)
}

// deleteSessionsMatching deletes every stored session that req matches.
func (s *Server) deleteSessionsMatching(req *saml.IdpLogoutRequest) error {
	ids, err := s.Store.List("/sessions/")
	if err != nil {
		return err
	}
	for _, id := range ids {
		session := &saml.Session{}
		if err := s.Store.Get(sessionKey(id), session); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return err
		}
		if !req.MatchesSession(session) {
			continue
		}
		if err := s.deleteSession(id); err != nil {
			return err
		}
	}
	return nil
}

func sessionKey(id string) string {
	return fmt.Sprintf("/sessions/%s", id)
}

// expireSessionCookie tells the browser to delete the session cookie.
func expireSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is set when served over https, as for the session cookie itself
		Name:     sessionCookieName,
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.URL.Scheme == "https",
		Path:     "/",
	})
}
