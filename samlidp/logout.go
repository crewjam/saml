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
//   - if the request carries any SessionIndex, any stored session with one
//     of those indexes and the request's NameID. This ends the session when the browser
//     did not send the session cookie, for example because the LogoutRequest
//     arrived in a cross-site POST. The SessionIndex is a random value the
//     IdP only discloses in the assertions it issues, so a service provider
//     can only end sessions it took part in this way.
//
// Without a SessionIndex, only the browser's own session is ended.
//
// A LogoutRequest received with the SOAP binding (if Options.SOAPLogout is
// set) comes from the service provider's server, so there is no session
// cookie: every stored session the request matches is ended. Without a
// SessionIndex, that is every session of the request's NameID, as
// saml-core-2.0-os §3.7.3.2 asks, and the same sessions whose other
// participants ServeSLO logs out. Any service provider registered with the
// server can thus end all the sessions of a NameID it knows, with a request
// signed with its key; include a SessionIndex to end only that session.
//
// Sessions are stored by NameID, so a request that identifies the principal
// with a BaseID (accepted only if the IdP's AcceptLogoutRequestBaseID is set)
// ends no session and returns an error matching saml.ErrUnsupported, and
// ServeSLO answers it with StatusResponder.
func (s *Server) InvalidateSession(w http.ResponseWriter, r *http.Request, req *saml.IdpLogoutRequest) error {
	if req.Request.NameID == nil {
		return fmt.Errorf("%w: cannot end the sessions of a principal identified by a BaseID", saml.ErrUnsupported)
	}
	if req.Binding == saml.SOAPBinding {
		return s.deleteSessionsMatching(req)
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		session := &saml.Session{}
		err := s.Store.Get(sessionKey(cookie.Value), session)
		switch {
		case err == nil && req.MatchesSession(session):
			if err := s.deleteSession(cookie.Value); err != nil {
				return err
			}
			s.expireSessionCookie(w, r)
			return nil
		case errors.Is(err, ErrNotFound):
			// The session is already gone; drop the stale cookie.
			s.expireSessionCookie(w, r)
		case err != nil:
			return err
		}
	}

	if !hasSessionIndex(&req.Request) {
		return nil
	}
	return s.deleteSessionsMatching(req)
}

// hasSessionIndex reports whether req carries a non-empty SessionIndex.
func hasSessionIndex(req *saml.LogoutRequest) bool {
	for _, sessionIndex := range req.AllSessionIndexes() {
		if sessionIndex.Value != "" {
			return true
		}
	}
	return false
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

// expireSessionCookie tells the browser to delete the session cookie. It
// has the attributes of the session cookie itself (see sessionCookie), so
// that browsers replace it.
func (s *Server) expireSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.sessionCookie(r, "", -1))
}

// sessionCookie returns the session cookie with value and maxAge.
//
// The cookie is Secure when the IdP is served over https: when its
// configured URL (Options.URL) is https, or when the request itself
// arrived over TLS. The configured URL is what counts behind a proxy that
// terminates TLS, where the request does not show that the browser used
// https.
//
// A Secure cookie is also SameSite=None, so that browsers send it with the
// cross-site POST of an AuthnRequest (HTTP-POST binding) to /sso and of a
// LogoutRequest to /slo; with the default (Lax) they do not, and the user
// would have to log in again on every such request. Browsers refuse
// SameSite=None on a cookie that is not Secure, so a cookie served over
// plain http keeps the browser default.
func (s *Server) sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	secure := r.TLS != nil || s.IDP.SSOURL.Scheme == "https"
	cookie := &http.Cookie{ //nolint:gosec // G124: SameSite is set to None below when Secure; plain http keeps the browser default
		Name:     sessionCookieName,
		Value:    value,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		Path:     "/",
	}
	if secure {
		cookie.SameSite = http.SameSiteNoneMode
	}
	return cookie
}
