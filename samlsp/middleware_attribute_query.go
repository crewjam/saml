package samlsp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
)

// ErrSessionNameIDUnknown is returned by Middleware.QueryAttributes when the
// session does not record the full NameID of its user: a session issued
// before JWTSessionCodec recorded the NameID's Format and qualifiers, or one
// from a SessionProvider or SessionCodec that does not implement
// SessionWithSAMLNameID. The user must log in again to get a session that
// does.
var ErrSessionNameIDUnknown = errors.New("saml: the session does not record the user's full NameID; the user must log in again")

// QueryAttributes asks the IdP's attribute authority for attributes of the
// user of the request's session, with ServiceProvider.QueryAttributes, and
// returns what it returns. The query is made with the request's context.
//
// The user is named by the NameID the session was made from, with the
// Format and qualifiers the IdP issued it with, which the session must
// record (see SessionWithSAMLNameID). The session is the one RequireAccount
// put in the request's context or, if there is none, the one Session
// returns for the request.
//
// It returns an error matching ErrNoSession if the request has no session,
// and one matching ErrSessionNameIDUnknown if the session does not record
// the full NameID, for example because it was issued by an earlier version
// of this package; the user must then log in again.
//
// attributes, if any, restricts the query to those attributes, as for
// ServiceProvider.MakeAttributeQuery. The result describes the user; it does
// not authenticate them.
func (m *Middleware) QueryAttributes(r *http.Request, attributes ...saml.Attribute) (*saml.AttributeQueryResult, error) {
	nameID, err := m.sessionSAMLNameID(r)
	if err != nil {
		return nil, fmt.Errorf("saml: cannot query attributes: %w", err)
	}
	return m.ServiceProvider.QueryAttributes(r.Context(), nameID, attributes...)
}

// sessionSAMLNameID returns the full NameID of the request's session.
func (m *Middleware) sessionSAMLNameID(r *http.Request) (saml.NameID, error) {
	session := SessionFromContext(r.Context())
	if session == nil {
		if m.Session == nil {
			return saml.NameID{}, ErrNoSession
		}
		var err error
		session, err = m.Session.GetSession(r)
		if err != nil {
			return saml.NameID{}, err
		}
		if session == nil {
			return saml.NameID{}, ErrNoSession
		}
	}
	sessionWithNameID, ok := session.(SessionWithSAMLNameID)
	if !ok {
		return saml.NameID{}, fmt.Errorf("%w (session type %T does not implement SessionWithSAMLNameID)",
			ErrSessionNameIDUnknown, session)
	}
	nameID, ok := sessionWithNameID.GetSAMLNameID()
	if !ok {
		return saml.NameID{}, fmt.Errorf("%w (the session predates the NameID Format claim)", ErrSessionNameIDUnknown)
	}
	return nameID, nil
}
