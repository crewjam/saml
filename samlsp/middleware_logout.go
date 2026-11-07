package samlsp

import (
	"errors"
	"net/http"

	"github.com/crewjam/saml"
)

// SessionWithNameID is a session that knows the SAML NameID of the user it
// belongs to. HandleStartLogout needs it to tell the IDP whose session to end.
type SessionWithNameID interface {
	Session
	GetNameID() string
}

// GetNameID implements SessionWithNameID. It returns the NameID of the
// assertion the session was made from, which JWTSessionCodec stores as the
// JWT subject.
func (c JWTSessionClaims) GetNameID() string {
	return c.Subject
}

var _ SessionWithNameID = JWTSessionClaims{}

// errLogoutNoNameID is passed to OnError by HandleStartLogout when the
// session does not expose a NameID.
var errLogoutNoNameID = errors.New("saml: cannot start single logout: the session does not implement SessionWithNameID")

// errNoLogoutRequestTracker is passed to OnError when SP initiated single
// logout is used without a LogoutRequestTracker.
var errNoLogoutRequestTracker = errors.New("saml: single logout needs Middleware.LogoutRequestTracker")

// errSLOUnexpectedMessage is passed to OnError by ServeSLO when the request
// carries neither a SAMLRequest nor a SAMLResponse.
var errSLOUnexpectedMessage = errors.New("saml: single logout endpoint received neither a SAMLRequest nor a SAMLResponse")

// HandleStartLogout starts SP initiated single logout. It deletes the local
// session and sends the browser to the IDP with a LogoutRequest for the
// session's NameID (and SessionIndex, if known), using the HTTP-Redirect
// binding if the IDP supports it and the HTTP-POST binding otherwise. The
// request is tracked with LogoutRequestTracker, and its index is the
// RelayState. The IDP answers with a LogoutResponse to
// ServiceProvider.SloURL, which ServeHTTP handles (see ServeSLO).
//
// If the request has no session, or the IDP metadata lists no
// SingleLogoutService, only the local session is ended and the browser is
// redirected to "/".
//
// To use it, route a path of your application to it, for example:
//
//	http.HandleFunc("/logout", samlMiddleware.HandleStartLogout)
func (m *Middleware) HandleStartLogout(w http.ResponseWriter, r *http.Request) {
	session, err := m.Session.GetSession(r)
	if errors.Is(err, ErrNoSession) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if err != nil {
		m.OnError(w, r, err)
		return
	}

	sessionWithNameID, ok := session.(SessionWithNameID)
	if !ok {
		m.OnError(w, r, errLogoutNoNameID)
		return
	}
	nameID := sessionWithNameID.GetNameID()
	var opts []saml.LogoutRequestOption
	if sa, ok := session.(SessionWithAttributes); ok {
		if sessionIndex := sa.GetAttributes().Get(claimNameSessionIndex); sessionIndex != "" {
			opts = append(opts, saml.WithSessionIndex(sessionIndex))
		}
	}

	binding := m.sloBinding()
	if binding == "" {
		// The IDP does not support single logout; end the local session only.
		if err := m.Session.DeleteSession(w, r); err != nil {
			m.OnError(w, r, err)
			return
		}
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if m.LogoutRequestTracker == nil {
		m.OnError(w, r, errNoLogoutRequestTracker)
		return
	}

	logoutRequest, err := m.ServiceProvider.MakeLogoutRequest(
		m.ServiceProvider.GetSLOBindingLocation(binding), nameID, opts...)
	if err != nil {
		m.OnError(w, r, err)
		return
	}
	relayState, err := m.LogoutRequestTracker.TrackRequest(w, r, logoutRequest.ID)
	if err != nil {
		m.OnError(w, r, err)
		return
	}

	if err := m.Session.DeleteSession(w, r); err != nil {
		m.OnError(w, r, err)
		return
	}

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := m.ServiceProvider.RedirectLogoutRequestURL(logoutRequest, relayState)
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	m.writePostForm(w, postRequestScriptHash, logoutRequest.PostWithNonce(relayState, m.scriptNonce(r)))
}

// sloBinding returns the binding to send logout messages to the IDP with:
// HTTP-Redirect if the IDP supports it, otherwise HTTP-POST if it supports
// that, otherwise "".
func (m *Middleware) sloBinding() string {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		if m.ServiceProvider.GetSLOBindingLocation(binding) != "" {
			return binding
		}
	}
	return ""
}

// ServeSLO handles requests for the SAML SingleLogoutService endpoint,
// ServiceProvider.SloURL, using either the HTTP-Redirect or the HTTP-POST
// binding.
//
// A LogoutResponse is the IDP's answer to a LogoutRequest sent by
// HandleStartLogout. It is accepted only if its InResponseTo is the ID of a
// LogoutRequest pending in LogoutRequestTracker. Once it is validated, the
// request stops being tracked, the session (if any is left) is deleted and
// the browser is redirected to "/".
//
// A LogoutRequest is IDP initiated single logout. Once it is validated, the
// session of the requesting browser is deleted and the browser is sent back
// to the IDP with a LogoutResponse. A SessionProvider that keeps sessions on
// the server, rather than in a cookie, should also end the sessions of the
// request's NameID; such applications can handle SloURL themselves with
// ServiceProvider.ValidateLogoutRequest.
//
// Invalid messages are passed to OnError.
func (m *Middleware) ServeSLO(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		m.OnError(w, r, err)
		return
	}

	switch {
	case r.Form.Get("SAMLRequest") != "":
		m.serveSLORequest(w, r)
	case r.Form.Get("SAMLResponse") != "":
		m.serveSLOResponse(w, r)
	default:
		m.OnError(w, r, errSLOUnexpectedMessage)
	}
}

func (m *Middleware) serveSLOResponse(w http.ResponseWriter, r *http.Request) {
	if m.LogoutRequestTracker == nil {
		m.OnError(w, r, errNoLogoutRequestTracker)
		return
	}

	trackedRequests := m.LogoutRequestTracker.GetTrackedRequests(r)
	possibleRequestIDs := make([]string, 0, len(trackedRequests))
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	logoutResponse, err := m.ServiceProvider.ParseLogoutResponse(r, possibleRequestIDs)
	if err != nil {
		m.OnError(w, r, err)
		return
	}

	for _, tr := range trackedRequests {
		if tr.SAMLRequestID != logoutResponse.InResponseTo {
			continue
		}
		if err := m.LogoutRequestTracker.StopTrackingRequest(w, r, tr.Index); err != nil {
			m.OnError(w, r, err)
			return
		}
	}

	if err := m.Session.DeleteSession(w, r); err != nil {
		m.OnError(w, r, err)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (m *Middleware) serveSLORequest(w http.ResponseWriter, r *http.Request) {
	logoutRequest, err := m.ServiceProvider.ValidateLogoutRequest(r)
	if err != nil {
		m.OnError(w, r, err)
		return
	}

	if err := m.Session.DeleteSession(w, r); err != nil {
		m.OnError(w, r, err)
		return
	}

	// The RelayState of the request must be returned unchanged with the
	// response (saml-bindings-2.0-os sections 3.4.3 and 3.5.3).
	relayState := r.Form.Get("RelayState")
	switch m.sloBinding() {
	case saml.HTTPRedirectBinding:
		redirectURL, err := m.ServiceProvider.MakeRedirectLogoutResponse(logoutRequest.ID, relayState)
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound) //nolint:gosec // the target is the IDP's SLO location from its metadata; the RelayState is only a query parameter
	case saml.HTTPPostBinding:
		resp, err := m.ServiceProvider.MakeLogoutResponse(
			m.ServiceProvider.GetSLOBindingLocation(saml.HTTPPostBinding), logoutRequest.ID)
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		m.writePostForm(w, postResponseScriptHash, resp.PostWithNonce(relayState, m.scriptNonce(r)))
	default:
		// The IDP sent a LogoutRequest but lists no endpoint for the
		// response; there is nowhere to answer it.
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
