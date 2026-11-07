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
// session's NameID (and its SessionIndexes, if known), using LogoutBinding if it
// is set and the IDP supports it, otherwise the HTTP-Redirect binding if the
// IDP supports it and the HTTP-POST binding otherwise. The
// request is tracked with LogoutRequestTracker, and its index is the
// RelayState. The IDP answers with a LogoutResponse to
// ServiceProvider.SloURL, which ServeHTTP handles (see ServeSLO).
//
// If LogoutBinding is saml.SOAPBinding, the IDP metadata lists a SOAP
// SingleLogoutService and the session knows the full NameID of its user (see
// SessionWithSAMLNameID), the LogoutRequest is instead sent to the IDP from
// the server, with ServiceProvider.SendSOAPLogoutRequest and the request's
// context (back-channel single logout, saml-profiles §4.4). The local
// session is then deleted and the browser redirected to "/", as after a
// LogoutResponse. If the IDP cannot be reached or does not answer Success,
// the error is passed to OnError (whose response is discarded), the local
// session is still deleted, and the browser is sent to the IDP with a
// LogoutRequest over a front-channel binding, if the IDP supports one, so
// that the IDP can still end its session with the browser's help;
// otherwise it is redirected to "/".
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
		// The session keeps the SessionIndex of every AuthnStatement of the
		// assertion; the request lists them all (saml-core-2.0-os §3.7.1).
		if sessionIndexes := sa.GetAttributes()[claimNameSessionIndex]; len(sessionIndexes) > 0 {
			opts = append(opts, saml.WithSessionIndexes(sessionIndexes...))
		}
	}

	if soapNameID, ok := m.soapLogoutNameID(session); ok {
		m.startSOAPLogout(w, r, soapNameID, opts)
		return
	}
	m.startFrontChannelLogout(w, r, nameID, opts, true)
}

// startFrontChannelLogout sends the browser to the IDP with a LogoutRequest
// for nameID, over the binding sloBinding picks, and deletes the local
// session first if deleteSession is set. If the IDP supports no such
// binding, the browser is redirected to "/".
func (m *Middleware) startFrontChannelLogout(w http.ResponseWriter, r *http.Request, nameID string, opts []saml.LogoutRequestOption, deleteSession bool) {
	binding := m.sloBinding()
	if binding == "" {
		// The IDP does not support single logout; end the local session only.
		if deleteSession {
			if err := m.Session.DeleteSession(w, r); err != nil {
				m.OnError(w, r, err)
				return
			}
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

	if deleteSession {
		if err := m.Session.DeleteSession(w, r); err != nil {
			m.OnError(w, r, err)
			return
		}
	}

	m.sendLogoutRequest(w, r, binding, logoutRequest, relayState)
}

// sendLogoutRequest sends logoutRequest to the IDP with binding.
func (m *Middleware) sendLogoutRequest(w http.ResponseWriter, r *http.Request, binding string, logoutRequest *saml.LogoutRequest, relayState string) {
	switch binding {
	case saml.HTTPRedirectBinding:
		redirectURL, err := m.ServiceProvider.RedirectLogoutRequestURL(logoutRequest, relayState)
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		setNoCacheHeaders(w.Header())
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	case saml.HTTPPostSimpleSignBinding:
		// The SimpleSign signature replaces the enveloped XML signature, as
		// in ServiceProvider.MakeSimpleSignLogoutRequest.
		logoutRequest.Signature = nil
		form, err := logoutRequest.SimpleSignWithNonce(relayState, m.scriptNonce(r), &m.ServiceProvider)
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		// Same auto-submit script, so the same hash, as the HTTP-POST form.
		m.writePostForm(w, postRequestScriptHash, form)
	default:
		m.writePostForm(w, postRequestScriptHash, logoutRequest.PostWithNonce(relayState, m.scriptNonce(r)))
	}
}

// sloBinding returns the binding to send logout messages to the IDP with
// through the browser: LogoutBinding if it is set, is not the SOAP binding,
// and the IDP supports it, otherwise HTTP-Redirect if the IDP supports it,
// otherwise HTTP-POST if it supports that, otherwise "".
func (m *Middleware) sloBinding() string {
	if m.LogoutBinding != "" && m.LogoutBinding != saml.SOAPBinding &&
		m.ServiceProvider.GetSLOBindingLocation(m.LogoutBinding) != "" {
		return m.LogoutBinding
	}
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		if m.ServiceProvider.GetSLOBindingLocation(binding) != "" {
			return binding
		}
	}
	return ""
}

// ServeSLO handles requests for the SAML SingleLogoutService endpoint,
// ServiceProvider.SloURL, using the HTTP-Redirect, HTTP-POST or
// HTTP-POST-SimpleSign binding.
//
// A LogoutResponse is the IDP's answer to a LogoutRequest sent by
// HandleStartLogout. It is accepted only if its InResponseTo is the ID of a
// LogoutRequest pending in LogoutRequestTracker. Once it is validated, the
// request stops being tracked, the session (if any is left) is deleted and
// the browser is redirected to "/".
//
// A LogoutRequest is IDP initiated single logout. Once it is validated, the
// session of the requesting browser is deleted and the browser is sent back
// to the IDP with a LogoutResponse. If Session implements
// SessionTerminator, the sessions the request names are also ended there,
// as for a request sent with the SOAP binding, so that other copies of the
// session, in other browsers, are refused too: those with one of its
// SessionIndexes or, if it has none, every session of its NameID issued
// before it. A session provider that cannot do that
// (ErrSessionTerminationUnsupported) only has the browser's session
// deleted and the IDP is answered with Success, as before: the session of
// the browser it sent has ended, and the provider never promised more. Any
// other error ending them is passed to OnError, whose response is
// discarded, and the IDP is answered with Success and the second-level
// status PartialLogout (saml-core-2.0-os §3.7.3.2): the browser's session
// has ended, but other copies of it may still be accepted.
//
// A POST with Content-Type text/xml is a LogoutRequest sent with the SOAP
// binding (back-channel single logout, saml-profiles §4.4): the IDP sends it
// itself, without the browser. It must be signed by the IDP (see
// saml.ServiceProvider.ValidateSOAPLogoutRequest). Once it is validated, the
// sessions it names are ended with the session provider's
// TerminateSessions (see SessionTerminator), and the IDP is answered with a
// signed LogoutResponse with the status Success, or Responder if Session
// does not implement SessionTerminator or could not end them. An invalid
// SOAP request is passed to OnError, whose response is discarded, and
// answered with a SOAP Fault. To have the IDP use it, advertise the SOAP
// binding in the SP metadata (see Options.LogoutBindings).
//
// Invalid messages are passed to OnError.
func (m *Middleware) ServeSLO(w http.ResponseWriter, r *http.Request) {
	if saml.IsSOAPRequest(r) {
		m.serveSOAPLogoutRequest(w, r)
		return
	}
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
	status := m.terminateFrontChannelSessions(r, logoutRequest)

	// The RelayState of the request must be returned unchanged with the
	// response (saml-bindings-2.0-os sections 3.4.3 and 3.5.3).
	relayState := r.Form.Get("RelayState")
	switch binding := m.sloBinding(); binding {
	case saml.HTTPRedirectBinding:
		redirectURL, err := m.ServiceProvider.MakeRedirectLogoutResponseWithStatus(logoutRequest.ID, relayState, status)
		if err != nil {
			m.OnError(w, r, err)
			return
		}
		setNoCacheHeaders(w.Header())
		http.Redirect(w, r, redirectURL.String(), http.StatusFound) //nolint:gosec // the target is the IDP's SLO location from its metadata; the RelayState is only a query parameter
	case saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding:
		m.postLogoutResponse(w, r, binding, logoutRequest.ID, relayState, status)
	default:
		// The IDP sent a LogoutRequest but lists no endpoint for the
		// response; there is nowhere to answer it.
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

// postLogoutResponse sends the IDP a LogoutResponse to the LogoutRequest
// logoutRequestID, with status, in an auto-submitting form, with the
// HTTP-POST or the HTTP-POST-SimpleSign binding.
func (m *Middleware) postLogoutResponse(w http.ResponseWriter, r *http.Request, binding, logoutRequestID, relayState string, status saml.Status) {
	resp, err := m.ServiceProvider.MakeLogoutResponseWithStatus(
		m.ServiceProvider.GetSLOBindingLocation(binding), logoutRequestID, status)
	if err != nil {
		m.OnError(w, r, err)
		return
	}
	if binding != saml.HTTPPostSimpleSignBinding {
		m.writePostForm(w, postResponseScriptHash, resp.PostWithNonce(relayState, m.scriptNonce(r)))
		return
	}
	// The SimpleSign signature replaces the enveloped XML signature, as in
	// ServiceProvider.MakeSimpleSignLogoutResponse.
	resp.Signature = nil
	form, err := resp.SimpleSignWithNonce(relayState, m.scriptNonce(r), &m.ServiceProvider)
	if err != nil {
		m.OnError(w, r, err)
		return
	}
	// Same auto-submit script, so the same hash, as the HTTP-POST form.
	m.writePostForm(w, postResponseScriptHash, form)
}
