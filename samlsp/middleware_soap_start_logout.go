package samlsp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
)

// errSOAPStartLogoutFailed wraps the reason a LogoutRequest that
// HandleStartLogout sent with the SOAP binding did not end the session at
// the IDP; it is passed to OnError.
var errSOAPStartLogoutFailed = errors.New("saml: the IDP did not end the session for a back-channel LogoutRequest")

// soapLogoutNameID returns the NameID to send the IDP a LogoutRequest for
// session with the SOAP binding, and whether that binding is to be used:
// LogoutBinding must select it, the IDP metadata must list a SOAP
// SingleLogoutService, and session must know the full NameID of its user.
//
// A session made before samlsp recorded the full NameID (see
// SessionWithSAMLNameID) knows only its value. The front-channel request
// carries the NameID Format and qualifiers this service provider asks
// for, as it always has; over SOAP, without the browser's cookie at the IDP,
// the NameID is all the IDP has to find the session by, so such sessions
// are logged out through the browser instead.
func (m *Middleware) soapLogoutNameID(session Session) (saml.NameID, bool) {
	if m.LogoutBinding != saml.SOAPBinding || m.ServiceProvider.GetSLOBindingLocation(saml.SOAPBinding) == "" {
		return saml.NameID{}, false
	}
	withSAMLNameID, ok := session.(SessionWithSAMLNameID)
	if !ok {
		return saml.NameID{}, false
	}
	return withSAMLNameID.GetSAMLNameID()
}

// startSOAPLogout sends the IDP a LogoutRequest for nameID with the SOAP
// binding, deletes the local session whatever the outcome, and redirects
// the browser to "/" if the IDP ended its session. Otherwise the error is
// passed to OnError, and the browser is sent to the IDP with a front-channel
// LogoutRequest, if the IDP supports one, so that the IDP gets a second
// chance to end its session, using its own cookie, and the user sees its
// answer. Without one, the browser is redirected to "/".
func (m *Middleware) startSOAPLogout(w http.ResponseWriter, r *http.Request, nameID saml.NameID, opts []saml.LogoutRequestOption) {
	soapErr := m.sendSOAPLogoutRequest(r, nameID, opts)

	if err := m.Session.DeleteSession(w, r); err != nil {
		m.OnError(w, r, err)
		return
	}
	if soapErr == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	m.reportBackChannelError(r, fmt.Errorf("%w: %w", errSOAPStartLogoutFailed, soapErr))
	if m.sloBinding() == "" || m.LogoutRequestTracker == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	m.startFrontChannelLogout(w, r, nameID.Value, opts, false)
}

// sendSOAPLogoutRequest sends the IDP a LogoutRequest for nameID with the
// SOAP binding and the context of r, and returns an error unless the IDP
// answered Success.
func (m *Middleware) sendSOAPLogoutRequest(r *http.Request, nameID saml.NameID, opts []saml.LogoutRequestOption) error {
	logoutRequest, err := m.ServiceProvider.MakeSOAPLogoutRequest(nameID, opts...)
	if err != nil {
		return err
	}
	_, err = m.ServiceProvider.SendSOAPLogoutRequest(r.Context(), logoutRequest)
	return err
}
