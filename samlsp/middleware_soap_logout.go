package samlsp

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
)

// errSOAPLogoutNotTerminated wraps the reason ServeSLO answered a SOAP
// LogoutRequest with the status Responder; it is passed to OnError.
var errSOAPLogoutNotTerminated = errors.New("saml: cannot end the sessions named by a back-channel LogoutRequest")

// serveSOAPLogoutRequest answers a LogoutRequest sent by the IDP with the
// SOAP binding.
func (m *Middleware) serveSOAPLogoutRequest(w http.ResponseWriter, r *http.Request) {
	logoutRequest, err := m.ServiceProvider.ValidateSOAPLogoutRequest(r)
	if err != nil {
		m.reportBackChannelError(r, err)
		// Say no more than that the request was refused: whoever sent it
		// has not been authenticated.
		_ = saml.WriteSOAPFault(w, "the LogoutRequest was refused")
		return
	}

	statusCode := saml.StatusSuccess
	if err := m.terminateSessions(r, logoutRequest); err != nil {
		m.reportBackChannelError(r, fmt.Errorf("%w: %w", errSOAPLogoutNotTerminated, err))
		statusCode = saml.StatusResponder
	}

	resp, err := m.ServiceProvider.MakeSOAPLogoutResponse(logoutRequest.ID, saml.Status{
		StatusCode: saml.StatusCode{Value: statusCode},
	})
	if err != nil {
		m.reportBackChannelError(r, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := saml.WriteSOAPLogoutResponse(w, resp); err != nil {
		m.reportBackChannelError(r, err)
	}
}

// terminateSessions ends the sessions logoutRequest names with Session, if
// it implements SessionTerminator.
func (m *Middleware) terminateSessions(r *http.Request, logoutRequest *saml.LogoutRequest) error {
	terminator, ok := m.Session.(SessionTerminator)
	if !ok {
		return fmt.Errorf("%w: %T does not implement SessionTerminator", ErrSessionTerminationUnsupported, m.Session)
	}
	return terminator.TerminateSessions(r.Context(), logoutRequest)
}

// reportBackChannelError passes err to OnError, for logging, and discards
// what OnError writes: the request comes from the IDP, not a browser, and is
// answered with a SOAP message instead.
func (m *Middleware) reportBackChannelError(r *http.Request, err error) {
	m.OnError(&discardResponseWriter{header: http.Header{}}, r, err)
}

// discardResponseWriter is an http.ResponseWriter that discards what is
// written to it.
type discardResponseWriter struct {
	header http.Header
}

func (d *discardResponseWriter) Header() http.Header         { return d.header }
func (d *discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardResponseWriter) WriteHeader(int)             {}

// terminateFrontChannelSessions ends the sessions that logoutRequest, a
// LogoutRequest the IDP sent through the browser, names with Session, if it
// implements SessionTerminator, so that copies of them held elsewhere are
// refused as after a back-channel LogoutRequest, and returns the status to
// answer the IDP with. The browser's own session has already been deleted,
// so the top-level status is always Success. If the provider cannot end
// sessions on the server at all, nothing more was promised and that is all.
// Any other failure is passed to OnError, whose response is discarded, and
// the status carries the second-level status PartialLogout
// (saml-core-2.0-os §3.7.3.2), as other copies of the sessions may still be
// accepted.
func (m *Middleware) terminateFrontChannelSessions(r *http.Request, logoutRequest *saml.LogoutRequest) saml.Status {
	status := saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}
	terminator, ok := m.Session.(SessionTerminator)
	if !ok {
		return status
	}
	err := terminator.TerminateSessions(r.Context(), logoutRequest)
	if err == nil || errors.Is(err, ErrSessionTerminationUnsupported) {
		return status
	}
	m.reportBackChannelError(r, fmt.Errorf("%w: %w", errFrontChannelLogoutNotTerminated, err))
	status.StatusCode.StatusCode = &saml.StatusCode{Value: saml.StatusPartialLogout}
	return status
}

// errFrontChannelLogoutNotTerminated wraps the reason ServeSLO could not
// end, beyond the requesting browser's session, the sessions named by a
// LogoutRequest the IDP sent through the browser; it is passed to OnError.
var errFrontChannelLogoutNotTerminated = errors.New("saml: cannot end the other sessions named by a front-channel LogoutRequest")
