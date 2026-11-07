package samlsp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/crewjam/saml"
)

// LogoutOption customizes LogoutRequest and LogoutResponse.
type LogoutOption interface {
	applyLogout(*logoutOptions)
}

type logoutOptions struct {
	messageOptions
	sessionIndexes []string
	status         *saml.Status
}

type logoutOptionFunc func(*logoutOptions)

func (f logoutOptionFunc) applyLogout(o *logoutOptions) { f(o) }

// WithSessionIndex names the user's sessions at the IdP that a
// LogoutRequest ends. Pass Assertion.SessionIndexes. Without it, the
// request asks the IdP to end all of the user's sessions. Some IdPs require
// it.
func WithSessionIndex(indexes ...string) LogoutOption {
	return logoutOptionFunc(func(o *logoutOptions) {
		o.sessionIndexes = append(o.sessionIndexes, indexes...)
	})
}

// WithStatus sets the status of a LogoutResponse. The default is
// saml.StatusSuccess. For example, answer with saml.StatusSuccess and the
// second-level status saml.StatusPartialLogout if the SP could not end
// every session that the request names.
func WithStatus(status saml.Status) LogoutOption {
	return logoutOptionFunc(func(o *logoutOptions) { o.status = &status })
}

// LogoutRequest returns a request that starts single logout at the identity
// provider for the user identified by nameID. nameID is the
// Assertion.NameID of the user's login. Send the request with Message.Write,
// and keep Message.ID to pass to ParseLogoutResponse when the IdP replies.
//
// Ending the local session is up to the caller. Do that first, so that the
// user is logged out of this SP even if the IdP never replies. If the IdP
// does not support single logout, LogoutRequest returns an error matching
// ErrNoEndpoint.
//
// The request is signed if the key of WithKey can sign.
func (c *Config) LogoutRequest(ctx context.Context, nameID saml.NameID, relayState string, opts ...LogoutOption) (*Message, error) {
	var o logoutOptions
	for _, opt := range opts {
		opt.applyLogout(&o)
	}
	sp, err := c.serviceProvider(ctx, o.sp)
	if err != nil {
		return nil, err
	}
	binding, location, err := chooseBinding(o.binding, sp.GetSLOBindingLocation)
	if err != nil {
		return nil, err
	}

	samlOpts := []saml.LogoutRequestOption{
		// Name the user exactly as the IdP did (saml-core §3.7.1). The
		// default from package saml only copies the value.
		func(req *saml.LogoutRequest) {
			id := nameID
			req.NameID = &id
		},
	}
	if len(o.sessionIndexes) > 0 {
		samlOpts = append(samlOpts, saml.WithSessionIndexes(o.sessionIndexes...))
	}
	req, err := sp.MakeLogoutRequest(location, nameID.Value, samlOpts...)
	if err != nil {
		return nil, err
	}

	m := &Message{ID: req.ID, Binding: binding, Destination: location, RelayState: relayState, scriptHash: requestScriptHash}
	switch binding {
	case saml.HTTPRedirectBinding:
		if m.redirectURL, err = sp.RedirectLogoutRequestURL(req, relayState); err != nil {
			return nil, err
		}
	case saml.HTTPPostBinding:
		m.form = req.PostWithNonce(relayState, o.scriptNonce)
	case saml.HTTPPostSimpleSignBinding:
		if sp.LogoutSignatureMethod == "" {
			return nil, errors.New("samlsp: the HTTP-POST-SimpleSign binding needs an RSA or ECDSA key (see WithKey)")
		}
		// The SimpleSign signature replaces the enveloped one.
		req.Signature = nil
		if m.form, err = req.SimpleSignWithNonce(relayState, o.scriptNonce, sp); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// LogoutRequest is a verified logout request from the identity provider,
// which ends the user's session at this SP.
type LogoutRequest struct {
	// ID is the ID of the request. LogoutResponse answers it.
	ID string

	// NameID identifies the user whose sessions to end.
	NameID saml.NameID

	// SessionIndexes, if not empty, name the sessions to end. If it is
	// empty, end all of the user's sessions.
	SessionIndexes []string

	// RelayState is the RelayState that came with the request.
	// LogoutResponse sends it back.
	RelayState string

	// Binding is the binding the request came with. For saml.SOAPBinding
	// (see BackChannelLogout), LogoutResponse answers with SOAP too.
	Binding string

	// Raw is the request as package saml returned it.
	Raw *saml.LogoutRequest
}

// IsLogoutRequest reports whether r, sent to the SLO URL, carries a
// LogoutRequest from the IdP, for ParseLogoutRequest: one sent through the
// browser (a SAMLRequest parameter) or with the SOAP binding.
func IsLogoutRequest(r *http.Request) bool {
	return saml.IsSOAPRequest(r) || r.FormValue("SAMLRequest") != ""
}

// IsLogoutResponse reports whether r, sent to the SLO URL, carries a
// LogoutResponse from the IdP (a SAMLResponse parameter), for
// ParseLogoutResponse.
func IsLogoutResponse(r *http.Request) bool {
	return !saml.IsSOAPRequest(r) && r.FormValue("SAMLResponse") != ""
}

// WriteLogoutRequestError answers a LogoutRequest that ParseLogoutRequest
// refused: with a SOAP fault for one sent with the SOAP binding, as the
// binding requires, and with 400 Bad Request otherwise. The answer does
// not say what was wrong.
func WriteLogoutRequestError(w http.ResponseWriter, r *http.Request) {
	if saml.IsSOAPRequest(r) {
		_ = saml.WriteSOAPFault(w, "invalid logout request")
		return
	}
	http.Error(w, "invalid logout request", http.StatusBadRequest)
}

// ParseLogoutRequest verifies a LogoutRequest that the identity provider
// sent to the SLO URL: through the browser, with the HTTP-Redirect,
// HTTP-POST or HTTP-POST-SimpleSign binding, or, with BackChannelLogout,
// directly with the SOAP binding. A SOAP LogoutRequest must be signed by
// the IdP.
//
// The caller then ends the sessions that the request names and answers
// with LogoutResponse, or, if the request is refused, with
// WriteLogoutRequestError. IsLogoutRequest tells such a request from a
// LogoutResponse, which is for ParseLogoutResponse.
func (c *Config) ParseLogoutRequest(ctx context.Context, r *http.Request, opts ...ServiceProviderOption) (*LogoutRequest, error) {
	sp, err := c.serviceProvider(ctx, opts)
	if err != nil {
		return nil, err
	}

	var req *saml.LogoutRequest
	out := &LogoutRequest{}
	if saml.IsSOAPRequest(r) {
		if !c.backChannel {
			return nil, errors.New("samlsp: a SOAP LogoutRequest was received, but BackChannelLogout is not enabled")
		}
		if req, err = sp.ValidateSOAPLogoutRequest(r.WithContext(ctx)); err != nil {
			return nil, err
		}
		out.Binding = saml.SOAPBinding
	} else {
		// Parse the form here: r.WithContext makes a copy, and a body the
		// copy parsed could not be read again for RelayState.
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		if req, err = sp.ValidateLogoutRequest(r.WithContext(ctx)); err != nil {
			return nil, err
		}
		out.RelayState = r.FormValue("RelayState")
		out.Binding = saml.HTTPPostBinding
		if r.URL.Query().Get("SAMLRequest") != "" {
			out.Binding = saml.HTTPRedirectBinding
		}
	}
	out.ID = req.ID
	out.Raw = req
	if req.NameID != nil {
		out.NameID = *req.NameID
	}
	for _, si := range req.AllSessionIndexes() {
		out.SessionIndexes = append(out.SessionIndexes, si.Value)
	}
	return out, nil
}

// LogoutResponse returns the response to req, to send the browser back to
// the identity provider with by calling Message.Write. Its status is
// success unless WithStatus says otherwise. It carries req.RelayState.
//
// A request that came with the SOAP binding is answered with SOAP: the
// Message writes a signed LogoutResponse as the reply to the IdP's HTTP
// request, and WithBinding is ignored.
//
// If the IdP lists no endpoint for the response, LogoutResponse returns an
// error matching ErrNoEndpoint.
func (c *Config) LogoutResponse(ctx context.Context, req *LogoutRequest, opts ...LogoutOption) (*Message, error) {
	var o logoutOptions
	for _, opt := range opts {
		opt.applyLogout(&o)
	}
	sp, err := c.serviceProvider(ctx, o.sp)
	if err != nil {
		return nil, err
	}
	status := saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}
	if o.status != nil {
		status = *o.status
	}
	if req.Binding == saml.SOAPBinding {
		resp, err := sp.MakeSOAPLogoutResponse(req.ID, status)
		if err != nil {
			return nil, err
		}
		return &Message{Binding: saml.SOAPBinding, soapResponse: resp}, nil
	}
	binding, location, err := chooseBinding(o.binding, sp.GetSLOBindingLocation)
	if err != nil {
		return nil, err
	}

	// Message.ID is left empty: the response's own ID is of no use to
	// the caller.
	m := &Message{Binding: binding, Destination: location, RelayState: req.RelayState, scriptHash: responseScriptHash}
	if binding == saml.HTTPRedirectBinding {
		if m.redirectURL, err = sp.MakeRedirectLogoutResponseWithStatus(req.ID, req.RelayState, status); err != nil {
			return nil, err
		}
		return m, nil
	}

	resp, err := sp.MakeLogoutResponseWithStatus(location, req.ID, status)
	if err != nil {
		return nil, err
	}
	switch binding {
	case saml.HTTPPostBinding:
		m.form = resp.PostWithNonce(req.RelayState, o.scriptNonce)
	case saml.HTTPPostSimpleSignBinding:
		if sp.LogoutSignatureMethod == "" {
			return nil, errors.New("samlsp: the HTTP-POST-SimpleSign binding needs an RSA or ECDSA key (see WithKey)")
		}
		resp.Signature = nil
		if m.form, err = resp.SimpleSignWithNonce(req.RelayState, o.scriptNonce, sp); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ParseLogoutResponse verifies the identity provider's response to a
// LogoutRequest sent by LogoutRequest. Pass WithRequestID with the
// Message.ID of each logout request that is still pending. The response
// must answer one of them. AllowUnsolicited is refused: a LogoutResponse
// always answers a request.
//
// It returns an error matching saml.ErrBadStatus if the IdP could not log
// the user out.
func (c *Config) ParseLogoutResponse(ctx context.Context, r *http.Request, opts ...ResponseOption) (*saml.LogoutResponse, error) {
	var o responseOptions
	for _, opt := range opts {
		opt.applyResponse(&o)
	}
	if o.unsolicited {
		return nil, errors.New("samlsp: a LogoutResponse cannot be unsolicited")
	}
	if len(o.requestIDs) == 0 {
		return nil, ErrNoRequestID
	}
	sp, err := c.serviceProvider(ctx, o.sp)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return sp.ParseLogoutResponse(r.WithContext(ctx), o.requestIDs)
}

// SendLogoutRequest asks the identity provider to end the sessions of the
// user identified by nameID, with a signed LogoutRequest sent directly to
// it with the SOAP binding, without the browser: for example, when an
// administrator logs a user out, or when the user's account is disabled.
// It needs BackChannelLogout, and returns the IdP's verified
// LogoutResponse.
//
// It returns an error matching ErrNoEndpoint if the IdP has no SOAP
// SingleLogoutService, and one matching saml.ErrBadStatus if the IdP could
// not end the sessions. The request is sent with the HTTP client from
// ClientContext, to an https endpoint only.
func (c *Config) SendLogoutRequest(ctx context.Context, nameID saml.NameID, opts ...LogoutOption) (*saml.LogoutResponse, error) {
	if !c.backChannel {
		return nil, errors.New("samlsp: SendLogoutRequest needs BackChannelLogout")
	}
	var o logoutOptions
	for _, opt := range opts {
		opt.applyLogout(&o)
	}
	sp, err := c.serviceProvider(ctx, o.sp)
	if err != nil {
		return nil, err
	}
	var samlOpts []saml.LogoutRequestOption
	if len(o.sessionIndexes) > 0 {
		samlOpts = append(samlOpts, saml.WithSessionIndexes(o.sessionIndexes...))
	}
	req, err := sp.MakeSOAPLogoutRequest(nameID, samlOpts...)
	if errors.Is(err, saml.ErrNoSOAPSingleLogoutService) {
		return nil, fmt.Errorf("%w %s", ErrNoEndpoint, saml.SOAPBinding)
	}
	if err != nil {
		return nil, err
	}
	return sp.SendSOAPLogoutRequest(ctx, req)
}
