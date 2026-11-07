package samlsp

import (
	"context"
	"errors"
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
// The request is signed if Key can sign.
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
			return nil, errors.New("samlsp: the HTTP-POST-SimpleSign binding needs an RSA or ECDSA Key")
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

	// Raw is the request as package saml returned it.
	Raw *saml.LogoutRequest
}

// ParseLogoutRequest verifies a LogoutRequest that the identity provider
// sent to the SLO URL through the browser, with the HTTP-Redirect, HTTP-POST
// or HTTP-POST-SimpleSign binding.
//
// The caller then ends the sessions that the request names and answers
// with LogoutResponse. A request is for this handler if it carries a
// SAMLRequest parameter. A SAMLResponse parameter is for
// ParseLogoutResponse.
func (c *Config) ParseLogoutRequest(ctx context.Context, r *http.Request, opts ...ServiceProviderOption) (*LogoutRequest, error) {
	sp, err := c.serviceProvider(ctx, opts)
	if err != nil {
		return nil, err
	}
	// Parse the form here: r.WithContext makes a copy, and a body the copy
	// parsed could not be read again for RelayState.
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	req, err := sp.ValidateLogoutRequest(r.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	out := &LogoutRequest{
		ID:         req.ID,
		RelayState: r.FormValue("RelayState"),
		Raw:        req,
	}
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
			return nil, errors.New("samlsp: the HTTP-POST-SimpleSign binding needs an RSA or ECDSA Key")
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
