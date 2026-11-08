// Package slo adds SAML single logout (saml-profiles §4.4) to a service
// provider made with github.com/crewjam/saml/x/samlsp.
//
// Configure the SP's single logout service with Endpoint when making the
// Config, then use a Service:
//
//	config, err := samlsp.New(entityID, idp, samlsp.WithSigningKey(key, cert),
//		slo.Endpoint("https://sp.example.com/saml/slo"))
//	logout, err := slo.New(config)
//	http.HandleFunc(logout.Path(), sloHandler)
//
// Logout started by the SP sends the browser to the IdP with Request, and
// verifies the IdP's answer with ParseResponse. Logout started by the IdP
// arrives as a request that ParseRequest verifies and Response answers.
// The IdP's requests and responses both arrive at the SLO URL; IsRequest
// and IsResponse tell them apart.
// With BackChannel, the IdP and the SP can also exchange logout messages
// directly, server to server (SendRequest, and SOAP requests to
// ParseRequest).
//
// Logout messages are signed with the key of samlsp.WithSigningKey. The
// single logout profile requires signatures with the browser bindings
// (saml-profiles §4.4.3), and many IdPs enforce it.
package slo

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// ErrNoRequestID is returned by ParseResponse when it is given no request
// ID.
var ErrNoRequestID = errors.New("slo: no request ID to match InResponseTo against")

// EndpointOption configures Endpoint.
type EndpointOption func(*endpointOptions)

type endpointOptions struct {
	backChannel   bool
	encryptNameID bool
	acceptBaseID  bool
}

// BackChannel enables single logout with the SAML SOAP binding, in which
// the IdP and the SP exchange LogoutRequests and LogoutResponses directly,
// server to server, without the user's browser (saml-profiles §4.4). The SP
// metadata then advertises a SOAP SingleLogoutService, ParseRequest
// accepts SOAP LogoutRequests, and SendRequest can be used.
//
// Enable it only if the application can end a user's sessions on the
// server, by NameID and SessionIndex: a SOAP LogoutRequest comes without
// the browser, so deleting a session cookie does not end anything. It
// needs samlsp.WithSigningKey, which signs the SOAP messages.
var BackChannel EndpointOption = func(o *endpointOptions) { o.backChannel = true }

// EncryptNameID makes Request and SendRequest identify the user with an
// EncryptedID, encrypted to the IdP's encryption certificate, instead of a
// NameID, so that the browser carrying the request does not see it
// (saml-core §3.7.1). Some IdPs require it. Sending a request fails if the
// IdP metadata has no encryption certificate.
var EncryptNameID EndpointOption = func(o *endpointOptions) { o.encryptNameID = true }

// AcceptBaseID makes ParseRequest accept a LogoutRequest that identifies
// the user with a saml:BaseID instead of a NameID (saml-core §2.2.3),
// given as Request.BaseID. Without it, such requests are refused.
var AcceptBaseID EndpointOption = func(o *endpointOptions) { o.acceptBaseID = true }

// Endpoint configures the SP's single logout service at location, an
// absolute URL, for samlsp.New: the SP metadata advertises it with the
// HTTP-Redirect and HTTP-POST bindings (and SOAP with BackChannel). Serve
// the handler that calls ParseRequest and ParseResponse at Service.Path.
func Endpoint(location string, opts ...EndpointOption) samlsp.Option {
	var o endpointOptions
	for _, opt := range opts {
		opt(&o)
	}
	u, err := url.Parse(location)
	if err == nil && (!u.IsAbs() || u.Host == "") {
		err = fmt.Errorf("slo: the SLO URL must be an absolute URL, not %q", location)
	}
	if err != nil {
		return samlsp.WithCheck(func(*saml.ServiceProvider) error { return err })
	}
	return samlsp.Options(
		samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
			sp.SloURL = *u
			sp.LogoutBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}
			if o.backChannel {
				sp.LogoutBindings = append(sp.LogoutBindings, saml.SOAPBinding)
			}
			sp.EncryptLogoutNameID = o.encryptNameID
			sp.AcceptLogoutRequestBaseID = o.acceptBaseID
		}),
		samlsp.WithCheck(func(sp *saml.ServiceProvider) error {
			if o.backChannel && sp.LogoutSignatureMethod == "" {
				return errors.New("slo: BackChannel needs an RSA or ECDSA key (see samlsp.WithSigningKey) to sign SOAP messages")
			}
			return nil
		}),
	)
}

// Service sends and receives single logout messages for a Config.
type Service struct {
	config *samlsp.Config
}

// New returns a Service for config, which must have been made with
// Endpoint.
func New(config *samlsp.Config) (*Service, error) {
	if md := config.Metadata(context.Background()); len(md.SPSSODescriptors) == 0 ||
		len(md.SPSSODescriptors[0].SingleLogoutServices) == 0 {
		return nil, errors.New("slo: the Config has no single logout service; make it with slo.Endpoint")
	}
	return &Service{config: config}, nil
}

// URL returns the URL of the SP's single logout service.
func (s *Service) URL() string {
	return s.config.Metadata(context.Background()).SPSSODescriptors[0].SingleLogoutServices[0].Location
}

// Path returns the path of URL, to serve the SLO handler at, so that it
// cannot drift from the URL in the SP metadata:
//
//	http.HandleFunc(logout.Path(), slo)
func (s *Service) Path() string {
	u, err := url.Parse(s.URL())
	if err != nil {
		return "" // Endpoint has checked the URL
	}
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// backChannel reports whether sp offers the SOAP binding.
func backChannel(sp *saml.ServiceProvider) bool {
	return slices.Contains(sp.LogoutBindings, saml.SOAPBinding)
}

// WithSessionIndex names the user's sessions at the IdP that a
// LogoutRequest ends. Pass samlsp.Assertion.SessionIndexes. Without it, the
// request asks the IdP to end all of the user's sessions. Some IdPs require
// it.
func WithSessionIndex(indexes ...string) samlsp.MessageOption {
	return samlsp.WithModify(func(req *saml.LogoutRequest) error {
		saml.WithSessionIndexes(indexes...)(req)
		return nil
	})
}

// WithReason says why the user is being logged out, in a LogoutRequest:
// saml.LogoutReasonUser when the user asked, saml.LogoutReasonAdmin when an
// administrator did, or a URI agreed with the IdP.
func WithReason(reason string) samlsp.MessageOption {
	return samlsp.WithModify(func(req *saml.LogoutRequest) error {
		req.Reason = reason
		return nil
	})
}

// WithNotOnOrAfter sets the time after which the IdP must not act on a
// LogoutRequest (saml-core §3.7.1).
func WithNotOnOrAfter(t time.Time) samlsp.MessageOption {
	return samlsp.WithModify(func(req *saml.LogoutRequest) error {
		t := t.UTC()
		req.NotOnOrAfter = &t
		return nil
	})
}

// WithStatus sets the status of a LogoutResponse. The default is
// saml.StatusSuccess. For example, answer with saml.StatusSuccess and the
// second-level status saml.StatusPartialLogout if the SP could not end
// every session that the request names.
func WithStatus(status saml.Status) samlsp.MessageOption {
	return samlsp.WithModify(func(resp *saml.LogoutResponse) error {
		resp.Status = status
		return nil
	})
}

// unsigned clears the signature methods of sp, a ServiceProvider of a
// single call, so that package saml makes messages unsigned: Send signs
// them as their binding requires.
func unsigned(sp *saml.ServiceProvider) {
	sp.SignatureMethod = ""
	sp.LogoutSignatureMethod = ""
}

// Request returns a LogoutRequest that starts single logout at the IdP for
// the user identified by nameID, the samlsp.Assertion.NameID of the user's
// login. Send it with Message.Write, and keep Message.ID to pass to
// ParseResponse when the IdP replies. opts are WithSessionIndex, WithReason,
// WithNotOnOrAfter and the samlsp.MessageOptions, such as
// samlsp.WithBinding.
//
// End the local session first, so that the user is logged out of this SP
// even if the IdP never replies. If the IdP does not support single
// logout, Request returns an error matching samlsp.ErrNoEndpoint.
//
// The request is signed with the key of samlsp.WithSigningKey, if there is
// one.
func (s *Service) Request(ctx context.Context, nameID saml.NameID, relayState string, opts ...samlsp.MessageOption) (*samlsp.Message, error) {
	return s.config.Send(ctx, samlsp.OutgoingMessage{
		Service:    samlsp.SingleLogoutService,
		Param:      "SAMLRequest",
		RelayState: relayState,
		Sign:       true,
		Build: func(sp *saml.ServiceProvider, destination string, modify func(any) error) (*etree.Element, error) {
			unsigned(sp)
			var modifyErr error
			req, err := sp.MakeLogoutRequest(destination, nameID.Value,
				// Name the user exactly as the IdP did (saml-core §3.7.1).
				func(req *saml.LogoutRequest) {
					id := nameID
					req.NameID = &id
				},
				func(req *saml.LogoutRequest) { modifyErr = modify(req) })
			if err != nil {
				return nil, err
			}
			if modifyErr != nil {
				return nil, modifyErr
			}
			return req.Element(), nil
		},
	}, opts...)
}

// Request is a verified logout request from the identity provider, asking
// this SP to end the user's sessions.
type Request struct {
	// ID is the ID of the request. Response answers it.
	ID string

	// NameID identifies the user whose sessions to end.
	NameID saml.NameID

	// BaseID identifies the user instead of NameID, with AcceptBaseID; its
	// meaning depends on its xsi:type. It is nil otherwise.
	BaseID *etree.Element

	// SessionIndexes, if not empty, name the sessions to end. If it is
	// empty, end all of the user's sessions.
	SessionIndexes []string

	// RelayState is the RelayState that came with the request. Response
	// sends it back.
	RelayState string

	// Binding is the binding the request came with: saml.HTTPRedirectBinding,
	// HTTPPostBinding, HTTPPostSimpleSignBinding or, with BackChannel,
	// SOAPBinding, which Response answers with SOAP too.
	Binding string

	// Raw is the request as package saml returned it.
	Raw *saml.LogoutRequest
}

// IsRequest reports whether r, sent to the SLO URL, carries a
// LogoutRequest from the IdP, for ParseRequest: one sent through the
// browser (a SAMLRequest parameter) or with the SOAP binding.
func IsRequest(r *http.Request) bool {
	return saml.IsSOAPRequest(r) || r.FormValue("SAMLRequest") != ""
}

// IsResponse reports whether r, sent to the SLO URL, carries a
// LogoutResponse from the IdP (a SAMLResponse parameter), for
// ParseResponse.
func IsResponse(r *http.Request) bool {
	return !saml.IsSOAPRequest(r) && r.FormValue("SAMLResponse") != ""
}

// WriteRequestError answers a LogoutRequest that ParseRequest refused: with
// a SOAP fault for one sent with the SOAP binding, as the binding
// requires, and with 400 Bad Request otherwise. The answer does not say
// what was wrong.
func WriteRequestError(w http.ResponseWriter, r *http.Request) {
	if saml.IsSOAPRequest(r) {
		_ = saml.WriteSOAPFault(w, "invalid logout request")
		return
	}
	http.Error(w, "invalid logout request", http.StatusBadRequest)
}

// ParseRequest verifies a LogoutRequest that the identity provider sent to
// the SLO URL: through the browser, with the HTTP-Redirect, HTTP-POST or
// HTTP-POST-SimpleSign binding, or, with BackChannel, directly with the
// SOAP binding. A SOAP LogoutRequest must be signed by the IdP.
//
// The caller then ends the sessions that the request names and answers
// with Response, or, if the request is refused, with WriteRequestError.
func (s *Service) ParseRequest(ctx context.Context, r *http.Request, opts ...samlsp.ServiceProviderOption) (*Request, error) {
	sp, err := s.config.ServiceProvider(ctx, opts...)
	if err != nil {
		return nil, err
	}
	var req *saml.LogoutRequest
	out := &Request{}
	if saml.IsSOAPRequest(r) {
		if !backChannel(sp) {
			return nil, errors.New("slo: a SOAP LogoutRequest was received, but BackChannel is not enabled")
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
		switch {
		case r.URL.Query().Get("SAMLRequest") != "":
			out.Binding = saml.HTTPRedirectBinding
		case r.PostForm.Has("SigAlg") || r.PostForm.Has("Signature"):
			out.Binding = saml.HTTPPostSimpleSignBinding
		default:
			out.Binding = saml.HTTPPostBinding
		}
	}
	out.ID = req.ID
	out.Raw = req
	if req.NameID != nil {
		out.NameID = *req.NameID
	}
	out.BaseID = req.BaseID
	for _, si := range req.AllSessionIndexes() {
		out.SessionIndexes = append(out.SessionIndexes, si.Value)
	}
	return out, nil
}

// successStatus is the status of a LogoutResponse by default.
func successStatus() saml.Status {
	return saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}}
}

// Response returns the response to req, to send the browser back to the
// identity provider with by calling Message.Write. Its status is success
// unless WithStatus says otherwise. It carries req.RelayState.
//
// A request that came with the SOAP binding is answered with SOAP: the
// Message writes a signed LogoutResponse as the reply to the IdP's HTTP
// request, and the binding options are ignored.
//
// If the IdP lists no endpoint for the response, Response returns an error
// matching samlsp.ErrNoEndpoint.
func (s *Service) Response(ctx context.Context, req *Request, opts ...samlsp.MessageOption) (*samlsp.Message, error) {
	if req.Binding == saml.SOAPBinding {
		sp, modify, err := s.config.Prepare(ctx, opts...)
		if err != nil {
			return nil, err
		}
		// Sign SOAP with the configured method, which package saml takes
		// from SignatureMethod.
		sp.SignatureMethod = sp.LogoutSignatureMethod
		resp, err := sp.MakeSOAPLogoutResponse(req.ID, successStatus())
		if err != nil {
			return nil, err
		}
		// Sign after the options have changed it.
		resp.Signature = nil
		if err := modify(resp); err != nil {
			return nil, err
		}
		if err := sp.SignLogoutResponse(resp); err != nil {
			return nil, err
		}
		return samlsp.NewMessage(resp.ID, saml.SOAPBinding, func(w http.ResponseWriter) {
			_ = saml.WriteSOAPLogoutResponse(w, resp)
		}), nil
	}
	return s.config.Send(ctx, samlsp.OutgoingMessage{
		Service:    samlsp.SingleLogoutService,
		Param:      "SAMLResponse",
		RelayState: req.RelayState,
		Sign:       true,
		Build: func(sp *saml.ServiceProvider, destination string, modify func(any) error) (*etree.Element, error) {
			unsigned(sp)
			resp, err := sp.MakeLogoutResponseWithStatus(destination, req.ID, successStatus())
			if err != nil {
				return nil, err
			}
			if err := modify(resp); err != nil {
				return nil, err
			}
			return resp.Element(), nil
		},
	}, opts...)
}

// ParseResponse verifies the identity provider's response to a
// LogoutRequest sent by Request. requestIDs are the Message.IDs of the
// logout requests that are still pending; the response must answer one of
// them.
//
// It returns an error matching saml.ErrBadStatus if the IdP could not log
// the user out.
func (s *Service) ParseResponse(ctx context.Context, r *http.Request, requestIDs ...string) (*saml.LogoutResponse, error) {
	if len(requestIDs) == 0 {
		return nil, ErrNoRequestID
	}
	sp, err := s.config.ServiceProvider(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	return sp.ParseLogoutResponse(r.WithContext(ctx), requestIDs)
}

// SendRequest asks the identity provider to end the sessions of the user
// identified by nameID, with a signed LogoutRequest sent directly to it
// with the SOAP binding, without the browser: for example, when an
// administrator logs a user out. It needs BackChannel, and returns the
// IdP's verified LogoutResponse. opts are WithSessionIndex, WithReason,
// WithNotOnOrAfter and samlsp.ServiceProviderOptions.
//
// It returns an error matching samlsp.ErrNoEndpoint if the IdP has no SOAP
// SingleLogoutService, and one matching saml.ErrBadStatus if the IdP could
// not end the sessions. The request is sent with the HTTP client of
// samlsp.WithHTTPClient, to an https endpoint only.
func (s *Service) SendRequest(ctx context.Context, nameID saml.NameID, opts ...samlsp.MessageOption) (*saml.LogoutResponse, error) {
	sp, modify, err := s.config.Prepare(ctx, opts...)
	if err != nil {
		return nil, err
	}
	if !backChannel(sp) {
		return nil, errors.New("slo: SendRequest needs BackChannel")
	}
	sp.SignatureMethod = sp.LogoutSignatureMethod
	var modifyErr error
	req, err := sp.MakeSOAPLogoutRequest(nameID, func(req *saml.LogoutRequest) { modifyErr = modify(req) })
	if errors.Is(err, saml.ErrNoSOAPSingleLogoutService) {
		return nil, fmt.Errorf("%w %s", samlsp.ErrNoEndpoint, saml.SOAPBinding)
	}
	if err != nil {
		return nil, err
	}
	if modifyErr != nil {
		return nil, modifyErr
	}
	return sp.SendSOAPLogoutRequest(ctx, req)
}
