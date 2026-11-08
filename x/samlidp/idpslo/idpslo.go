// Package idpslo adds SAML single logout (saml-profiles §4.4) to an
// identity provider made with github.com/crewjam/saml/x/samlidp. It is the
// IdP's side of github.com/crewjam/saml/x/samlsp/slo.
//
// Configure the IdP's single logout service with Endpoint when making the
// Config, then use a Service:
//
//	config, err := samlidp.New(entityID, sps, samlidp.WithSigningKey(key, cert),
//		idpslo.Endpoint("https://idp.example.com/saml/slo"))
//	logout, err := idpslo.New(config)
//	http.HandleFunc(logout.Path(), sloHandler)
//
// The IdP is the session authority: a user who logs out of one service
// provider (SP) must be logged out of the IdP and of every other SP their
// IdP session was used for, its session participants. The application
// records them: each samlidp.Message that carries an assertion has a
// Participant, to keep with the user's IdP session.
//
// Logout started by an SP arrives at the SLO URL as a LogoutRequest, which
// ParseRequest verifies. The application ends the IdP session, logs the
// user out of the other participants, then answers the SP with Response.
// Logout started at the IdP, such as from its own "log out" button, logs
// the user out of each participant in turn.
//
// A participant is logged out through the browser with Request, which
// sends the browser to the SP with a LogoutRequest; the SP sends it back
// to the SLO URL with a LogoutResponse, which ParseResponse verifies.
// Participants are visited one at a time, and the application keeps where
// it is between them. With BackChannel, SendRequest logs a participant out
// directly, server to server, with the SOAP binding, for SPs whose metadata
// offers it.
//
// The SPs' requests and responses both arrive at the SLO URL; IsRequest and
// IsResponse tell them apart.
//
// Logout messages are signed with the key of samlidp.WithSigningKey, as
// the single logout profile requires (saml-profiles §4.4.3), and those of
// SPs must be signed too.
package idpslo

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/timelimit"
	"github.com/crewjam/saml/x/samlidp"
)

// ErrNoEndpoint is returned when the service provider's metadata lists no
// SingleLogoutService for the binding a message would be sent with.
var ErrNoEndpoint = errors.New("idpslo: the service provider has no single logout endpoint for the binding")

// ErrNoRequestID is returned by ParseResponse when it is given no request
// ID.
var ErrNoRequestID = errors.New("idpslo: no request ID to match InResponseTo against")

// ErrPartialLogout is matched by the error ParseResponse and SendRequest
// return, with the response, when the SP answers with the status
// saml.StatusSuccess and the second-level status saml.StatusPartialLogout:
// it ended the user's session, but not all of it (saml-core §3.7.3.2).
// The user is logged out of that participant, and the application may
// tell the SP that started the logout so (see PartialLogout, the
// ResponseOption).
var ErrPartialLogout = errors.New("idpslo: the service provider could not end every session of the user")

// logoutRequestReplayPrefix and logoutResponseReplayPrefix keep the replay
// keys of LogoutRequests and LogoutResponses apart from those of other
// messages.
const (
	logoutRequestReplayPrefix  = "LogoutRequest:"
	logoutResponseReplayPrefix = "LogoutResponse:"
)

// EndpointOption configures Endpoint.
type EndpointOption func(*endpointOptions)

type endpointOptions struct {
	backChannel    bool
	encryptNameID  bool
	acceptBaseID   bool
	decryptionKeys []*rsa.PrivateKey
	encryptionCert *x509.Certificate
	httpClient     *http.Client
}

// BackChannel enables single logout with the SAML SOAP binding, in which
// the IdP and the SPs exchange LogoutRequests and LogoutResponses
// directly, server to server, without the user's browser (saml-profiles
// §4.4). The IdP metadata then advertises a SOAP SingleLogoutService,
// ParseRequest accepts SOAP LogoutRequests, and SendRequest can be used.
//
// Enable it only if the application can end a user's IdP session on the
// server, by NameID and SessionIndex: a SOAP LogoutRequest comes without
// the browser, so deleting a session cookie does not end anything.
var BackChannel EndpointOption = func(o *endpointOptions) { o.backChannel = true }

// EncryptNameID makes Request and SendRequest identify the user with an
// EncryptedID, encrypted to the SP's encryption certificate, instead of a
// NameID, so that the browser carrying the request does not see it
// (saml-core §3.7.1). An SP whose metadata publishes no encryption
// certificate is sent the NameID in the clear.
var EncryptNameID EndpointOption = func(o *endpointOptions) { o.encryptNameID = true }

// AcceptBaseID makes ParseRequest accept a LogoutRequest that identifies
// the user with a saml:BaseID instead of a NameID (saml-core §2.2.3),
// given as Request.BaseID. Without it, such requests are refused.
var AcceptBaseID EndpointOption = func(o *endpointOptions) { o.acceptBaseID = true }

// WithDecryptionKey publishes cert in the IdP metadata as its encryption
// certificate, so that SPs can encrypt the NameID of their LogoutRequests
// to it (as x/samlsp/slo.EncryptNameID does), and decrypts with key. The
// previous keys, if any, also decrypt, for SPs that have not yet fetched
// the IdP metadata since the key was rotated. Without it, the IdP publishes
// no encryption certificate, and refuses encrypted NameIDs.
func WithDecryptionKey(key *rsa.PrivateKey, cert *x509.Certificate, previous ...*rsa.PrivateKey) EndpointOption {
	return func(o *endpointOptions) {
		o.encryptionCert = cert
		o.decryptionKeys = append([]*rsa.PrivateKey{key}, previous...)
	}
}

// WithHTTPClient sets the HTTP client SendRequest sends SOAP messages
// with. By default, a client gives up after 10 seconds, does not follow
// redirects, and connects only to public addresses: SendRequest sends to
// the SOAP SingleLogoutService in the SP's metadata, and an SP that
// registers its own metadata could otherwise point it at services on your
// own network (server-side request forgery). A client given here is used
// as it is: guard its dialer too, such as with code.dny.dev/ssrf, if SPs
// register their own metadata.
func WithHTTPClient(client *http.Client) EndpointOption {
	return func(o *endpointOptions) { o.httpClient = client }
}

// Endpoint configures the IdP's single logout service at location, an
// absolute URL, for samlidp.New: the IdP metadata advertises it with the
// HTTP-Redirect and HTTP-POST bindings (and SOAP with BackChannel). Serve
// the handler that calls ParseRequest and ParseResponse at Service.Path.
func Endpoint(location string, opts ...EndpointOption) samlidp.Option {
	var o endpointOptions
	for _, opt := range opts {
		opt(&o)
	}
	u, err := url.Parse(location)
	if err == nil && (!u.IsAbs() || u.Host == "") {
		err = fmt.Errorf("idpslo: the SLO URL must be an absolute URL, not %q", location)
	}
	if err == nil && o.encryptionCert != nil {
		pub, ok := o.encryptionCert.PublicKey.(*rsa.PublicKey)
		if !ok || o.decryptionKeys[0] == nil || !pub.Equal(&o.decryptionKeys[0].PublicKey) {
			err = errors.New("idpslo: the certificate of WithDecryptionKey is not for its key")
		}
	}
	if err != nil {
		return samlidp.WithCheck(func(*saml.IdentityProvider) error { return err })
	}
	return samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
		idp.LogoutURL = *u
		idp.LogoutBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}
		if o.backChannel {
			idp.LogoutBindings = append(idp.LogoutBindings, saml.SOAPBinding)
		}
		idp.EncryptLogoutNameID = o.encryptNameID
		idp.AcceptLogoutRequestBaseID = o.acceptBaseID
		if o.encryptionCert != nil {
			idp.EncryptionCertificate = o.encryptionCert
			idp.DecryptionKeys = o.decryptionKeys
		}
		if o.httpClient != nil {
			idp.HTTPClient = o.httpClient
		}
	})
}

// Service sends and receives single logout messages for a Config.
type Service struct {
	config *samlidp.Config
}

// New returns a Service for config, which must have been made with
// Endpoint.
func New(config *samlidp.Config) (*Service, error) {
	if config.IdentityProvider().LogoutURL.String() == "" {
		return nil, errors.New("idpslo: the Config has no single logout service; make it with idpslo.Endpoint")
	}
	return &Service{config: config}, nil
}

// URL returns the URL of the IdP's single logout service.
func (s *Service) URL() string { return s.config.IdentityProvider().LogoutURL.String() }

// Path returns the path of URL, to serve the SLO handler at, so that it
// cannot drift from the URL in the IdP metadata:
//
//	http.HandleFunc(logout.Path(), slo)
func (s *Service) Path() string {
	u := s.config.IdentityProvider().LogoutURL
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// IsRequest reports whether r, sent to the SLO URL, carries a
// LogoutRequest from an SP, for ParseRequest: one sent through the browser
// (a SAMLRequest parameter) or with the SOAP binding.
func IsRequest(r *http.Request) bool {
	return saml.IsSOAPRequest(r) || r.FormValue("SAMLRequest") != ""
}

// IsResponse reports whether r, sent to the SLO URL, carries a
// LogoutResponse from an SP (a SAMLResponse parameter), for
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

// Request is a verified logout request from a service provider, asking the
// IdP to end the user's session, and so to log them out of every other
// participant of it.
//
// It is plain data, so that the application can keep it, such as with
// encoding/json, while it logs the user out of the other participants
// through the browser, before it answers with Response. BaseID and Raw are
// not kept by encoding/json. Keep it where the user cannot change it.
type Request struct {
	// ID is the ID of the request. Response answers it.
	ID string

	// ServiceProvider is the entity ID of the SP that sent it.
	ServiceProvider string

	// NameID identifies the user whose sessions to end: the NameID the IdP
	// issued to the SP, decrypted if the SP sent an EncryptedID.
	NameID saml.NameID

	// BaseID identifies the user instead of NameID, with AcceptBaseID; its
	// meaning depends on its xsi:type. It is nil otherwise.
	BaseID *etree.Element `json:"-"`

	// SessionIndexes, if not empty, name the sessions to end: the
	// SessionIndexes the IdP issued. If it is empty, end all of the user's
	// sessions.
	SessionIndexes []string

	// Reason, if not empty, says why the user is logged out, such as
	// saml.LogoutReasonUser.
	Reason string

	// RelayState is the RelayState that came with the request. Response
	// sends it back unchanged, as the bindings require (saml-bindings
	// §3.4.3 and §3.5.3), even if the SP sent more than the 80 bytes they
	// allow, as samlidp.Response does with the RelayState of an
	// AuthnRequest.
	RelayState string

	// Binding is the binding the request came with: saml.HTTPRedirectBinding,
	// HTTPPostBinding, HTTPPostSimpleSignBinding or, with BackChannel,
	// SOAPBinding, which Response answers with SOAP too, in the same HTTP
	// exchange.
	Binding string

	// ResponseLocation and ResponseBinding are the SingleLogoutService of
	// the SP that Response sends the LogoutResponse to: the one with the
	// binding of the request if there is one (HTTP-POST for
	// HTTP-POST-SimpleSign), and otherwise its first HTTP-Redirect or
	// HTTP-POST one. They are empty for a SOAP request.
	ResponseLocation string
	ResponseBinding  string

	// Raw is the request as package saml returned it.
	Raw *saml.LogoutRequest `json:"-"`
}

// Matches reports whether p, a participant of an IdP session, is one of
// the sessions the request names: the request's NameID value must be that
// of p, and if the request names SessionIndexes, p's SessionIndex must be
// one of them. Only the SP that sent the request is matched: use it to
// find the IdP sessions to end, then log the user out of the other
// participants of those sessions.
func (req *Request) Matches(p saml.SessionParticipant) bool {
	if p.ServiceProviderID != req.ServiceProvider || req.NameID.Value == "" || p.NameID.Value != req.NameID.Value {
		return false
	}
	if len(req.SessionIndexes) == 0 {
		return true
	}
	for _, index := range req.SessionIndexes {
		if index == p.SessionIndex {
			return true
		}
	}
	return false
}

// ParseRequest verifies a LogoutRequest that a service provider sent to
// the SLO URL: through the browser, with the HTTP-Redirect, HTTP-POST or
// HTTP-POST-SimpleSign binding, or, with BackChannel, directly with the
// SOAP binding. It must be signed by an SP that the ServiceProviderFunc
// knows, be addressed to the SLO URL and be current, and is accepted only
// once (see samlidp.WithReplayState).
//
// The caller then ends the IdP sessions that the request names (see
// Request.Matches), logs the user out of their other participants, and
// answers with Response; or, if the request is refused, with
// WriteRequestError. A request that is valid, but whose sessions the IdP
// will not end, such as from an SP that is not a participant of them, is
// answered with Response and a status that says so (see WithStatus).
func (s *Service) ParseRequest(ctx context.Context, r *http.Request, opts ...samlidp.IdentityProviderOption) (*Request, error) {
	idp := s.config.IdentityProvider(opts...)
	if r.Method == http.MethodPost && !saml.IsSOAPRequest(r) {
		// Parse the form here: r.WithContext makes a copy, and a body the
		// copy parsed could not be read again.
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
	}
	ireq, err := saml.NewIdpLogoutRequest(idp, r.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	if err := ireq.Validate(); err != nil {
		return nil, err
	}
	q := &ireq.Request
	sp := ireq.ServiceProviderMetadata.EntityID
	if err := s.config.Consume(ctx, sp, logoutRequestReplayPrefix+q.ID, q.IssueInstant.Add(timelimit.IDPIssueDelay(idp))); err != nil {
		return nil, fmt.Errorf("idpslo: logout request %q from %s: %w", q.ID, sp, err)
	}

	out := &Request{
		ID:              q.ID,
		ServiceProvider: sp,
		BaseID:          q.BaseID,
		Reason:          q.Reason,
		RelayState:      ireq.RelayState,
		Binding:         ireq.Binding,
		Raw:             q,
	}
	if q.NameID != nil {
		out.NameID = *q.NameID
	}
	for _, si := range q.AllSessionIndexes() {
		out.SessionIndexes = append(out.SessionIndexes, si.Value)
	}
	if ep := ireq.SLOEndpoint; ep != nil && ep.Binding != saml.SOAPBinding {
		out.ResponseBinding = ep.Binding
		out.ResponseLocation = responseLocation(*ep)
	}
	return out, nil
}

// responseLocation returns where a LogoutResponse is sent at endpoint: its
// ResponseLocation if set, otherwise its Location (saml-metadata §2.2.2).
func responseLocation(ep saml.Endpoint) string {
	if ep.ResponseLocation != "" {
		return ep.ResponseLocation
	}
	return ep.Location
}

// ResponseOption customizes Response.
type ResponseOption func(*responseOptions)

type responseOptions struct {
	status *saml.Status
	nonce  string
}

// WithStatus sets the status of the LogoutResponse. The default is
// saml.StatusSuccess. Use PartialLogout when some participants could not
// be logged out, and saml.StatusRequester or saml.StatusResponder (with a
// second-level status such as saml.StatusRequestDenied) when the IdP did
// not end the sessions.
func WithStatus(status saml.Status) ResponseOption {
	return func(o *responseOptions) { s := status; o.status = &s }
}

// PartialLogout is WithStatus of saml.StatusSuccess with the second-level
// status saml.StatusPartialLogout: the IdP session ended, but some of its
// participants could not be logged out (saml-core §3.7.3.2), such as when
// ParseResponse or SendRequest returned an error matching saml.ErrBadStatus
// or ErrPartialLogout.
var PartialLogout = WithStatus(saml.Status{StatusCode: saml.StatusCode{
	Value:      saml.StatusSuccess,
	StatusCode: &saml.StatusCode{Value: saml.StatusPartialLogout},
}})

// WithResponseScriptNonce sets the nonce attribute of the script of the
// HTTP-POST form of the response (see samlidp.WithScriptNonce).
func WithResponseScriptNonce(nonce string) ResponseOption {
	return func(o *responseOptions) { o.nonce = nonce }
}

// Response returns the LogoutResponse to req, a request ParseRequest
// verified, signed, to send with Message.Write. Its status is success
// unless WithStatus says otherwise. It carries req.RelayState.
//
// A request that came through the browser is answered at
// req.ResponseLocation, which must still be a SingleLogoutService of the
// SP. One that came with the SOAP binding is answered with SOAP: the
// Message writes the LogoutResponse as the reply to the SP's HTTP request.
func (s *Service) Response(ctx context.Context, req *Request, opts ...ResponseOption) (*samlidp.Message, error) {
	if req == nil {
		return nil, errors.New("idpslo: nil Request")
	}
	var o responseOptions
	for _, opt := range opts {
		opt(&o)
	}
	md, err := s.config.ServiceProvider(ctx, req.ServiceProvider)
	if err != nil {
		return nil, err
	}
	resp := &saml.LogoutResponse{
		ID:           newID(),
		InResponseTo: req.ID,
		Version:      "2.0",
		IssueInstant: s.config.Now(),
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  s.config.EntityID(),
		},
		Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	if o.status != nil {
		resp.Status = *o.status
	}

	if req.Binding == saml.SOAPBinding {
		signed, err := s.config.SignElement(resp.Element())
		if err != nil {
			return nil, err
		}
		body, err := soapEnvelope(signed)
		if err != nil {
			return nil, err
		}
		msg := samlidp.NewMessage(resp.ID, saml.SOAPBinding, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache, no-store")
			_, _ = w.Write(body)
		})
		msg.InResponseTo = req.ID
		return msg, nil
	}

	if !hasEndpoint(md, req.ResponseBinding, req.ResponseLocation) {
		return nil, fmt.Errorf("%w %s at %s", ErrNoEndpoint, req.ResponseBinding, req.ResponseLocation)
	}
	resp.Destination = req.ResponseLocation
	return s.config.Send(samlidp.OutgoingMessage{
		Element:      resp.Element(),
		Destination:  req.ResponseLocation,
		Binding:      req.ResponseBinding,
		Param:        "SAMLResponse",
		RelayState:   req.RelayState,
		InResponseTo: req.ID,
		ScriptNonce:  o.nonce,
	})
}

// hasEndpoint reports whether md lists a SingleLogoutService with binding
// whose response location is location.
func hasEndpoint(md *saml.EntityDescriptor, binding, location string) bool {
	for _, d := range md.SPSSODescriptors {
		for _, ep := range d.SingleLogoutServices {
			if ep.Binding == binding && responseLocation(ep) == location {
				return true
			}
		}
	}
	return false
}

// RequestOption customizes Request and SendRequest.
type RequestOption func(*requestOptions)

type requestOptions struct {
	binding      string
	reason       string
	notOnOrAfter *time.Time
	nonce        string
	idp          []samlidp.IdentityProviderOption
}

// modify sets the Reason and NotOnOrAfter of the options on req.
func (o *requestOptions) modify(req *saml.LogoutRequest) {
	req.Reason = o.reason
	req.NotOnOrAfter = o.notOnOrAfter
}

// WithBinding sends the LogoutRequest with binding: saml.HTTPRedirectBinding
// or saml.HTTPPostBinding. By default HTTP-Redirect is used when the SP
// supports it, and HTTP-POST otherwise. SendRequest ignores it.
func WithBinding(binding string) RequestOption {
	return func(o *requestOptions) { o.binding = binding }
}

// WithReason says why the user is being logged out, in a LogoutRequest:
// saml.LogoutReasonUser when the user asked, saml.LogoutReasonAdmin when an
// administrator did, or a URI agreed with the SP.
func WithReason(reason string) RequestOption {
	return func(o *requestOptions) { o.reason = reason }
}

// WithNotOnOrAfter sets the time after which the SP must not act on a
// LogoutRequest (saml-core §3.7.1).
func WithNotOnOrAfter(t time.Time) RequestOption {
	return func(o *requestOptions) { t := t.UTC(); o.notOnOrAfter = &t }
}

// WithScriptNonce sets the nonce attribute of the script of the HTTP-POST
// form of the request (see samlidp.WithScriptNonce). SendRequest ignores
// it.
func WithScriptNonce(nonce string) RequestOption {
	return func(o *requestOptions) { o.nonce = nonce }
}

// WithIdentityProviderOptions applies opts to the saml.IdentityProvider
// that makes and sends the request, after those passed to samlidp.New.
func WithIdentityProviderOptions(opts ...samlidp.IdentityProviderOption) RequestOption {
	return func(o *requestOptions) { o.idp = append(o.idp, opts...) }
}

// Request returns a signed LogoutRequest that logs the user out of p, a
// participant of their IdP session (see samlidp.Message.Participant):
// send the browser to the SP with Message.Write, and keep Message.ID and
// p.ServiceProviderID to pass to ParseResponse when the SP sends the
// browser back to the SLO URL with its answer. relayState comes back with
// it, to find where the logout was: it must be at most 80 bytes
// (saml-bindings §3.4.3 and §3.5.3), or the error matches
// saml.ErrRelayStateTooLong.
//
// If the SP's metadata lists no HTTP-Redirect or HTTP-POST
// SingleLogoutService (or none for WithBinding), the error matches
// ErrNoEndpoint: the SP does not support single logout through the
// browser, and the logout is partial.
func (s *Service) Request(ctx context.Context, p saml.SessionParticipant, relayState string, opts ...RequestOption) (*samlidp.Message, error) {
	var o requestOptions
	for _, opt := range opts {
		opt(&o)
	}
	if len(relayState) > saml.MaxRelayStateLength {
		return nil, fmt.Errorf("idpslo: the RelayState is %d bytes, longer than the %d the SAML bindings allow: %w",
			len(relayState), saml.MaxRelayStateLength, saml.ErrRelayStateTooLong)
	}
	md, err := s.config.ServiceProvider(ctx, p.ServiceProviderID)
	if err != nil {
		return nil, err
	}
	ep, err := requestEndpoint(md, o.binding)
	if err != nil {
		return nil, err
	}
	idp := s.config.IdentityProvider(o.idp...)
	req, err := idp.MakeLogoutRequest(md, p, ep.Location)
	if err != nil {
		return nil, err
	}
	o.modify(req)
	return s.config.Send(samlidp.OutgoingMessage{
		Element:     req.Element(),
		Destination: ep.Location,
		Binding:     ep.Binding,
		Param:       "SAMLRequest",
		RelayState:  relayState,
		ScriptNonce: o.nonce,
	}, o.idp...)
}

// requestEndpoint returns the SingleLogoutService of md to send a
// LogoutRequest to: the first with binding, or by default the first
// HTTP-Redirect one, or else the first HTTP-POST one.
func requestEndpoint(md *saml.EntityDescriptor, binding string) (*saml.Endpoint, error) {
	bindings := []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}
	if binding != "" {
		if binding != saml.HTTPRedirectBinding && binding != saml.HTTPPostBinding {
			return nil, fmt.Errorf("idpslo: unsupported binding %q", binding)
		}
		bindings = []string{binding}
	}
	for _, b := range bindings {
		for _, d := range md.SPSSODescriptors {
			for _, ep := range d.SingleLogoutServices {
				if ep.Binding != b {
					continue
				}
				if u, err := url.Parse(ep.Location); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
					continue
				}
				return &ep, nil
			}
		}
	}
	if binding == "" {
		return nil, ErrNoEndpoint
	}
	return nil, fmt.Errorf("%w %s", ErrNoEndpoint, binding)
}

// ParseResponse verifies the LogoutResponse that the service provider
// serviceProvider sent to the SLO URL in answer to a LogoutRequest sent by
// Request. requestIDs are the Message.IDs of the logout requests to that
// SP that are still pending; the response must answer one of them. Each
// response is accepted only once (see samlidp.WithReplayState), but the
// application should still remove the request it answers, its
// InResponseTo, from those pending.
//
// It returns the response, and an error matching saml.ErrBadStatus if the
// SP could not log the user out, or one matching ErrPartialLogout if it
// logged the user out only in part.
func (s *Service) ParseResponse(ctx context.Context, r *http.Request, serviceProvider string, requestIDs ...string) (*saml.LogoutResponse, error) {
	if len(requestIDs) == 0 {
		return nil, ErrNoRequestID
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	idp := s.config.IdentityProvider()
	resp, err := idp.ValidateLogoutResponse(r.WithContext(ctx), serviceProvider, requestIDs)
	if err != nil {
		return nil, err
	}
	if resp.ID == "" {
		return nil, fmt.Errorf("idpslo: the logout response from %s has no ID", serviceProvider)
	}
	if err := s.config.Consume(ctx, serviceProvider, logoutResponseReplayPrefix+resp.ID, resp.IssueInstant.Add(timelimit.IDPIssueDelay(idp))); err != nil {
		return nil, fmt.Errorf("idpslo: logout response %q from %s: %w", resp.ID, serviceProvider, err)
	}
	if code := resp.Status.StatusCode.Value; code != saml.StatusSuccess {
		return resp, fmt.Errorf("idpslo: logout response from %s: %w", serviceProvider, saml.ErrBadStatus{Status: code})
	}
	return resp, partialLogout(resp, serviceProvider)
}

// partialLogout returns an error matching ErrPartialLogout if resp, a
// LogoutResponse from serviceProvider whose status is success, has the
// second-level status saml.StatusPartialLogout.
func partialLogout(resp *saml.LogoutResponse, serviceProvider string) error {
	if second := resp.Status.StatusCode.StatusCode; second != nil && second.Value == saml.StatusPartialLogout {
		return fmt.Errorf("idpslo: logout response %q from %s: %w", resp.ID, serviceProvider, ErrPartialLogout)
	}
	return nil
}

// SendRequest logs the user out of p, a participant of their IdP session,
// with a signed LogoutRequest sent directly to the SP with the SOAP
// binding, without the browser. It needs BackChannel, and returns the SP's
// verified LogoutResponse. opts are WithReason, WithNotOnOrAfter and
// WithIdentityProviderOptions.
//
// It returns an error matching ErrNoEndpoint if the SP's metadata lists no
// SOAP SingleLogoutService (or only ones that are not https), one
// matching saml.ErrBadStatus if the SP could not log the user out, and the
// response with one matching ErrPartialLogout if it logged the user out
// only in part. The request is sent with the HTTP client of WithHTTPClient.
func (s *Service) SendRequest(ctx context.Context, p saml.SessionParticipant, opts ...RequestOption) (*saml.LogoutResponse, error) {
	var o requestOptions
	for _, opt := range opts {
		opt(&o)
	}
	idp := s.config.IdentityProvider(o.idp...)
	if !hasSOAP(idp.LogoutBindings) {
		return nil, errors.New("idpslo: SendRequest needs BackChannel")
	}
	md, err := s.config.ServiceProvider(ctx, p.ServiceProviderID)
	if err != nil {
		return nil, err
	}
	resp, err := idp.SendSOAPLogoutRequest(ctx, md, p, o.modify)
	if errors.Is(err, saml.ErrNoSOAPLogoutEndpoint) {
		return nil, fmt.Errorf("%w %s", ErrNoEndpoint, saml.SOAPBinding)
	}
	if err != nil {
		return resp, err
	}
	return resp, partialLogout(resp, p.ServiceProviderID)
}

func hasSOAP(bindings []string) bool {
	for _, b := range bindings {
		if b == saml.SOAPBinding {
			return true
		}
	}
	return false
}

// soapEnvelope returns el in a SOAP 1.1 envelope, as bytes.
func soapEnvelope(el *etree.Element) ([]byte, error) {
	env := etree.NewElement("soapenv:Envelope")
	env.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	env.CreateElement("soapenv:Body").AddChild(el)
	doc := etree.NewDocument()
	doc.SetRoot(env)
	return doc.WriteToBytes()
}

// newID returns a new random XML ID.
func newID() string {
	b := make([]byte, 20)
	if _, err := io.ReadFull(saml.RandReader, b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("id-%x", b)
}
