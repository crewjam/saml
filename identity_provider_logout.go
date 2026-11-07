package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// SessionInvalidator is an optional interface that a SessionProvider may
// implement to support single logout. When IdentityProvider.ServeSLO has
// validated a LogoutRequest from a service provider, it calls
// InvalidateSession if the SessionProvider implements this interface.
//
// InvalidateSession must terminate the IdP session (or sessions) that req
// refers to. Use req.MatchesSession to decide whether a Session is one of
// them: its NameID must be the request's NameID and, if the request carries
// SessionIndexes, its Index must be one of them. If the IdP's
// AcceptLogoutRequestBaseID is set, the request may instead identify the
// principal with req.Request.BaseID, leaving req.Request.NameID nil; then
// MatchesSession matches no session. Ending no session, for
// example because the user is already logged out, is not an error.
//
// A LogoutRequest received with the SOAP binding (req.Binding is
// SOAPBinding) comes from the service provider's server, so r carries no
// cookie of the user: InvalidateSession must then find the sessions to end
// among those it stores, with req.MatchesSession. Only accept that binding
// (by adding SOAPBinding to IdentityProvider.LogoutBindings) if it can.
//
// InvalidateSession may set headers on w, for example to expire a session
// cookie, but must not write the status line or a body: ServeSLO writes the
// LogoutResponse afterwards. If it returns an error, ServeSLO logs it and
// answers the service provider with a LogoutResponse whose status is
// StatusResponder.
type SessionInvalidator interface {
	InvalidateSession(w http.ResponseWriter, r *http.Request, req *IdpLogoutRequest) error
}

// IdpLogoutRequest is used by IdentityProvider to handle a single logout
// request (saml-core-2.0-os §3.7) sent by a service provider.
type IdpLogoutRequest struct {
	IDP         *IdentityProvider
	HTTPRequest *http.Request

	// Binding is the binding the request was received with,
	// HTTPRedirectBinding, HTTPPostBinding, HTTPPostSimpleSignBinding or
	// SOAPBinding. A request
	// received with SOAPBinding comes from the service provider's server,
	// not through the browser: HTTPRequest carries no cookie of the user.
	Binding string

	RelayState    string
	RequestBuffer []byte
	Request       LogoutRequest

	// ServiceProviderMetadata is the metadata of the service provider that
	// issued the request, and SLOEndpoint is the SingleLogoutService endpoint
	// of that service provider the LogoutResponse is sent to. Both are set by
	// Validate. For a request received with the SOAP binding, the response
	// is returned in the HTTP response, so SLOEndpoint has the SOAP binding
	// and no Location.
	ServiceProviderMetadata *EntityDescriptor
	SLOEndpoint             *Endpoint

	Now time.Time

	// redirectMessage is the parsed query of a request received with the
	// HTTP-Redirect binding. Its signature is checked by Validate.
	redirectMessage *redirectBindingMessage

	// simpleSign is the message of a request received with the
	// HTTP-POST-SimpleSign binding. Its signature is checked by Validate.
	simpleSign *simpleSignMessage

	// authenticated is set by Validate once the signature of the request
	// has been verified, so that the service provider that issued it is
	// known even if Validate then fails.
	authenticated bool
}

// NewIdpLogoutRequest returns a new IdpLogoutRequest for the given HTTP
// request to the single logout service. A GET request is decoded as an
// HTTP-Redirect binding message, a POST request as an HTTP-POST binding
// message, or as an HTTP-POST-SimpleSign binding message when the form has
// a SigAlg or Signature field, and a POST request whose Content-Type is text/xml as a SOAP
// binding message (a SOAP 1.1 envelope whose Body holds the LogoutRequest)
// if LogoutBindings includes SOAPBinding. The request is not validated; call
// Validate for that.
func NewIdpLogoutRequest(idp *IdentityProvider, r *http.Request) (*IdpLogoutRequest, error) {
	req := &IdpLogoutRequest{
		IDP:         idp,
		HTTPRequest: r,
		Now:         idp.now(),
	}

	switch {
	case IsSOAPRequest(r):
		if !idp.acceptsSOAPLogout() {
			return nil, errors.New("the SOAP binding is not enabled for single logout")
		}
		var err error
		req.RequestBuffer, err = readSOAPLogoutRequest(r)
		if err != nil {
			return nil, err
		}
		req.Binding = SOAPBinding
	case r.Method == http.MethodGet:
		m, err := parseRedirectBindingQuery(r.URL.RawQuery, redirectParamSAMLRequest)
		if err != nil {
			return nil, err
		}
		compressed, err := base64.StdEncoding.DecodeString(m.Message)
		if err != nil {
			return nil, fmt.Errorf("cannot decode request: %w", err)
		}
		req.RequestBuffer, err = io.ReadAll(newSaferFlateReader(bytes.NewReader(compressed)))
		if err != nil {
			return nil, fmt.Errorf("cannot decompress request: %w", err)
		}
		req.Binding = HTTPRedirectBinding
		req.RelayState = m.RelayState
		req.redirectMessage = m
	case r.Method == http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("cannot parse form: %w", err)
		}
		simpleSign, err := parseSimpleSignRequest(r, redirectParamSAMLRequest)
		if err != nil {
			return nil, err
		}
		if simpleSign != nil {
			req.RequestBuffer = simpleSign.XML
			req.Binding = HTTPPostSimpleSignBinding
			req.RelayState = simpleSign.RelayState
			req.simpleSign = simpleSign
			break
		}
		req.RequestBuffer, err = base64.StdEncoding.DecodeString(r.PostForm.Get(redirectParamSAMLRequest))
		if err != nil {
			return nil, fmt.Errorf("cannot decode request: %w", err)
		}
		req.Binding = HTTPPostBinding
		req.RelayState = r.PostForm.Get(redirectParamRelayState)
	default:
		return nil, errors.New("method not allowed")
	}
	return req, nil
}

// Validate checks that the logout request is well formed, was issued by a
// known service provider, is signed by that service provider, and is
// addressed to this IdP and still current. It assigns Request,
// ServiceProviderMetadata and SLOEndpoint. It returns a non-nil error if the
// request is not valid.
//
// The principal is identified by a NameID or an EncryptedID, or by a BaseID
// if the IdP's AcceptLogoutRequestBaseID is set. An EncryptedID is decrypted
// with the IdP's Key, if it is an *rsa.PrivateKey, then with each of its
// DecryptionKeys; Request.NameID (or Request.BaseID) is then set to the
// identifier it holds.
//
// The request must be signed: with the HTTP-Redirect binding, with a query
// string signature (SigAlg and Signature) or an enveloped XML signature;
// with the HTTP-POST binding, with an enveloped XML signature; with the
// HTTP-POST-SimpleSign binding, with its SimpleSign signature. The signature
// is checked against the signing certificates in the service provider's
// metadata (saml-profiles-2.0-os §4.4.4.1). As is usual for keys distributed
// in metadata, the certificates' validity periods are not checked.
//
// If IdentityProvider.ReplayCache is set, the request's ID is recorded in it
// once the request is otherwise valid, and a request whose ID is already
// recorded is refused, so Validate accepts a given request only once.
func (req *IdpLogoutRequest) Validate() error {
	root, err := req.parseRequest()
	if err != nil {
		return err
	}

	if req.Request.Issuer == nil || req.Request.Issuer.Value == "" {
		return errors.New("logout request is missing an issuer")
	}
	if req.IDP.ServiceProviderProvider == nil {
		return errors.New("IdentityProvider.ServiceProviderProvider is not set")
	}
	serviceProviderID := req.Request.Issuer.Value
	serviceProvider, err := req.IDP.ServiceProviderProvider.GetServiceProvider(req.HTTPRequest, serviceProviderID)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot handle logout request from unknown service provider %s", serviceProviderID)
	} else if err != nil {
		return fmt.Errorf("cannot find service provider %s: %w", serviceProviderID, err)
	}
	if serviceProvider == nil {
		return fmt.Errorf("cannot find service provider %s", serviceProviderID)
	}
	req.ServiceProviderMetadata = serviceProvider

	signed, err := req.verifySignature(root)
	if err != nil {
		return fmt.Errorf("cannot verify signature of logout request from %s: %w", serviceProviderID, err)
	}
	if signed != nil {
		// Read the request again from what the enveloped signature covers.
		// The issuer it names must be the one whose keys verified it.
		req.Request = LogoutRequest{}
		if err := unmarshalElement(signed, &req.Request); err != nil {
			return fmt.Errorf("cannot parse logout request: %w", err)
		}
		if req.Request.Issuer == nil || req.Request.Issuer.Value != serviceProviderID {
			return fmt.Errorf("signed logout request is not from %s", serviceProviderID)
		}
	}
	req.authenticated = true
	if err := req.validateFields(); err != nil {
		return err
	}

	req.SLOEndpoint, err = req.sloEndpoint()
	if err != nil {
		return fmt.Errorf("cannot respond to logout request from %s: %w", serviceProviderID, err)
	}

	// Record the request last, so that only a request that is otherwise
	// valid uses up its ID.
	if err := consumeLogoutRequest(req.IDP.ReplayCache, &req.Request); err != nil {
		return fmt.Errorf("cannot accept logout request from %s: %w", serviceProviderID, err)
	}
	return nil
}

// parseRequest parses RequestBuffer into Request and returns the root
// element of the request.
func (req *IdpLogoutRequest) parseRequest() (*etree.Element, error) {
	if err := xmlroundtrip.Validate(req.RequestBuffer); err != nil {
		return nil, fmt.Errorf("logout request contains invalid XML: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.RequestBuffer); err != nil {
		return nil, fmt.Errorf("cannot parse logout request: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("cannot parse logout request: no root element")
	}
	// LogoutRequest binds its element names to their namespaces, so this
	// fails unless the root is a samlp:LogoutRequest. unmarshalElement
	// reads attribute fields only from unqualified attributes, so a
	// namespace declaration that the signature does not cover cannot
	// replace one.
	if err := unmarshalElement(root, &req.Request); err != nil {
		return nil, fmt.Errorf("cannot parse logout request: %w", err)
	}
	return root, nil
}

// verifySignature checks the signature of the request against the signing
// certificates of the service provider that issued it.
//
// For an enveloped XML signature it returns what the signature covers (see
// verifiedEnvelopedElement); for a query string signature, which covers the
// whole message, it returns nil.
func (req *IdpLogoutRequest) verifySignature(root *etree.Element) (*etree.Element, error) {
	// spSigningCerts (shared with the HTTP-POST-SimpleSign binding) fails if
	// the metadata has no signing certificate.
	certs, err := spSigningCerts(req.ServiceProviderMetadata)
	if err != nil {
		return nil, err
	}

	if req.simpleSign != nil {
		// The signature covers the whole message, as received.
		return nil, checkSPSimpleSignSignature(req.IDP.RejectSHA1Signatures, req.simpleSign, req.ServiceProviderMetadata, req.Now)
	}
	if req.redirectMessage != nil && req.redirectMessage.SignedContent != nil {
		if err := checkSigAlgNotSHA1(req.IDP.RejectSHA1Signatures, req.redirectMessage.SigAlg); err != nil {
			return nil, err
		}
		return nil, checkRedirectBindingSignature(req.redirectMessage, func() ([]*x509.Certificate, error) {
			return certs, nil
		}, req.Now, true)
	}
	if err := checkEnvelopedSignatureNotSHA1(req.IDP.RejectSHA1Signatures, root); err != nil {
		return nil, err
	}
	return verifiedEnvelopedElement(root, certs, req.IDP.dsigClock())
}

// validateFields checks the fields of the (authenticated) request.
func (req *IdpLogoutRequest) validateFields() error {
	r := &req.Request
	if r.Version != "2.0" {
		return fmt.Errorf("expected SAML request version 2.0 got %v", r.Version)
	}
	if r.ID == "" {
		return errors.New("logout request is missing an ID")
	}

	if err := req.validateDestination(); err != nil {
		return err
	}

	if r.IssueInstant.Add(MaxIssueDelay).Before(req.Now) {
		return fmt.Errorf("logout request expired at %s", r.IssueInstant.Add(MaxIssueDelay))
	}
	if r.IssueInstant.Add(-MaxClockSkew).After(req.Now) {
		return fmt.Errorf("logout request IssueInstant %s is in the future", r.IssueInstant)
	}
	if r.NotOnOrAfter != nil && !req.Now.Before(r.NotOnOrAfter.Add(MaxClockSkew)) {
		return fmt.Errorf("logout request expired at %s", r.NotOnOrAfter)
	}
	if err := resolveLogoutRequestNameID(r, req.IDP.decryptElement, req.IDP.AcceptLogoutRequestBaseID); err != nil {
		return fmt.Errorf("logout request: %w", err)
	}
	return nil
}

// validateDestination checks the Destination of the request. A message
// signed for the HTTP-Redirect or HTTP-POST binding must carry a
// Destination, and it must be the location at which the message was
// received (saml-bindings-2.0-os §3.4.5.2 and §3.5.5.2). The SOAP binding
// has no such rule, as the message goes straight from the service provider
// to the IdP, so Destination may then be absent; if present it must still be
// LogoutURL (saml-core-2.0-os §3.2.1).
func (req *IdpLogoutRequest) validateDestination() error {
	destination := req.Request.Destination
	if req.Binding == SOAPBinding && destination == "" {
		return nil
	}
	if logoutURL := req.IDP.LogoutURL.String(); logoutURL == "" || destination != logoutURL {
		return fmt.Errorf("expected logout request destination to be %q, not %q", logoutURL, destination)
	}
	return nil
}

// sloEndpoint returns the SingleLogoutService endpoint of the service
// provider to send the LogoutResponse to. It prefers an endpoint with the
// binding the request was received with, and otherwise uses the first one
// with a binding that ServeSLO can respond with. A request received with
// the SOAP binding is answered in the HTTP response, at no endpoint of the
// metadata.
func (req *IdpLogoutRequest) sloEndpoint() (*Endpoint, error) {
	if req.Binding == SOAPBinding {
		return &Endpoint{Binding: SOAPBinding}, nil
	}
	// The IdP cannot send a SimpleSign LogoutResponse; a request that came
	// with that binding is answered with HTTP-POST if it can be.
	preferred := req.Binding
	if preferred == HTTPPostSimpleSignBinding {
		preferred = HTTPPostBinding
	}
	var fallback *Endpoint
	for _, spssoDescriptor := range req.ServiceProviderMetadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.SingleLogoutServices {
			if endpoint.Binding != HTTPRedirectBinding && endpoint.Binding != HTTPPostBinding {
				continue
			}
			if location, err := checkEndpointLocation(endpoint.Binding, logoutResponseLocation(endpoint)); err != nil || location == "" {
				continue
			}
			if endpoint.Binding == preferred {
				return &endpoint, nil
			}
			if fallback == nil {
				fallback = &endpoint
			}
		}
	}
	if fallback == nil {
		return nil, errors.New("the service provider metadata has no HTTP-Redirect or HTTP-POST SingleLogoutService endpoint")
	}
	return fallback, nil
}

// logoutResponseLocation returns the location a LogoutResponse is sent to at
// endpoint: its ResponseLocation if set, otherwise its Location
// (saml-metadata-2.0-os §2.2.2).
func logoutResponseLocation(endpoint Endpoint) string {
	if endpoint.ResponseLocation != "" {
		return endpoint.ResponseLocation
	}
	return endpoint.Location
}

// MatchesSession reports whether session is one that the logout request asks
// to terminate: its NameID must be the request's NameID and, if the request
// carries any SessionIndex, its Index must be equal to one of them
// (saml-core-2.0-os §3.7.1). Call it only after Validate has succeeded.
//
// The NameID's Format, NameQualifier and SPNameQualifier are not compared:
// Session does not record the qualifiers, and service providers, including
// those built with this package (ServiceProvider.MakeLogoutRequest), often
// send their configured NameID format rather than the one they were
// issued. ServeSLO instead refuses a request from a service provider that
// is not a participant of the sessions it names, when the SessionProvider
// tracks participants.
func (req *IdpLogoutRequest) MatchesSession(session *Session) bool {
	if session == nil || req.Request.NameID == nil || req.Request.NameID.Value == "" {
		return false
	}
	if session.NameID != req.Request.NameID.Value {
		return false
	}
	sessionIndexes := req.Request.AllSessionIndexes()
	if len(sessionIndexes) == 0 {
		return true
	}
	for _, sessionIndex := range sessionIndexes {
		if sessionIndex.Value == session.Index {
			return true
		}
	}
	return false
}

// MakeLogoutResponse returns an unsigned LogoutResponse to the request with
// the given top-level status code (for example StatusSuccess or
// StatusResponder), addressed to SLOEndpoint. Validate must have succeeded.
func (req *IdpLogoutRequest) MakeLogoutResponse(statusCode string) *LogoutResponse {
	var destination string
	if req.SLOEndpoint != nil {
		destination = logoutResponseLocation(*req.SLOEndpoint)
	}
	return &LogoutResponse{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		InResponseTo: req.Request.ID,
		Version:      "2.0",
		IssueInstant: req.Now,
		Destination:  destination,
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.MetadataURL.String(),
		},
		Status: Status{
			StatusCode: StatusCode{Value: statusCode},
		},
	}
}

// WriteLogoutResponse signs resp with the IdP's key and sends it to the
// browser using the binding of SLOEndpoint: with HTTP-Redirect, a redirect
// whose query carries a SigAlg and Signature (saml-bindings-2.0-os
// §3.4.4.1); with HTTP-POST, an auto-submitting form (see
// IdentityProvider.ResponseFormTemplate) carrying the response with an
// enveloped XML signature. The request's RelayState is passed back. With the
// SOAP binding, the response, with an enveloped XML signature, is written in
// a SOAP envelope as the answer to the service provider's HTTP request.
//
// It returns errors before it starts writing to w.
func (req *IdpLogoutRequest) WriteLogoutResponse(w http.ResponseWriter, resp *LogoutResponse) error {
	if req.SLOEndpoint == nil {
		return errors.New("no SingleLogoutService endpoint to send the logout response to; call Validate first")
	}
	signingContext, err := req.IDP.signingContext()
	if err != nil {
		return err
	}

	switch req.SLOEndpoint.Binding {
	case HTTPRedirectBinding:
		return req.writeRedirectLogoutResponse(w, resp, signingContext)
	case HTTPPostBinding:
		return req.writePostLogoutResponse(w, resp, signingContext)
	case SOAPBinding:
		return writeSOAPLogoutResponse(w, resp, signingContext)
	default:
		return fmt.Errorf("unsupported binding %s", req.SLOEndpoint.Binding)
	}
}

func (req *IdpLogoutRequest) writeRedirectLogoutResponse(w http.ResponseWriter, resp *LogoutResponse, signingContext *dsig.SigningContext) error {
	unsigned := *resp
	unsigned.Signature = nil
	encoded, err := deflateAndEncode(unsigned.Element())
	if err != nil {
		return err
	}
	sigAlg := signingContext.GetSignatureMethodIdentifier()
	if sigAlg == "" {
		return errors.New("cannot determine the signature algorithm")
	}
	u, err := signedRedirectBindingURL(resp.Destination, redirectParamSAMLResponse, encoded, req.RelayState, sigAlg, signingContext)
	if err != nil {
		return err
	}
	setNoCacheHeaders(w.Header())
	http.Redirect(w, req.HTTPRequest, u.String(), http.StatusFound) //nolint:gosec // the destination is the SingleLogoutService location from the SP metadata (http/https only); the request only contributes the query-escaped RelayState
	return nil
}

func (req *IdpLogoutRequest) writePostLogoutResponse(w http.ResponseWriter, resp *LogoutResponse, signingContext *dsig.SigningContext) error {
	signed, err := signingContext.SignEnveloped(resp.Element())
	if err != nil {
		return err
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	if err != nil {
		return err
	}

	tmpl := req.IDP.ResponseFormTemplate
	if tmpl == nil {
		tmpl = defaultResponseFormTemplate
	}
	form := IdpAuthnRequestForm{
		URL:          resp.Destination,
		SAMLResponse: base64.StdEncoding.EncodeToString(buf),
		RelayState:   req.RelayState,
	}
	out := bytes.NewBuffer(nil)
	if err := tmpl.Execute(out, form); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setNoCacheHeaders(w.Header())
	_, err = io.Copy(w, out)
	return err
}

// ServeSLO handles SAML LogoutRequests sent by service providers
// (SP-initiated single logout, saml-profiles-2.0-os §4.4) with the
// HTTP-Redirect, HTTP-POST or HTTP-POST-SimpleSign binding. Serve it at
// LogoutURL. A SimpleSign request is answered with HTTP-POST (or
// HTTP-Redirect), as the IdP does not send SimpleSign logout messages. It also
// handles the LogoutResponses of service providers to the LogoutRequests the
// IdP sends while it propagates a logout (see StartLogout and
// SessionParticipantTracker).
//
// The request must be signed by the service provider and is validated as
// described in IdpLogoutRequest.Validate. An invalid request, or one already
// recorded in ReplayCache, is answered with HTTP 400 and no LogoutResponse.
//
// If the SessionProvider implements SessionParticipantTracker and it lists
// participants for the sessions the request names, but the service provider
// that sent it is not one of them, the request is refused: no session is
// ended, and it is answered with StatusRequester. Otherwise any service
// provider that can name a user's NameID could end that user's sessions,
// and have the logout propagated to every service provider they use.
//
// For a valid request, the IdP session is terminated by calling
// InvalidateSession if the SessionProvider implements SessionInvalidator.
// Then a signed LogoutResponse is sent to the service provider's
// SingleLogoutService endpoint, preferring the binding the request came
// with. Its status is StatusSuccess if the session was terminated, and
// StatusResponder if InvalidateSession failed or the SessionProvider does not
// implement SessionInvalidator, as the IdP session was then not ended.
//
// If the SessionProvider implements SessionParticipantTracker and the session
// was terminated, the logout is first propagated to the other service
// providers the ended sessions were used for (saml-profiles-2.0-os
// §4.4.4.2), as StartLogout does: over the SOAP binding to those whose
// metadata lists a SOAP SingleLogoutService, and otherwise by sending the
// browser to each with a LogoutRequest, one at a time. Only then is the
// LogoutResponse sent to the service provider that asked. If some of them
// could not be logged out, its status is StatusSuccess with the second-level
// status StatusPartialLogout (saml-core-2.0-os §3.7.3.2). Without a
// SessionParticipantTracker, the logout is not propagated, and the status is
// a plain StatusSuccess unless ReportPartialLogoutWithoutTracker is set, in
// which case it carries StatusPartialLogout, as the other participants could
// not be contacted.
//
// If LogoutBindings includes SOAPBinding, ServeSLO also accepts a
// LogoutRequest sent server to server with the SOAP binding
// (saml-bindings-2.0-os §3.2): a POST whose Content-Type is text/xml and
// whose body, of at most MaxSOAPLogoutMessageSize bytes, is a SOAP 1.1
// envelope holding the LogoutRequest. No browser takes part, so:
//
//   - the request must carry an enveloped XML signature by the service
//     provider (the IdP does not authenticate it by TLS client certificate);
//     its Destination may be absent;
//   - the SessionInvalidator is called with no session cookie of the user,
//     and must find the sessions with req.MatchesSession (see
//     SessionInvalidator);
//   - the logout is propagated only to the participants whose metadata lists
//     a SOAP SingleLogoutService. The others cannot be reached without a
//     browser and count as not logged out (StatusPartialLogout);
//   - the signed LogoutResponse is the HTTP response, in a SOAP envelope.
//     A request that is authenticated but invalid (for example expired,
//     replayed, or with an EncryptedID that cannot be decrypted) is answered
//     with StatusRequester. A request that cannot be read or authenticated is
//     answered with a SOAP Client fault and HTTP 500 (SOAP 1.1 §6.2), with no
//     LogoutResponse.
func (idp *IdentityProvider) ServeSLO(w http.ResponseWriter, r *http.Request) {
	if IsSOAPRequest(r) && idp.acceptsSOAPLogout() {
		idp.serveSOAPLogoutRequest(w, r)
		return
	}
	if isLogoutResponseMessage(r) {
		idp.serveLogoutResponse(w, r)
		return
	}

	req, err := NewIdpLogoutRequest(idp, r)
	if err != nil {
		idp.Logger.Printf("failed to parse logout request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if err := req.Validate(); err != nil {
		idp.Logger.Printf("failed to validate logout request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Find the other participants before the sessions are ended.
	participants, isParticipant, tracked, participantsErr := idp.sessionParticipantsOf(r, req.MatchesSession, req.ServiceProviderMetadata.EntityID)
	if participantsErr != nil {
		idp.Logger.Printf("cannot find the session participants to propagate logout request %s from %s to: %s",
			req.Request.ID, req.ServiceProviderMetadata.EntityID, participantsErr)
	}

	if !isParticipant {
		idp.refuseNonParticipantLogout(req)
		if err := req.WriteLogoutResponse(w, req.MakeLogoutResponse(StatusRequester)); err != nil {
			idp.Logger.Printf("failed to write logout response: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return
	}

	statusCode := idp.invalidateSession(w, r, req)

	if statusCode == StatusSuccess && len(participants) > 0 {
		idp.propagateLogout(w, r, req, participants)
		return
	}
	resp := req.MakeLogoutResponse(statusCode)
	if statusCode == StatusSuccess && idp.participantsUnknown(tracked, participantsErr) {
		resp = makeLogoutResponseWithStatus(req, true)
	}
	if err := req.WriteLogoutResponse(w, resp); err != nil {
		idp.Logger.Printf("failed to write logout response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

// refuseNonParticipantLogout logs that req, a valid LogoutRequest, is
// refused because its service provider is not a participant of the sessions
// it names. The caller answers it with StatusRequester.
func (idp *IdentityProvider) refuseNonParticipantLogout(req *IdpLogoutRequest) {
	idp.Logger.Printf("refusing logout request %s from %s: it is not a participant of the sessions it names",
		req.Request.ID, req.ServiceProviderMetadata.EntityID)
}

// invalidateSession ends the IdP sessions the valid LogoutRequest req refers
// to with the SessionProvider's SessionInvalidator, and returns the status
// to answer req with: StatusSuccess if they were ended, StatusResponder if
// they could not be.
func (idp *IdentityProvider) invalidateSession(w http.ResponseWriter, r *http.Request, req *IdpLogoutRequest) string {
	invalidator, ok := idp.SessionProvider.(SessionInvalidator)
	if !ok {
		idp.Logger.Printf("cannot terminate session for logout request %s from %s: the SessionProvider does not implement SessionInvalidator",
			req.Request.ID, req.ServiceProviderMetadata.EntityID)
		return StatusResponder
	}
	if err := invalidator.InvalidateSession(w, r, req); err != nil {
		idp.Logger.Printf("failed to terminate session for logout request %s from %s: %s",
			req.Request.ID, req.ServiceProviderMetadata.EntityID, err)
		return StatusResponder
	}
	return StatusSuccess
}

// verifiedEnvelopedElement checks the enveloped XML signature of el, which
// must be a direct child of el and reference it as saml-core-2.0-os §5.4.2
// asks (see checkSignatureReference), against certs, and returns
// what the signature covers: el without its Signature, parsed from the
// canonical bytes that were digested. The certificates' validity periods are
// ignored. clock may be nil.
func verifiedEnvelopedElement(el *etree.Element, certs []*x509.Certificate, clock *dsig.Clock) (*etree.Element, error) {
	sigEl, err := findChild(el, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	if err != nil {
		return nil, err
	}
	if sigEl == nil {
		return nil, errSignatureElementNotPresent
	}

	certs = withoutValidityPeriod(certs)
	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	validationContext.IdAttribute = "ID"
	if clock != nil {
		validationContext.Clock = clock
	}

	noCertInKeyInfo := stripKeyInfoWithoutCertificate(el)

	ctx, err := unboundedParentContext(el)
	if err != nil {
		return nil, err
	}
	ctx, err = ctx.SubContext(el)
	if err != nil {
		return nil, err
	}
	el, err = etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, err
	}

	// See ServiceProvider.validateSignature: without a certificate in
	// KeyInfo, dsig can only pick the certificate itself if it trusts
	// exactly one.
	var signed *etree.Element
	if noCertInKeyInfo && len(certs) > 1 {
		signed, err = validatedWithEachCert(validationContext, certs, el)
	} else {
		signed, err = validationContext.Validate(el)
	}
	if err != nil {
		return nil, err
	}
	if err := checkSignatureReference(el); err != nil {
		return nil, err
	}
	return signed, nil
}
