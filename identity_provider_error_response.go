package saml

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// errVersionMismatch is attached, with ErrUnsupported, when an AuthnRequest
// is not SAML 2.0, so that ServeSSO can answer it with a VersionMismatch
// status.
var errVersionMismatch = errors.New("saml: version mismatch")

// StatusError is an error that asks the IdentityProvider to answer an
// AuthnRequest with a SAML <Response> carrying an error <Status> and no
// assertion, as saml-core §3.4.1.4 requires when the identity provider
// cannot or will not authenticate the principal as requested (for example
// Responder with NoPassive for an IsPassive request it cannot satisfy
// without a login prompt, or Responder with NoAuthnContext).
//
// When an AssertionMaker returns a *StatusError (possibly wrapped),
// ServeSSO and ServeIDPInitiated send that Response to the assertion
// consumer service instead of responding with HTTP 500. A SessionProvider
// can send one itself with IdentityProvider.SendErrorResponse, and then
// return nil.
type StatusError struct {
	// TopLevel is the top-level status code: StatusRequester,
	// StatusResponder or StatusVersionMismatch (saml-core §3.2.2.2).
	TopLevel string

	// SecondLevel, if not empty, is the second-level status code nested in
	// the top-level one, such as StatusNoPassive, StatusNoAuthnContext,
	// StatusRequestDenied or StatusInvalidNameIDPolicy.
	SecondLevel string

	// Message, if not empty, is sent as the <StatusMessage>. It is read by
	// the service provider, so it should not reveal anything the service
	// provider should not know.
	Message string
}

// Error implements error.
func (e *StatusError) Error() string {
	msg := "saml: status " + e.TopLevel
	if e.SecondLevel != "" {
		msg += " (" + e.SecondLevel + ")"
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

// MakeErrorResponse sets ResponseEl to a signed SAML <Response> to the
// request with an error <Status> and no assertion: topLevel is the top-level
// status code, which must be StatusRequester, StatusResponder or
// StatusVersionMismatch; secondLevel, if not empty, the second-level status
// code nested in it; and message, if not empty, the <StatusMessage>. The
// Response has the same Issuer, InResponseTo and Destination as the one
// MakeResponse makes, so the request must have an ACSEndpoint, as it does
// once Validate has succeeded or NewIdpInitiatedRequest has returned it.
//
// Assertion and AssertionEl are set to nil, so that a ResponseWriter sees
// there is no assertion. Write the Response with WriteResponse or a
// ResponseWriter, as for a successful Response, or use
// IdentityProvider.SendErrorResponse to do both.
func (req *IdpAuthnRequest) MakeErrorResponse(topLevel, secondLevel, message string) error {
	switch topLevel {
	case StatusRequester, StatusResponder, StatusVersionMismatch:
	default:
		return fmt.Errorf("cannot make an error response with top-level status %q", topLevel)
	}
	if req.ACSEndpoint == nil {
		return errors.New("cannot make an error response: no assertion consumer service")
	}

	status := Status{StatusCode: StatusCode{Value: topLevel}}
	if secondLevel != "" {
		status.StatusCode.StatusCode = &StatusCode{Value: secondLevel}
	}
	if message != "" {
		status.StatusMessage = &StatusMessage{Value: message}
	}
	response := &Response{
		Destination:  req.ACSEndpoint.Location,
		ID:           fmt.Sprintf("id-%x", randomBytes(req.IDP.randReader(), 20)),
		InResponseTo: req.Request.ID,
		IssueInstant: req.Now,
		Version:      "2.0",
		Issuer: &Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.MetadataURL.String(),
		},
		Status: status,
	}

	signingContext, err := req.signingContext()
	if err != nil {
		return err
	}
	signedResponseEl, err := signingContext.SignEnveloped(response.Element())
	if err != nil {
		return err
	}
	response.Signature = signedResponseEl.ChildElements()[len(signedResponseEl.ChildElements())-1]

	req.Assertion = nil
	req.AssertionEl = nil
	req.ResponseEl = response.Element()
	return nil
}

// SendErrorResponse makes the error Response statusErr describes for req
// with req.MakeErrorResponse and writes it with the ResponseWriter, as
// ServeSSO does when the AssertionMaker returns a *StatusError. A
// SessionProvider can call it to answer a request it will not prompt the
// user for, such as an IsPassive one, and then return nil from GetSession.
//
// req must have been validated: the Response goes to req.ACSEndpoint, which
// must come from the service provider's metadata. If it returns an error,
// nothing has been written to w unless the ResponseWriter failed part way.
func (idp *IdentityProvider) SendErrorResponse(w http.ResponseWriter, req *IdpAuthnRequest, statusErr *StatusError) error {
	if statusErr == nil {
		return errors.New("cannot send an error response without a status")
	}
	if err := req.MakeErrorResponse(statusErr.TopLevel, statusErr.SecondLevel, statusErr.Message); err != nil {
		return fmt.Errorf("failed to make error response: %w", err)
	}
	if err := idp.responseWriter().WriteResponse(w, req); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	return nil
}

// sendStatusError sends the error Response statusErr describes, and reports
// an HTTP 500 error through onError if it cannot.
func (idp *IdentityProvider) sendStatusError(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest, statusErr *StatusError) {
	if err := idp.SendErrorResponse(w, req, statusErr); err != nil {
		idp.onError(w, r, http.StatusInternalServerError, err)
	}
}

// validationErrorResponse returns the error status ServeSSO answers with
// for an AuthnRequest that Validate rejected with err, or nil if the request
// must be answered with HTTP 400 instead: UnsupportedBinding (see
// unsupportedBindingStatusError), or, when SendErrorResponses is set, the
// status validationStatusError returns.
func (req *IdpAuthnRequest) validationErrorResponse(err error) *StatusError {
	if errors.Is(err, errUnsupportedACSBinding) {
		return req.unsupportedBindingStatusError()
	}
	if req.IDP.SendErrorResponses {
		return req.validationStatusError(err)
	}
	return nil
}

// checkSendableACS returns an error matching errUnsupportedACSBinding if
// the default ResponseWriter is used and the assertion consumer service of
// the validated request has a binding it cannot send a Response with (see
// isSendableBinding). A custom ResponseWriter may support other bindings,
// so it is given the endpoint.
func (req *IdpAuthnRequest) checkSendableACS() error {
	switch req.IDP.ResponseWriter.(type) {
	case nil, DefaultResponseWriter, *DefaultResponseWriter:
	default:
		return nil
	}
	if isSendableBinding(req.ACSEndpoint.Binding) {
		return nil
	}
	return classify(fmt.Errorf("cannot send a response to an assertion consumer service with binding %q", req.ACSEndpoint.Binding),
		ErrUnsupported, errUnsupportedACSBinding)
}

// unsupportedBindingStatusError returns the error status ServeSSO answers
// with when the IdP cannot send a Response to the assertion consumer service
// the request names: Requester with the second-level status
// UnsupportedBinding (saml-core §3.2.2.2). It sets ACSEndpoint to the
// service provider's default assertion consumer service among those the IdP
// can send to, so that the Response goes to an endpoint from the metadata,
// never to one the request alone names. It returns nil, so that the request
// gets HTTP 400, if there is no such endpoint or the request has no ID to
// answer.
//
// It is only used once the request has passed every other check of
// Validate: it is current, SAML 2.0, has an ID and a Destination as
// required, comes from a known service provider, and has a valid
// SimpleSign signature if it came with that binding. Validate checks the
// assertion consumer service last, and only returns errUnsupportedACSBinding
// from there; checkSendableACS runs once Validate has succeeded.
func (req *IdpAuthnRequest) unsupportedBindingStatusError() *StatusError {
	if req.Request.ID == "" || req.ServiceProviderMetadata == nil {
		return nil
	}
	if !req.selectDefaultACSEndpoint() {
		return nil
	}
	return &StatusError{
		TopLevel:    StatusRequester,
		SecondLevel: StatusUnsupportedBinding,
		Message:     "the requested assertion consumer service binding is not supported",
	}
}

// validationStatusError returns the error status ServeSSO answers with,
// when SendErrorResponses is set, for an AuthnRequest that Validate rejected
// with err, or nil if the request must be answered with HTTP 400 instead.
//
// Only an expired request or one with another SAML version is answered, and
// only when the rest of the request checks out: it has an ID to answer, a
// known service provider as its Issuer, a valid SimpleSign signature if it
// came with that binding, and names an assertion consumer service in the
// service provider's metadata that a Response can be posted to.
func (req *IdpAuthnRequest) validationStatusError(err error) *StatusError {
	var statusErr *StatusError
	switch {
	case errors.Is(err, errVersionMismatch):
		statusErr = &StatusError{
			TopLevel:    StatusVersionMismatch,
			SecondLevel: versionMismatchSecondLevel(req.Request.Version),
			Message:     "SAML version 2.0 is required",
		}
	case errors.Is(err, ErrExpired):
		statusErr = &StatusError{
			TopLevel: StatusRequester,
			Message:  "the request has expired",
		}
	default:
		return nil
	}

	if req.Request.ID == "" {
		return nil
	}
	if err := req.resolveServiceProvider(); err != nil {
		return nil
	}
	if binding := req.ACSEndpoint.Binding; binding != HTTPPostBinding && binding != HTTPPostSimpleSignBinding {
		return nil
	}
	return statusErr
}

// versionMismatchSecondLevel returns RequestVersionTooHigh or
// RequestVersionTooLow for a request whose major version is above or below
// 2, or "" if the version cannot be compared.
func versionMismatchSecondLevel(version string) string {
	majorStr, _, _ := strings.Cut(version, ".")
	major, err := strconv.Atoi(majorStr)
	switch {
	case err != nil:
		return ""
	case major > 2:
		return StatusRequestVersionTooHigh
	case major < 2:
		return StatusRequestVersionTooLow
	default:
		return ""
	}
}
