package saml

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/internal/signerutil"
)

// This file implements both sides of the Single Logout profile
// (saml-profiles §4.4) over the SAML SOAP binding (saml-bindings §3.2) at
// the service provider: answering the IdP's back-channel LogoutRequests, and
// sending the IdP a LogoutRequest without involving the browser.

// MaxSOAPLogoutMessageSize is the largest SOAP message body, in bytes, that
// the service provider reads in back-channel single logout: a LogoutRequest
// the IdP sends with ValidateSOAPLogoutRequest, and the IdP's answer to
// SendSOAPLogoutRequest. A larger body is rejected without being parsed.
var MaxSOAPLogoutMessageSize int64 = 1 << 20

// ErrNoSOAPSingleLogoutService is returned by MakeSOAPLogoutRequest when the
// IdP metadata publishes no SingleLogoutService with the SAML SOAP binding.
var ErrNoSOAPSingleLogoutService = errors.New("the IdP metadata has no SingleLogoutService with the SOAP binding")

// IsSOAPRequest reports whether r is a message sent with the SAML SOAP
// binding: a POST whose Content-Type is text/xml (SOAP 1.1 over HTTP,
// saml-bindings §3.2.3.1). Browser bindings post forms instead.
func IsSOAPRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "text/xml"
}

// readLimited reads r to the end, failing if it holds more than limit bytes.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("body is larger than %d bytes", limit)
	}
	return buf, nil
}

// ValidateSOAPLogoutRequest validates a LogoutRequest the IdP sent to the
// SingleLogoutService of this service provider with the SAML SOAP binding
// (back-channel single logout, saml-profiles §4.4). r must be a POST with
// Content-Type text/xml (see IsSOAPRequest), and its body, at most
// MaxSOAPLogoutMessageSize bytes, is checked with ParseXMLSOAPLogoutRequest.
//
// On success, end the sessions the request names, then answer it with
// MakeSOAPLogoutResponse and WriteSOAPLogoutResponse. On failure, which is an
// *InvalidResponseError, answer with WriteSOAPFault: an unauthenticated
// request must not be answered with a signed LogoutResponse.
func (sp *ServiceProvider) ValidateSOAPLogoutRequest(r *http.Request) (*LogoutRequest, error) {
	if !IsSOAPRequest(r) {
		return nil, &InvalidResponseError{
			PrivateErr: classify(errors.New("not a SOAP message: expected a POST with Content-Type text/xml"), ErrMalformedMessage),
			Now:        sp.now(),
		}
	}
	body, err := readLimited(r.Body, MaxSOAPLogoutMessageSize)
	if err != nil {
		return nil, &InvalidResponseError{
			PrivateErr: classify(fmt.Errorf("cannot read the SOAP message: %w", err), ErrMalformedMessage),
			Now:        sp.now(),
		}
	}
	return sp.ParseXMLSOAPLogoutRequest(body)
}

// ParseXMLSOAPLogoutRequest validates soapRequestXML, a SOAP 1.1 envelope
// whose Body holds a samlp:LogoutRequest from the IdP, and returns the
// request. Use it to receive LogoutRequests with your own transport;
// ValidateSOAPLogoutRequest calls it for you.
//
// The request is checked as ValidateLogoutRequest checks one, except that:
//
//   - it must carry an enveloped XML signature by the IdP, verified with the
//     IdP's signing certificates (and refused if it uses SHA-1 when
//     RejectSHA1Signatures is set). The SOAP binding has no other signature
//     this service provider could check, and a LogoutRequest ends sessions;
//   - its Destination may be omitted, since the SOAP binding does not
//     require it (saml-core §3.2.1, saml-bindings §3.2); if present it must
//     be SloURL.
//
// As with the other bindings, its IssueInstant and NotOnOrAfter must be
// current, its Issuer must be the IdP, an EncryptedID is decrypted into
// NameID, and, if ReplayCache is set, its ID must not have been seen before.
// AllSessionIndexes returns all its SessionIndexes.
//
// If the function fails it returns an *InvalidResponseError whose PrivateErr
// says what was wrong.
func (sp *ServiceProvider) ParseXMLSOAPLogoutRequest(soapRequestXML []byte) (*LogoutRequest, error) {
	req, err := sp.parseSOAPLogoutRequest(soapRequestXML)
	if err != nil {
		return nil, &InvalidResponseError{
			PrivateErr: err,
			Response:   string(soapRequestXML),
			Now:        sp.now(),
		}
	}
	return req, nil
}

func (sp *ServiceProvider) parseSOAPLogoutRequest(soapRequestXML []byte) (*LogoutRequest, error) {
	if sp.IDPMetadata == nil {
		return nil, errors.New("IDPMetadata is not set")
	}
	requestEl, err := soapBodyElement(soapRequestXML, "LogoutRequest")
	if err != nil {
		return nil, classify(err, ErrMalformedMessage)
	}
	signedEl, err := sp.requireIDPSignature(requestEl)
	if err != nil {
		return nil, err
	}

	var req LogoutRequest
	if err := unmarshalElement(signedEl, &req); err != nil {
		return nil, err
	}
	if req.Destination != "" && req.Destination != sp.SloURL.String() {
		return nil, classify(fmt.Errorf("`Destination` %q is not SloURL (%q)", req.Destination, sp.SloURL.String()), ErrDestinationMismatch)
	}
	if err := sp.validateLogoutRequestFields(&req); err != nil {
		return nil, err
	}
	if err := consumeLogoutRequest(sp.ReplayCache, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// requireIDPSignature verifies the enveloped signature of el, which must
// have one, against the IdP's signing certificates, and returns what the
// signature covers.
func (sp *ServiceProvider) requireIDPSignature(el *etree.Element) (*etree.Element, error) {
	signed, err := sp.verifySignedElement(el, sp.getIDPSigningCerts)
	if err == errSignatureElementNotPresent {
		return nil, classify(fmt.Errorf("the %s is not signed", el.Tag), ErrInvalidSignature)
	}
	return signed, err
}

// MakeSOAPLogoutResponse returns a LogoutResponse to the LogoutRequest
// logoutRequestID with the given status, to send back to the IdP with the
// SOAP binding (see WriteSOAPLogoutResponse). It has no Destination, since a
// SOAP response goes back over the IdP's own connection.
//
// Use a status code of StatusSuccess when every session the request named
// has ended, and StatusResponder when they could not be ended, for example
// because sessions are kept only in browser cookies (saml-core §3.7.3.2).
//
// The response is signed when Key is set, with SignatureMethod or, when that
// is empty, with SHA-256 for the type of Key: the SOAP binding has no other
// way to show the IdP that the answer comes from this service provider
// (saml-profiles §4.4.4.2). Without Key it is unsigned, and the IdP must
// authenticate the service provider some other way, such as with TLS.
func (sp *ServiceProvider) MakeSOAPLogoutResponse(logoutRequestID string, status Status) (*LogoutResponse, error) {
	resp := sp.makeUnsignedLogoutResponse("", logoutRequestID)
	resp.Status = status
	if signerutil.IsNil(sp.Key) {
		return resp, nil
	}
	sigEl, err := sp.soapSignature(resp.Element())
	if err != nil {
		return nil, err
	}
	resp.Signature = sigEl
	return resp, nil
}

// soapSignature signs el, a message for the SOAP binding, with Key and
// SignatureMethod (or, when that is empty, SHA-256 for the type of Key), and
// returns the Signature element.
func (sp *ServiceProvider) soapSignature(el *etree.Element) (*etree.Element, error) {
	signatureMethod := sp.SignatureMethod
	if signatureMethod == "" {
		signatureMethod = defaultSignatureMethod(sp.Key.Public())
	}
	signingContext, err := sp.signingContext(signatureMethod)
	if err != nil {
		return nil, err
	}
	return signatureOf(signingContext, el)
}

// signatureOf signs el with signingContext and returns the enveloped
// Signature element.
func signatureOf(signingContext *dsig.SigningContext, el *etree.Element) (*etree.Element, error) {
	signedEl, err := signingContext.SignEnveloped(el)
	if err != nil {
		return nil, err
	}
	sigEl, ok := signedEl.Child[len(signedEl.Child)-1].(*etree.Element)
	if !ok {
		return nil, errors.New("cannot sign: no Signature element")
	}
	return sigEl, nil
}

// WriteSOAPLogoutResponse writes resp to w in a SOAP 1.1 envelope, as the
// answer to a LogoutRequest received with the SOAP binding.
func WriteSOAPLogoutResponse(w http.ResponseWriter, resp *LogoutResponse) error {
	return writeSOAP(w, http.StatusOK, soapEnvelope(resp.Element()))
}

// WriteSOAPFault writes a SOAP 1.1 Fault with the faultcode Client and
// faultString to w, with HTTP status 500 (SOAP 1.1 §4.4 and §6.2). Use it to
// refuse a message received with the SOAP binding that is not valid, such
// as one ValidateSOAPLogoutRequest rejects. faultString is sent to the
// requester, so it should not say more than that the message was refused.
func WriteSOAPFault(w http.ResponseWriter, faultString string) error {
	fault := etree.NewElement("soapenv:Fault")
	fault.CreateElement("faultcode").SetText("soapenv:Client")
	fault.CreateElement("faultstring").SetText(faultString)
	return writeSOAP(w, http.StatusInternalServerError, soapEnvelope(fault))
}

func writeSOAP(w http.ResponseWriter, status int, envelope *etree.Element) error {
	buf, err := elementToBytes(envelope)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	// saml-bindings §3.2.3.3: the response should not be cached.
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, err = w.Write(buf)
	return err
}

// MakeSOAPLogoutRequest returns a LogoutRequest for the principal nameID,
// addressed to the IdP's SingleLogoutService with the SAML SOAP binding, to
// send with SendSOAPLogoutRequest. It returns ErrNoSOAPSingleLogoutService if
// the IdP metadata has none.
//
// nameID is sent as is: pass the NameID the IdP issued, with its Format and
// qualifiers (for example from samlsp's SessionWithSAMLNameID). opts can add
// SessionIndexes. The NameID is encrypted if EncryptLogoutNameID is set.
//
// The request is signed when Key is set, whether or not SignatureMethod is
// (with SHA-256 for the type of Key if it is not): the SOAP binding has no
// other way to show the IdP that the request comes from this service
// provider (saml-profiles §4.4.3.1). Without Key it is unsigned, and the
// service provider must authenticate some other way, such as with a TLS
// client certificate in HTTPClient.
func (sp *ServiceProvider) MakeSOAPLogoutRequest(nameID NameID, opts ...LogoutRequestOption) (*LogoutRequest, error) {
	if sp.IDPMetadata == nil {
		return nil, errors.New("cannot make a logout request: IDPMetadata is not set")
	}
	location := sp.GetSLOBindingLocation(SOAPBinding)
	if location == "" {
		return nil, ErrNoSOAPSingleLogoutService
	}
	if nameID.Value == "" {
		return nil, errors.New("cannot make a logout request: the NameID is empty")
	}

	req := sp.makeUnsignedLogoutRequest(location, nameID.Value)
	req.NameID = &nameID
	for _, opt := range opts {
		opt(req)
	}
	if sp.EncryptLogoutNameID {
		if err := sp.EncryptLogoutRequestNameID(req); err != nil {
			return nil, err
		}
	}
	if !signerutil.IsNil(sp.Key) {
		sigEl, err := sp.soapSignature(req.Element())
		if err != nil {
			return nil, err
		}
		req.Signature = sigEl
	}
	return req, nil
}

// SendSOAPLogoutRequest sends req, made by MakeSOAPLogoutRequest, to its
// Destination with the SAML SOAP binding, using HTTPClient (or
// http.DefaultClient) and ctx, and returns the IdP's LogoutResponse once
// ParseXMLSOAPLogoutResponse has validated it. The response body is limited
// to MaxSOAPLogoutMessageSize bytes.
//
// This is SP initiated single logout without the browser. It does not end
// any session at this service provider: do that whatever the outcome.
//
// Errors in sending the request are returned as they are; an invalid
// response, or one whose status is not Success, is returned as an
// *InvalidResponseError (which matches ErrBadStatus for a status other than
// Success). A Success with the second-level status PartialLogout is
// returned without error; check resp.Status if it matters.
func (sp *ServiceProvider) SendSOAPLogoutRequest(ctx context.Context, req *LogoutRequest) (*LogoutResponse, error) {
	if req == nil || req.Destination == "" {
		return nil, errors.New("cannot send a logout request without a Destination")
	}
	// The Destination is the IdP's SOAP SingleLogoutService from its
	// metadata (see MakeSOAPLogoutRequest), not from the request.
	body, err := sp.postSOAP(ctx, req.Destination, soapEnvelope(req.Element()), MaxSOAPLogoutMessageSize)
	if err != nil {
		return nil, fmt.Errorf("logout request to %s: %w", req.Destination, err)
	}
	return sp.ParseXMLSOAPLogoutResponse(body, req)
}

// ParseXMLSOAPLogoutResponse validates soapResponseXML, the SOAP envelope the
// IdP returned for req, and returns the LogoutResponse it holds. Use it to
// send req with your own transport; SendSOAPLogoutRequest calls it for you.
//
// The SOAP Body must hold exactly one samlp:LogoutResponse, which must:
//
//   - carry an enveloped XML signature by the IdP;
//   - be InResponseTo req.ID, and recently issued;
//   - have Issuer equal to the IdP entity ID;
//   - have no Destination, or SloURL or the entity ID of this service
//     provider (a SOAP response is not delivered to an endpoint of the
//     service provider, so Destination is optional);
//   - have a Success status, or else an error matching ErrBadStatus is
//     returned.
//
// If the function fails it returns an *InvalidResponseError whose
// PrivateErr says what was wrong.
func (sp *ServiceProvider) ParseXMLSOAPLogoutResponse(soapResponseXML []byte, req *LogoutRequest) (*LogoutResponse, error) {
	now := sp.now()
	resp, err := sp.parseSOAPLogoutResponse(soapResponseXML, req, now)
	if err != nil {
		return nil, &InvalidResponseError{
			PrivateErr: err,
			Response:   string(soapResponseXML),
			Now:        now,
		}
	}
	return resp, nil
}

func (sp *ServiceProvider) parseSOAPLogoutResponse(soapResponseXML []byte, req *LogoutRequest, now time.Time) (*LogoutResponse, error) {
	if req == nil || req.ID == "" {
		return nil, errors.New("the logout request has no ID")
	}
	if sp.IDPMetadata == nil {
		return nil, errors.New("IDPMetadata is not set")
	}
	responseEl, err := soapBodyElement(soapResponseXML, "LogoutResponse")
	if err != nil {
		return nil, classify(err, ErrMalformedMessage)
	}
	signedEl, err := sp.requireIDPSignature(responseEl)
	if err != nil {
		return nil, err
	}
	var resp LogoutResponse
	if err := unmarshalElement(signedEl, &resp); err != nil {
		return nil, err
	}
	if err := sp.validateSOAPLogoutResponse(&resp, req, now); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (sp *ServiceProvider) validateSOAPLogoutResponse(resp *LogoutResponse, req *LogoutRequest, now time.Time) error {
	if resp.InResponseTo != req.ID {
		return classify(fmt.Errorf("`InResponseTo` %q does not match the logout request ID %q", resp.InResponseTo, req.ID), ErrRequestIDMismatch)
	}
	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return classify(fmt.Errorf("issueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay)), ErrExpired)
	}
	if resp.IssueInstant.Add(-MaxClockSkew).After(now) {
		return classify(fmt.Errorf("issueInstant %s is in the future", resp.IssueInstant), ErrNotYetValid)
	}
	if resp.Issuer == nil || resp.Issuer.Value != sp.IDPMetadata.EntityID {
		return classify(fmt.Errorf("issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID), ErrIssuerMismatch)
	}
	switch resp.Destination {
	case "", sp.SloURL.String(), sp.entityID():
	default:
		return classify(fmt.Errorf("`Destination` %q is not this service provider", resp.Destination), ErrDestinationMismatch)
	}
	return statusError(resp.Status)
}
