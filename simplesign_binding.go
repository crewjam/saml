package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// The HTTP-POST-SimpleSign binding (sstc-saml-binding-simplesign-cs-01)
// carries a protocol message in an HTML form like HTTP-POST
// (saml-bindings-2.0-os section 3.5): SAMLRequest or SAMLResponse holds the
// base64 encoded XML (not deflated) and RelayState the relay state. Instead
// of, or in addition to, an enveloped XML signature, the message may be
// signed with a detached signature carried in the SigAlg and Signature form
// controls (section 2.4). An optional KeyInfo control carries a base64
// encoded <ds:KeyInfo> element describing the signer's key.
//
// The signature covers the octet string (section 2.5)
//
//	SAMLRequest=<xml>&RelayState=<relay state>&SigAlg=<sigalg>
//
// or the same with SAMLResponse, where <xml> is the raw XML of the message
// (the base64 decoded form value, NOT the base64 text), and none of the
// values are URL encoded. The RelayState part is left out when the message
// has no relay state.
const simpleSignParamKeyInfo = "KeyInfo"

// simpleSignParams are the form controls the HTTP-POST-SimpleSign binding
// defines. Each may appear at most once in a SimpleSign message.
var simpleSignParams = []string{
	redirectParamSAMLRequest,
	redirectParamSAMLResponse,
	redirectParamRelayState,
	redirectParamSigAlg,
	redirectParamSignature,
	simpleSignParamKeyInfo,
}

// simpleSignBase64 decodes the base64 form values of a SimpleSign message.
// Line breaks are ignored, since the binding allows the message to be line
// wrapped, but non-canonical encodings are rejected.
var simpleSignBase64 = base64.StdEncoding.Strict()

// simpleSignMessage is a protocol message received with the
// HTTP-POST-SimpleSign binding.
type simpleSignMessage struct {
	// MessageParam is SAMLRequest or SAMLResponse.
	MessageParam string

	// XML is the protocol message, base64 decoded.
	XML []byte

	// RelayState is the RelayState form value. HasRelayState reports whether
	// the form carried a RelayState control at all, even an empty one; if so
	// it is part of the signed content.
	RelayState    string
	HasRelayState bool

	SigAlg    string
	Signature string

	// KeyInfo is the base64 encoded KeyInfo form value, or empty.
	KeyInfo string
}

// simpleSignSignedContent returns the octet string an HTTP-POST-SimpleSign
// signature covers (sstc-saml-binding-simplesign-cs-01 section 2.5).
// message is the raw XML of the protocol message. The relay state is
// included only if hasRelayState is set.
func simpleSignSignedContent(messageParam string, message []byte, relayState string, hasRelayState bool, sigAlg string) []byte {
	var b bytes.Buffer
	b.WriteString(messageParam)
	b.WriteByte('=')
	b.Write(message)
	if hasRelayState {
		b.WriteString("&" + redirectParamRelayState + "=")
		b.WriteString(relayState)
	}
	b.WriteString("&" + redirectParamSigAlg + "=")
	b.WriteString(sigAlg)
	return b.Bytes()
}

// signedContent returns the octet string m's signature covers.
func (m *simpleSignMessage) signedContent() []byte {
	return simpleSignSignedContent(m.MessageParam, m.XML, m.RelayState, m.HasRelayState, m.SigAlg)
}

// isSimpleSignRequest reports whether the posted form of req carries a
// SigAlg or Signature control, which marks it as an HTTP-POST-SimpleSign
// message (sstc-saml-binding-simplesign-cs-01 section 2.10). req.ParseForm
// must have been called.
func isSimpleSignRequest(req *http.Request) bool {
	_, hasSigAlg := req.PostForm[redirectParamSigAlg]
	_, hasSignature := req.PostForm[redirectParamSignature]
	return hasSigAlg || hasSignature
}

// parseSimpleSignRequest reads the HTTP-POST-SimpleSign message carried in
// messageParam (SAMLRequest or SAMLResponse) of the posted form of req. It
// returns nil and no error if the form carries neither SigAlg nor Signature,
// which means the message is a plain HTTP-POST binding message.
// req.ParseForm must have been called.
//
// Every binding control may appear at most once and only in the request
// body, never in the URL query, and a form carrying both SAMLRequest and
// SAMLResponse is rejected, so that the message that is verified and the
// message that is processed cannot diverge. Both SigAlg and Signature must
// be present and non-empty. The signature itself is not checked.
func parseSimpleSignRequest(req *http.Request, messageParam string) (*simpleSignMessage, error) {
	if !isSimpleSignRequest(req) {
		return nil, nil
	}
	form := req.PostForm

	query := req.URL.Query()
	for _, param := range simpleSignParams {
		if len(form[param]) > 1 {
			return nil, fmt.Errorf("form field %s appears more than once", param)
		}
		if _, ok := query[param]; ok {
			return nil, fmt.Errorf("HTTP-POST-SimpleSign message must not carry %s in the URL query", param)
		}
	}

	otherParam := redirectParamSAMLRequest
	if messageParam == redirectParamSAMLRequest {
		otherParam = redirectParamSAMLResponse
	}
	if _, ok := form[otherParam]; ok {
		return nil, fmt.Errorf("form contains both %s and %s", redirectParamSAMLRequest, redirectParamSAMLResponse)
	}
	if _, ok := form[messageParam]; !ok {
		return nil, fmt.Errorf("form does not contain %s", messageParam)
	}

	m := &simpleSignMessage{
		MessageParam: messageParam,
		SigAlg:       form.Get(redirectParamSigAlg),
		Signature:    form.Get(redirectParamSignature),
		KeyInfo:      form.Get(simpleSignParamKeyInfo),
	}
	if m.SigAlg == "" || m.Signature == "" {
		return nil, fmt.Errorf("form must contain both %s and %s, or neither", redirectParamSigAlg, redirectParamSignature)
	}
	_, m.HasRelayState = form[redirectParamRelayState]
	m.RelayState = form.Get(redirectParamRelayState)

	var err error
	m.XML, err = simpleSignBase64.DecodeString(form.Get(messageParam))
	if err != nil {
		return nil, fmt.Errorf("cannot decode %s: %w", messageParam, err)
	}
	if len(m.XML) == 0 {
		return nil, fmt.Errorf("%s is empty", messageParam)
	}
	return m, nil
}

// verifySimpleSignSignature checks the SimpleSign signature of m against the
// IDP's signing certificates, chosen as for HTTP-Redirect binding signatures
// (see redirectBindingCerts). With a fingerprint-only configuration the
// certificate is taken from the KeyInfo form control and must match the
// configured fingerprint, as for XML signatures. Otherwise the KeyInfo
// control is ignored: the signature is only ever checked against trusted
// certificates.
func (sp *ServiceProvider) verifySimpleSignSignature(m *simpleSignMessage) error {
	if err := checkSigAlgNotSHA1(sp.RejectSHA1Signatures, m.SigAlg); err != nil {
		return err
	}
	algorithm, signature, err := decodeDetachedSignature(m.SigAlg, m.Signature, simpleSignBase64)
	if err != nil {
		return err
	}

	certs, err := sp.simpleSignCerts(m)
	if err != nil {
		return fmt.Errorf("cannot validate signature: %w", err)
	}

	return checkDetachedSignature(algorithm, m.signedContent(), signature, certs, sp.dsigClock().Now(), sp.IgnoreCertificateExpiry)
}

// simpleSignCerts returns the IDP certificates that may have produced the
// SimpleSign signature of m.
func (sp *ServiceProvider) simpleSignCerts(m *simpleSignMessage) ([]*x509.Certificate, error) {
	if sp.IDPMetadata != nil && sp.IDPCertificate == nil &&
		sp.IDPCertificateFingerprint != nil && sp.IDPCertificateFingerprintAlgorithm != nil {
		return sp.simpleSignCertByFingerprint(m)
	}
	return sp.redirectBindingCerts()
}

// simpleSignCertByFingerprint returns the certificate in the KeyInfo form
// control of m if its fingerprint matches IDPCertificateFingerprint.
func (sp *ServiceProvider) simpleSignCertByFingerprint(m *simpleSignMessage) ([]*x509.Certificate, error) {
	if m.KeyInfo == "" {
		return nil, errors.New("IDP certificate fingerprints can only verify HTTP-POST-SimpleSign signatures that carry a KeyInfo")
	}
	keyInfoXML, err := simpleSignBase64.DecodeString(m.KeyInfo)
	if err != nil {
		return nil, fmt.Errorf("cannot decode KeyInfo: %w", err)
	}
	if err := xmlroundtrip.Validate(keyInfoXML); err != nil {
		return nil, fmt.Errorf("KeyInfo contains invalid XML: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(keyInfoXML); err != nil {
		return nil, fmt.Errorf("cannot parse KeyInfo: %w", err)
	}
	keyInfo := doc.Root()
	if keyInfo == nil || keyInfo.Tag != "KeyInfo" || keyInfo.NamespaceURI() != dsig.Namespace {
		return nil, errors.New("KeyInfo form field does not contain a ds:KeyInfo element")
	}

	// getCertBasedOnFingerprint looks for ./Signature/KeyInfo, as found in
	// an XML signature, so wrap the KeyInfo element accordingly.
	wrapper := etree.NewElement(m.MessageParam)
	wrapper.CreateElement("Signature").AddChild(keyInfo)
	return sp.getCertBasedOnFingerprint(wrapper)
}

// readSimpleSignMessage authenticates the SimpleSign message m and returns
// the root element of its protocol message. The SimpleSign signature is
// checked before the XML is parsed. If the root element also carries an
// enveloped XML signature, that signature must be valid as well.
//
// Errors are reported through retErr, mirroring the other Validate* methods.
func (sp *ServiceProvider) readSimpleSignMessage(m *simpleSignMessage, retErr *InvalidResponseError) (*etree.Element, error) {
	retErr.Response = string(m.XML)
	if err := sp.verifySimpleSignSignature(m); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	if err := xmlroundtrip.Validate(m.XML); err != nil {
		retErr.PrivateErr = fmt.Errorf("invalid xml: %w", err)
		return nil, retErr
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(m.XML); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = errors.New("invalid xml: no root")
		return nil, retErr
	}

	signed, err := sp.validatedElement(doc.Root())
	switch {
	case err == nil:
		// Read the message from what the enveloped signature covers.
		return signed, nil
	case errors.Is(err, errSignatureElementNotPresent):
		return doc.Root(), nil
	default:
		retErr.PrivateErr = err
		return nil, retErr
	}
}

// The auto-submitting forms for the HTTP-POST-SimpleSign binding. Their
// <script> elements are identical to those of the HTTP-POST forms made by
// AuthnRequest.PostWithNonce and LogoutResponse.PostWithNonce, so that a
// Content-Security-Policy that allows those scripts by hash allows these too.
// RelayState is only included when it is not empty, because a RelayState
// control, even an empty one, is part of the signed content.
var (
	simpleSignRequestFormTemplate = template.Must(template.New("saml-simplesign-request-form").Parse(`` +
		`<form method="post" action="{{.URL}}" id="SAMLRequestForm">` +
		`<input type="hidden" name="SAMLRequest" value="{{.Message}}" />` +
		`{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}` +
		`<input type="hidden" name="SigAlg" value="{{.SigAlg}}" />` +
		`<input type="hidden" name="Signature" value="{{.Signature}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script{{with .Nonce}} nonce="{{.}}"{{end}}>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLRequestForm').submit();</script>`))

	simpleSignResponseFormTemplate = template.Must(template.New("saml-simplesign-response-form").Parse(`` +
		`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
		`<input type="hidden" name="SAMLResponse" value="{{.Message}}" />` +
		`{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}" />{{end}}` +
		`<input type="hidden" name="SigAlg" value="{{.SigAlg}}" />` +
		`<input type="hidden" name="Signature" value="{{.Signature}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script{{with .Nonce}} nonce="{{.}}"{{end}}>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLResponseForm').submit();</script>`))
)

// simpleSignFormData is the data for the SimpleSign form templates.
type simpleSignFormData struct {
	URL        string
	Message    string
	RelayState string
	SigAlg     string
	Signature  string
	Nonce      string
}

// signSimpleSign signs message (the raw XML of a protocol message sent in
// messageParam) and relayState with signingContext for the
// HTTP-POST-SimpleSign binding. It returns the SigAlg and Signature values.
func signSimpleSign(signingContext *dsig.SigningContext, messageParam string, message []byte, relayState string) (sigAlg, signature string, err error) {
	sigAlg = signingContext.GetSignatureMethodIdentifier()
	if sigAlg == "" {
		return "", "", errors.New("cannot determine the signature algorithm")
	}
	content := simpleSignSignedContent(messageParam, message, relayState, relayState != "", sigAlg)
	signature, err = signDetached(signingContext, string(content))
	if err != nil {
		return "", "", err
	}
	return sigAlg, signature, nil
}

// simpleSignSigningContext returns the signing context the service provider
// uses for the HTTP-POST-SimpleSign binding, which requires signing, with
// signatureMethod.
func (sp *ServiceProvider) simpleSignSigningContext(signatureMethod string) (*dsig.SigningContext, error) {
	if signatureMethod == "" {
		return nil, errors.New("the HTTP-POST-SimpleSign binding requires ServiceProvider.SignatureMethod to be set")
	}
	return sp.signingContext(signatureMethod)
}

// simpleSignForm returns an auto-submitting HTML form that sends el to
// destination with the HTTP-POST-SimpleSign binding, in the messageParam
// (SAMLRequest or SAMLResponse) control, signed with the SP's key and
// SignatureMethod. el is sent as is: an XML signature it carries is kept,
// but none is added.
func (sp *ServiceProvider) simpleSignForm(destination, messageParam string, el *etree.Element, relayState, nonce, signatureMethod string) ([]byte, error) {
	if err := sp.validateIDPMetadata(); err != nil {
		return nil, err
	}
	signingContext, err := sp.simpleSignSigningContext(signatureMethod)
	if err != nil {
		return nil, err
	}

	doc := etree.NewDocument()
	doc.SetRoot(el)
	message, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	sigAlg, signature, err := signSimpleSign(signingContext, messageParam, message, relayState)
	if err != nil {
		return nil, err
	}

	tmpl := simpleSignRequestFormTemplate
	if messageParam == redirectParamSAMLResponse {
		tmpl = simpleSignResponseFormTemplate
	}
	var rv bytes.Buffer
	if err := tmpl.Execute(&rv, simpleSignFormData{
		URL:        destination,
		Message:    base64.StdEncoding.EncodeToString(message),
		RelayState: relayState,
		SigAlg:     sigAlg,
		Signature:  signature,
		Nonce:      nonce,
	}); err != nil {
		return nil, err
	}
	return rv.Bytes(), nil
}

// MakeSimpleSignAuthenticationRequest creates a SAML authentication request
// for the IDP's HTTP-POST-SimpleSign single sign-on endpoint. It returns an
// auto-submitting HTML form that sends the request to the IDP.
//
// The request carries no XML signature; it is signed with a SimpleSign
// signature (sstc-saml-binding-simplesign-cs-01 section 2.5) made with Key
// and SignatureMethod, which must be set. The response is requested with
// the HTTP-POST binding, as for MakePostAuthenticationRequest; use
// MakeAuthenticationRequest and AuthnRequest.SimpleSign to request another.
func (sp *ServiceProvider) MakeSimpleSignAuthenticationRequest(relayState string) ([]byte, error) {
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(HTTPPostSimpleSignBinding), HTTPPostSimpleSignBinding, HTTPPostBinding)
	if err != nil {
		return nil, err
	}
	return req.SimpleSign(relayState, sp)
}

// SimpleSign returns an auto-submitting HTML form that sends the request to
// its Destination with the HTTP-POST-SimpleSign binding, signed with sp's
// Key and SignatureMethod, which must be set. An XML signature the request
// already carries is kept.
func (r *AuthnRequest) SimpleSign(relayState string, sp *ServiceProvider) ([]byte, error) {
	return r.SimpleSignWithNonce(relayState, "", sp)
}

// SimpleSignWithNonce is like SimpleSign, but if nonce is not empty it is
// set as the nonce attribute of the form's auto-submit <script> element, as
// PostWithNonce does.
func (r *AuthnRequest) SimpleSignWithNonce(relayState, nonce string, sp *ServiceProvider) ([]byte, error) {
	if err := checkRelayState(sp.LimitRelayStateLength, relayState); err != nil {
		return nil, err
	}
	return sp.simpleSignForm(r.Destination, redirectParamSAMLRequest, r.Element(), relayState, nonce, sp.SignatureMethod)
}

// MakeSimpleSignLogoutRequest creates a SAML LogoutRequest for the IDP's
// HTTP-POST-SimpleSign single logout endpoint. It returns an
// auto-submitting HTML form that sends the request to the IDP, signed with
// a SimpleSign signature made with Key and SignatureMethod, which must be
// set. The request carries no XML signature.
func (sp *ServiceProvider) MakeSimpleSignLogoutRequest(nameID, relayState string, opts ...LogoutRequestOption) ([]byte, error) {
	req, err := sp.makeLogoutRequest(sp.GetSLOBindingLocation(HTTPPostSimpleSignBinding), nameID, opts...)
	if err != nil {
		return nil, err
	}
	return req.SimpleSign(relayState, sp)
}

// SimpleSign returns an auto-submitting HTML form that sends the request to
// its Destination with the HTTP-POST-SimpleSign binding, signed with sp's
// Key and SignatureMethod, which must be set. An XML signature the request
// already carries is kept.
func (r *LogoutRequest) SimpleSign(relayState string, sp *ServiceProvider) ([]byte, error) {
	return r.SimpleSignWithNonce(relayState, "", sp)
}

// SimpleSignWithNonce is like SimpleSign, but if nonce is not empty it is
// set as the nonce attribute of the form's auto-submit <script> element.
func (r *LogoutRequest) SimpleSignWithNonce(relayState, nonce string, sp *ServiceProvider) ([]byte, error) {
	if err := checkRelayState(sp.LimitRelayStateLength, relayState); err != nil {
		return nil, err
	}
	return sp.simpleSignForm(r.Destination, redirectParamSAMLRequest, r.Element(), relayState, nonce, sp.logoutSignatureMethod())
}

// MakeSimpleSignLogoutResponse creates a SAML LogoutResponse for the IDP's
// HTTP-POST-SimpleSign single logout endpoint. It returns an
// auto-submitting HTML form that sends the response to the IDP, signed with
// a SimpleSign signature made with Key and SignatureMethod, which must be
// set. The response carries no XML signature.
func (sp *ServiceProvider) MakeSimpleSignLogoutResponse(logoutRequestID, relayState string) ([]byte, error) {
	return sp.MakeSimpleSignLogoutResponseWithStatus(logoutRequestID, relayState, successStatus())
}

// MakeSimpleSignLogoutResponseWithStatus is like
// MakeSimpleSignLogoutResponse, but the response carries status instead of
// Success (see MakeLogoutResponseWithStatus). The SimpleSign signature
// covers the status.
func (sp *ServiceProvider) MakeSimpleSignLogoutResponseWithStatus(logoutRequestID, relayState string, status Status) ([]byte, error) {
	resp := sp.makeUnsignedLogoutResponse(sp.GetSLOBindingLocation(HTTPPostSimpleSignBinding), logoutRequestID)
	resp.Status = status
	return resp.SimpleSign(relayState, sp)
}

// SimpleSign returns an auto-submitting HTML form that sends the response to
// its Destination with the HTTP-POST-SimpleSign binding, signed with sp's
// Key and SignatureMethod, which must be set. An XML signature the response
// already carries is kept.
func (r *LogoutResponse) SimpleSign(relayState string, sp *ServiceProvider) ([]byte, error) {
	return r.SimpleSignWithNonce(relayState, "", sp)
}

// SimpleSignWithNonce is like SimpleSign, but if nonce is not empty it is
// set as the nonce attribute of the form's auto-submit <script> element.
func (r *LogoutResponse) SimpleSignWithNonce(relayState, nonce string, sp *ServiceProvider) ([]byte, error) {
	return sp.simpleSignForm(r.Destination, redirectParamSAMLResponse, r.Element(), relayState, nonce, sp.logoutSignatureMethod())
}

// SimpleSignValues returns the form fields that send el with the
// HTTP-POST-SimpleSign binding: messageParam ("SAMLRequest" or
// "SAMLResponse") holding el, RelayState if relayState is not empty, and
// the SigAlg and Signature of the SimpleSign signature made with
// signatureMethod and Key (sstc-saml-binding-simplesign-cs-01 section
// 2.10). Any Signature child of el is left out, since the SimpleSign
// signature replaces it. It works for any protocol message; post the
// fields from the browser to the message's Destination.
func (sp *ServiceProvider) SimpleSignValues(messageParam string, el *etree.Element, relayState, signatureMethod string) (url.Values, error) {
	signingContext, err := sp.simpleSignSigningContext(signatureMethod)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(withoutSignature(el))
	message, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	sigAlg, signature, err := signSimpleSign(signingContext, messageParam, message, relayState)
	if err != nil {
		return nil, err
	}
	values := url.Values{
		messageParam: {base64.StdEncoding.EncodeToString(message)},
		"SigAlg":     {sigAlg},
		"Signature":  {signature},
	}
	if relayState != "" {
		values.Set("RelayState", relayState)
	}
	return values, nil
}
