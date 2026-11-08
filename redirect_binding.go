package saml

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml/internal/xmlroundtrip"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// The query parameters defined by the SAML HTTP-Redirect binding
// (saml-bindings-2.0-os, section 3.4.4).
const (
	redirectParamSAMLRequest  = "SAMLRequest"
	redirectParamSAMLResponse = "SAMLResponse"
	redirectParamRelayState   = "RelayState"
	redirectParamSigAlg       = "SigAlg"
	redirectParamSignature    = "Signature"
)

// redirectSignatureAlgorithms maps the SigAlg URIs we accept on the
// HTTP-Redirect binding to the corresponding x509 signature algorithm. The
// set matches the signature methods GetSigningContext accepts for signing.
var redirectSignatureAlgorithms = map[string]x509.SignatureAlgorithm{
	dsig.RSASHA1SignatureMethod:     x509.SHA1WithRSA,
	dsig.RSASHA256SignatureMethod:   x509.SHA256WithRSA,
	dsig.RSASHA384SignatureMethod:   x509.SHA384WithRSA,
	dsig.RSASHA512SignatureMethod:   x509.SHA512WithRSA,
	dsig.ECDSASHA1SignatureMethod:   x509.ECDSAWithSHA1,
	dsig.ECDSASHA256SignatureMethod: x509.ECDSAWithSHA256,
	dsig.ECDSASHA384SignatureMethod: x509.ECDSAWithSHA384,
	dsig.ECDSASHA512SignatureMethod: x509.ECDSAWithSHA512,
}

// redirectBindingMessage is a SAML protocol message received via the
// HTTP-Redirect binding.
type redirectBindingMessage struct {
	// Message is the value of the SAMLRequest or SAMLResponse parameter
	// (base64 encoded, deflated XML) after URL decoding.
	Message string

	// SigAlg and Signature are the URL-decoded signature parameters. Both are
	// empty when the message carries no query string signature.
	SigAlg    string
	Signature string

	// RelayState is the URL-decoded RelayState parameter, and HasRelayState
	// reports whether the query carried one. They come from the same parse as
	// SignedContent, so the relay state that is echoed back is the one the
	// signature covers.
	RelayState    string
	HasRelayState bool

	// SignedContent is the octet string the signature covers. Per
	// saml-bindings-2.0-os section 3.4.4.1 it is built from the parameter
	// values exactly as they appeared in the URL, without re-encoding, so that
	// verification does not depend on how the sender chose to URL-encode them
	// (e.g. ADFS uses lower case percent escapes).
	SignedContent []byte
}

// parseRedirectBindingQuery parses rawQuery as an HTTP-Redirect binding
// message whose protocol message is carried in messageParam (SAMLRequest or
// SAMLResponse).
//
// The query is parsed exactly once and every value used later (the message
// that gets decoded and the content the signature is checked over) comes from
// that single parse. Any binding parameter that appears more than once, or a
// query that carries both SAMLRequest and SAMLResponse, is rejected so that
// the signed message and the processed message cannot diverge.
func parseRedirectBindingQuery(rawQuery, messageParam string) (*redirectBindingMessage, error) {
	rawValues := map[string]string{}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			return nil, fmt.Errorf("cannot parse query parameter name %q: %w", rawKey, err)
		}
		switch key {
		case redirectParamSAMLRequest, redirectParamSAMLResponse, redirectParamRelayState,
			redirectParamSigAlg, redirectParamSignature:
		default:
			continue
		}
		if _, seen := rawValues[key]; seen {
			return nil, fmt.Errorf("query parameter %s appears more than once", key)
		}
		rawValues[key] = rawValue
	}

	otherParam := redirectParamSAMLRequest
	if messageParam == redirectParamSAMLRequest {
		otherParam = redirectParamSAMLResponse
	}
	if _, ok := rawValues[otherParam]; ok {
		return nil, fmt.Errorf("query contains both %s and %s", redirectParamSAMLRequest, redirectParamSAMLResponse)
	}

	rawMessage, ok := rawValues[messageParam]
	if !ok {
		return nil, fmt.Errorf("query does not contain %s", messageParam)
	}

	decoded := map[string]string{}
	for key, rawValue := range rawValues {
		value, err := url.QueryUnescape(rawValue)
		if err != nil {
			return nil, fmt.Errorf("cannot parse query parameter %s: %w", key, err)
		}
		decoded[key] = value
	}

	rv := &redirectBindingMessage{
		Message:   decoded[messageParam],
		SigAlg:    decoded[redirectParamSigAlg],
		Signature: decoded[redirectParamSignature],
	}
	rv.RelayState, rv.HasRelayState = decoded[redirectParamRelayState]

	_, hasSigAlg := rawValues[redirectParamSigAlg]
	_, hasSignature := rawValues[redirectParamSignature]
	if hasSigAlg || hasSignature {
		if rv.SigAlg == "" || rv.Signature == "" {
			return nil, fmt.Errorf("query must contain both %s and %s, or neither", redirectParamSigAlg, redirectParamSignature)
		}
		signedContent := messageParam + "=" + rawMessage
		if rawRelayState, ok := rawValues[redirectParamRelayState]; ok {
			signedContent += "&" + redirectParamRelayState + "=" + rawRelayState
		}
		signedContent += "&" + redirectParamSigAlg + "=" + rawValues[redirectParamSigAlg]
		rv.SignedContent = []byte(signedContent)
	}

	return rv, nil
}

// redirectBindingCerts returns the IDP certificates that may have produced an
// HTTP-Redirect binding signature. It follows the same configuration rules as
// validateSignature, except that a fingerprint-only configuration cannot be
// used: that mode trusts the certificate embedded in the XML signature, and the
// redirect binding does not transmit one.
func (sp *ServiceProvider) redirectBindingCerts() ([]*x509.Certificate, error) {
	if sp.IDPMetadata == nil {
		return nil, errors.New("saml config not set up properly, specify either idp metadata url or actual certificate")
	}
	fingerprintSet := sp.IDPCertificateFingerprint != nil || sp.IDPCertificateFingerprintAlgorithm != nil
	switch {
	case !fingerprintSet && sp.IDPCertificate == nil:
		return sp.getIDPSigningCerts()
	case !fingerprintSet && sp.IDPCertificate != nil:
		cert, err := parseCert(*sp.IDPCertificate)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	case sp.IDPCertificate == nil:
		return nil, errors.New("IDP certificate fingerprints cannot be used to verify HTTP-Redirect binding signatures, specify either idp metadata url or actual certificate")
	default:
		return nil, errors.New("saml config not set up properly, specify either idp metadata url, fingerprints or actual certificate")
	}
}

// verifyRedirectBindingSignature checks the query string signature of an
// HTTP-Redirect binding message against the IDP's signing certificates.
func (sp *ServiceProvider) verifyRedirectBindingSignature(m *redirectBindingMessage) error {
	if err := checkSigAlgNotSHA1(sp.RejectSHA1Signatures, m.SigAlg); err != nil {
		return err
	}
	return checkRedirectBindingSignature(m, sp.redirectBindingCerts, sp.dsigClock().Now(), sp.IgnoreCertificateExpiry)
}

// checkRedirectBindingSignature checks the query string signature of an
// HTTP-Redirect binding message against the certificates returned by
// getCerts. Unless ignoreExpiry is set, a certificate is only used if it is
// valid at now.
func checkRedirectBindingSignature(m *redirectBindingMessage, getCerts func() ([]*x509.Certificate, error), now time.Time, ignoreExpiry bool) error {
	algorithm, signature, err := decodeDetachedSignature(m.SigAlg, m.Signature, base64.StdEncoding)
	if err != nil {
		return err
	}

	certs, err := getCerts()
	if err != nil {
		return fmt.Errorf("cannot validate signature: %w", err)
	}

	return checkDetachedSignature(algorithm, m.SignedContent, signature, certs, now, ignoreExpiry)
}

// decodeDetachedSignature maps the SigAlg value of a binding that carries a
// detached signature (HTTP-Redirect or HTTP-POST-SimpleSign) to an x509
// signature algorithm, and decodes the base64 Signature value with enc.
func decodeDetachedSignature(sigAlg, signature string, enc *base64.Encoding) (x509.SignatureAlgorithm, []byte, error) {
	algorithm, ok := redirectSignatureAlgorithms[sigAlg]
	if !ok {
		return x509.UnknownSignatureAlgorithm, nil, fmt.Errorf("unsupported signature algorithm %q", sigAlg)
	}

	sig, err := enc.DecodeString(signature)
	if err != nil {
		return x509.UnknownSignatureAlgorithm, nil, fmt.Errorf("cannot decode signature: %w", err)
	}
	return algorithm, sig, nil
}

// checkDetachedSignature returns nil if signature is a valid signature over
// signedContent, made with algorithm by the key of one of certs. Unless
// ignoreExpiry is set, a certificate is only accepted at a time (now) within
// its validity period.
func checkDetachedSignature(algorithm x509.SignatureAlgorithm, signedContent, signature []byte, certs []*x509.Certificate, now time.Time, ignoreExpiry bool) error {
	var lastErr error
	for _, cert := range certs {
		if !ignoreExpiry && (now.Before(cert.NotBefore) || now.After(cert.NotAfter)) {
			lastErr = errors.New("certificate is not valid at this time")
			continue
		}
		// CheckSignature also rejects a SigAlg whose key type does not match
		// the certificate's key (e.g. ecdsa-sha256 with an RSA certificate).
		if err := cert.CheckSignature(algorithm, signedContent, signature); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no certificates")
	}
	return fmt.Errorf("cannot validate signature: %w", lastErr)
}

// signDetached signs content with signingContext and returns the base64
// encoded signature, the value of the Signature parameter of the
// HTTP-Redirect and HTTP-POST-SimpleSign bindings.
func signDetached(signingContext *dsig.SigningContext, content string) (string, error) {
	sig, err := signingContext.SignString(content)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// readRedirectBindingMessage decodes the HTTP-Redirect binding message carried
// in messageParam of rawQuery and authenticates it, returning the root element
// of the protocol message.
//
// A message that carries SigAlg and Signature query parameters must have a
// valid query string signature. A message without them must carry a valid
// enveloped XML signature instead. Unsigned messages are always rejected.
//
// Errors are reported through retErr, mirroring the other Validate* methods.
func (sp *ServiceProvider) readRedirectBindingMessage(rawQuery, messageParam string, retErr *InvalidResponseError) (*etree.Element, error) {
	m, err := parseRedirectBindingQuery(rawQuery, messageParam)
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	rawBuf, err := base64.StdEncoding.DecodeString(m.Message)
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("unable to parse base64: %s", err)
		return nil, retErr
	}
	retErr.Response = string(rawBuf)

	inflated, err := io.ReadAll(newSaferFlateReader(bytes.NewBuffer(rawBuf)))
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	if err := xmlroundtrip.Validate(inflated); err != nil {
		retErr.PrivateErr = classify(fmt.Errorf("invalid xml: %w", err), ErrMalformedMessage)
		return nil, retErr
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(inflated); err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}
	if doc.Root() == nil {
		retErr.PrivateErr = errors.New("invalid xml: no root")
		return nil, retErr
	}

	root := doc.Root()
	if m.SignedContent != nil {
		err = sp.verifyRedirectBindingSignature(m)
	} else {
		// Read the message from what the enveloped signature covers.
		root, err = sp.validatedElement(root)
	}
	if err != nil {
		retErr.PrivateErr = err
		return nil, retErr
	}

	return root, nil
}

// deflateAndEncode serializes el, deflates it and base64 encodes the result,
// as the HTTP-Redirect binding requires.
func deflateAndEncode(el *etree.Element) (string, error) {
	var rv strings.Builder
	base64Writer := base64.NewEncoder(base64.StdEncoding, &rv)
	compressedWriter, err := flate.NewWriter(base64Writer, 9)
	if err != nil {
		return "", err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	if _, err := doc.WriteTo(compressedWriter); err != nil {
		return "", err
	}
	if err := compressedWriter.Close(); err != nil {
		return "", err
	}
	if err := base64Writer.Close(); err != nil {
		return "", err
	}
	return rv.String(), nil
}

// MaxRelayStateLength is the longest RelayState, in bytes, that a SAML
// message may carry with the HTTP-Redirect, HTTP-POST and
// HTTP-POST-SimpleSign bindings: "The value MUST NOT exceed 80 bytes in
// length" (saml-bindings-2.0-os §3.4.3 and §3.5.3).
const MaxRelayStateLength = 80

// checkRelayState refuses a RelayState longer than MaxRelayStateLength if
// limit is set (see ServiceProvider.LimitRelayStateLength and
// IdentityProvider.LimitRelayStateLength). It is checked where this package
// starts an exchange (AuthnRequests, LogoutRequests and IdP-initiated
// Responses), not where it echoes the RelayState of a message it answers,
// which must be returned unchanged.
func checkRelayState(limit bool, relayState string) error {
	if limit && len(relayState) > MaxRelayStateLength {
		return fmt.Errorf("RelayState is %d bytes, longer than the %d the SAML bindings allow: %w", len(relayState), MaxRelayStateLength, ErrRelayStateTooLong)
	}
	return nil
}

// redirectBindingURL returns destination with the HTTP-Redirect binding
// parameters for encodedMessage appended. If signatureMethod is set the
// query is signed with it as described in saml-bindings-2.0-os section
// 3.4.4.1. The
// signature covers only the SAML parameters, not any query parameters already
// present in destination.
func (sp *ServiceProvider) redirectBindingURL(destination, messageParam, encodedMessage, relayState, signatureMethod string) (*url.URL, error) {
	if signatureMethod == "" {
		return signedRedirectBindingURL(destination, messageParam, encodedMessage, relayState, "", nil)
	}
	signingContext, err := sp.signingContext(signatureMethod)
	if err != nil {
		return nil, err
	}
	return signedRedirectBindingURL(destination, messageParam, encodedMessage, relayState, signatureMethod, signingContext)
}

// signedRedirectBindingURL returns destination with the HTTP-Redirect binding
// parameters for encodedMessage appended. If signingContext is not nil, the
// query is signed with it and sigAlg is sent as the SigAlg parameter, as
// described in saml-bindings-2.0-os section 3.4.4.1.
func signedRedirectBindingURL(destination, messageParam, encodedMessage, relayState, sigAlg string, signingContext *dsig.SigningContext) (*url.URL, error) {
	rv, err := url.Parse(destination)
	if err != nil {
		return nil, err
	}

	// The parameters are built by hand because their order matters for the
	// signature, which url.Values.Encode does not preserve.
	query := messageParam + "=" + url.QueryEscape(encodedMessage)
	if relayState != "" {
		query += "&" + redirectParamRelayState + "=" + url.QueryEscape(relayState)
	}
	if signingContext != nil {
		query += "&" + redirectParamSigAlg + "=" + url.QueryEscape(sigAlg)
		sig, err := signDetached(signingContext, query)
		if err != nil {
			return nil, err
		}
		query += "&" + redirectParamSignature + "=" + url.QueryEscape(sig)
	}

	if rv.RawQuery != "" {
		rv.RawQuery += "&" + query
	} else {
		rv.RawQuery = query
	}
	return rv, nil
}

// RedirectBindingURL returns the URL that sends el to destination with the
// HTTP-Redirect binding, as the query parameter messageParam
// ("SAMLRequest" or "SAMLResponse"), with relayState. It works for any
// protocol message, as RedirectLogoutRequestURL does for a LogoutRequest.
//
// Any Signature child of el is left out of the message. If signatureMethod
// is not empty, the URL carries a query string signature made with it and
// Key (saml-bindings-2.0-os section 3.4.4.1). The length of relayState is
// not checked.
func (sp *ServiceProvider) RedirectBindingURL(destination, messageParam string, el *etree.Element, relayState, signatureMethod string) (*url.URL, error) {
	encoded, err := deflateAndEncode(withoutSignature(el))
	if err != nil {
		return nil, err
	}
	return sp.redirectBindingURL(destination, messageParam, encoded, relayState, signatureMethod)
}

// RedirectBindingURL returns the URL that sends el, a protocol message of
// the IdP, to destination with the HTTP-Redirect binding, as the query
// parameter messageParam ("SAMLRequest" or "SAMLResponse"), with
// relayState, and a query string signature made with the IdP's key and
// SignatureMethod (saml-bindings-2.0-os section 3.4.4.1). Any Signature
// child of el is left out of the message. The length of relayState is not
// checked.
func (idp *IdentityProvider) RedirectBindingURL(destination, messageParam string, el *etree.Element, relayState string) (*url.URL, error) {
	encoded, err := deflateAndEncode(withoutSignature(el))
	if err != nil {
		return nil, err
	}
	signingContext, err := idp.signingContext()
	if err != nil {
		return nil, err
	}
	sigAlg := signingContext.GetSignatureMethodIdentifier()
	if sigAlg == "" {
		return nil, errors.New("cannot determine the signature algorithm")
	}
	return signedRedirectBindingURL(destination, messageParam, encoded, relayState, sigAlg, signingContext)
}

// withoutSignature returns a copy of el without its Signature children.
func withoutSignature(el *etree.Element) *etree.Element {
	unsigned := el.Copy()
	for _, child := range unsigned.ChildElements() {
		if child.Tag == "Signature" {
			unsigned.RemoveChild(child)
		}
	}
	return unsigned
}
