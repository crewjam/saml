package samlsp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/crewjam/saml"
)

// ErrNoIssuer is returned by PeekIssuer when the request carries no SAML
// message, or one that does not name its issuer.
var ErrNoIssuer = errors.New("samlsp: no SAML message with an Issuer in the request")

const (
	samlProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	soapEnvelopeNamespace  = "http://schemas.xmlsoap.org/soap/envelope/"

	// peekInflateLimit caps a message inflated from the HTTP-Redirect
	// binding, as package saml does.
	peekInflateLimit = 1 << 20
)

// PeekIssuer returns the entity ID that names the issuer of the SAML
// message in r, without verifying the message. Use it only to choose the
// identity provider whose metadata will verify the message, when nothing
// of the SP's own, such as a RelayState it chose, says which IdP sent it:
// an unsolicited (IdP-initiated) Response at the ACS, or a LogoutRequest
// from an IdP at the single logout service. Then pass that IdP to the call
// that verifies the message (WithIdentityProvider, IdentityProviderContext).
//
// The result is chosen by whoever sent the request. A forged Issuer only
// chooses metadata that the message then fails to verify against, so it is
// safe for choosing an IdP, and for nothing else: never trust it before
// the message is verified. An SP that lets tenants register IdPs must not
// let two of them share an entity ID.
//
// It reads the message as package saml does: from the query string of a
// GET (HTTP-Redirect, deflated), from the form of a POST (HTTP-POST and
// HTTP-POST-SimpleSign), or from the body of a POST with Content-Type
// text/xml (SOAP), which it restores so that the message can then be
// verified. A message is a SAMLRequest or a SAMLResponse. Its Issuer is
// that of the message, or, for a Response that names none, that of its
// assertion. It returns an error matching ErrNoIssuer for a request that
// carries no message, carries an HTTP-Artifact (whose issuer is named only
// by a hash), or names no issuer, and another error for a message it
// cannot read.
func PeekIssuer(r *http.Request) (string, error) {
	data, err := peekMessage(r)
	if err != nil {
		return "", err
	}
	var msg peekedMessage
	if saml.IsSOAPRequest(r) {
		var env struct {
			XMLName xml.Name
			Body    struct {
				Message peekedMessage `xml:",any"`
			} `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
		}
		if err := xml.Unmarshal(data, &env); err != nil {
			return "", fmt.Errorf("samlsp: the SOAP message is not XML: %w", err)
		}
		if env.XMLName.Space != soapEnvelopeNamespace || env.XMLName.Local != "Envelope" {
			return "", errors.New("samlsp: the SOAP message is not a SOAP 1.1 Envelope")
		}
		msg = env.Body.Message
	} else if err := xml.Unmarshal(data, &msg); err != nil {
		return "", fmt.Errorf("samlsp: the SAML message is not XML: %w", err)
	}
	if msg.XMLName.Space != samlProtocolNamespace {
		return "", fmt.Errorf("samlsp: %s is not a SAML protocol message", msg.XMLName.Local)
	}
	issuer := strings.TrimSpace(msg.Issuer)
	if issuer == "" {
		issuer = strings.TrimSpace(msg.Assertion.Issuer)
	}
	if issuer == "" {
		return "", fmt.Errorf("%w: the %s names no issuer", ErrNoIssuer, msg.XMLName.Local)
	}
	return issuer, nil
}

// peekedMessage is what PeekIssuer reads of a SAML protocol message.
type peekedMessage struct {
	XMLName xml.Name
	Issuer  string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	// A Response's own Issuer is optional; its assertion's is not, unless
	// the assertion is encrypted.
	Assertion struct {
		Issuer string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// peekMessage returns the XML of the SAML message in r, decoded as its
// binding requires.
func peekMessage(r *http.Request) ([]byte, error) {
	if saml.IsSOAPRequest(r) {
		body, err := io.ReadAll(io.LimitReader(r.Body, saml.MaxSOAPLogoutMessageSize+1))
		if err != nil {
			return nil, fmt.Errorf("samlsp: cannot read the SOAP message: %w", err)
		}
		// Put the body back, so that the message can be verified.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		if int64(len(body)) > saml.MaxSOAPLogoutMessageSize {
			return nil, fmt.Errorf("samlsp: the SOAP message is larger than %d bytes", saml.MaxSOAPLogoutMessageSize)
		}
		return body, nil
	}

	var get func(string) string
	switch r.Method {
	case http.MethodGet:
		query := r.URL.Query()
		get = query.Get
	case http.MethodPost:
		get = r.PostFormValue
	default:
		return nil, ErrNoIssuer
	}
	request, response := get("SAMLRequest"), get("SAMLResponse")
	var encoded string
	switch {
	case request != "" && response != "":
		return nil, errors.New("samlsp: the request carries both a SAMLRequest and a SAMLResponse")
	case request != "":
		encoded = request
	case response != "":
		encoded = response
	case get("SAMLart") != "":
		return nil, fmt.Errorf("%w: an HTTP-Artifact message names its issuer only by a hash", ErrNoIssuer)
	default:
		return nil, ErrNoIssuer
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("samlsp: the SAML message is not base64: %w", err)
	}
	if r.Method != http.MethodGet {
		return data, nil
	}
	// HTTP-Redirect deflates the message (saml-bindings §3.4.4.1).
	inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(data)), peekInflateLimit+1))
	if err != nil {
		return nil, fmt.Errorf("samlsp: the SAML message is not deflated: %w", err)
	}
	if len(inflated) > peekInflateLimit {
		return nil, fmt.Errorf("samlsp: the SAML message inflates to more than %d bytes", peekInflateLimit)
	}
	return inflated, nil
}
