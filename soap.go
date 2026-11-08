package saml

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml/internal/xmlroundtrip"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/pkg/safehttp"
)

// This file holds what the requester and the responder sides of the SAML
// SOAP binding (saml-bindings §3.2) share: building and reading SOAP 1.1
// envelopes, and sending a SAML request in one.

// MaxSOAPLogoutMessageSize is the largest SOAP message body, in bytes, that
// is read for single logout over the SOAP binding: a LogoutRequest an
// IdentityProvider or a ServiceProvider receives, and the LogoutResponse
// either of them receives to its own LogoutRequest. A larger body is
// rejected without being parsed. Logout messages are small, so the default
// is far above what a legitimate message needs.
var MaxSOAPLogoutMessageSize int64 = 1 << 20

// defaultSOAPTimeout is how long the default HTTP client of an
// IdentityProvider waits for a SOAP exchange with a service provider.
const defaultSOAPTimeout = 10 * time.Second

// defaultSOAPHTTPClient is the HTTP client an IdentityProvider or a
// ServiceProvider sends SOAP messages with when its HTTPClient is nil. It
// gives up after defaultSOAPTimeout, so that an unresponsive peer does not
// hold up a logout, and does not follow redirects: the SOAP binding has
// none, and the message must only go to the endpoint in the metadata. It
// connects only to public addresses, since the endpoint is whatever the
// peer's metadata says (see package pkg/safehttp).
var defaultSOAPHTTPClient = safehttp.Client(defaultSOAPTimeout, refuseSOAPRedirect)

// soapHTTPClient returns the HTTP client to send a SOAP message with:
// defaultSOAPHTTPClient when client is nil, and otherwise a copy of client
// that follows no redirect, whatever the redirect policy of client.
//
// The SAML SOAP binding has no redirects: the message goes to the endpoint
// in the peer's metadata, and nowhere else (saml-bindings §3.2). Following
// a 307 or 308 would re-send the message, with the NameID, attributes or
// assertion it carries, to a location the metadata never named, possibly in
// the clear, and present the TLS client certificate of client there too.
func soapHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		return defaultSOAPHTTPClient
	}
	c := *client
	c.CheckRedirect = refuseSOAPRedirect
	return &c
}

// errSOAPRedirect is the error of a SOAP exchange whose endpoint answered
// with a redirect, which is never followed (see soapHTTPClient).
var errSOAPRedirect = errors.New("the SOAP endpoint answered with a redirect, which the SOAP binding does not allow")

// refuseSOAPRedirect is the CheckRedirect of every client soapHTTPClient
// returns.
func refuseSOAPRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("%w (to %s)", errSOAPRedirect, req.URL.Redacted())
}

// ErrInsecureSOAPEndpoint is returned when a SAML SOAP message would be sent
// to an endpoint whose Location is not an https URL. SOAP messages go
// server to server and carry the user's NameID, attributes or a whole
// assertion. The SOAP binding itself does nothing against an eavesdropper,
// or against someone who changes the messages in transit: saml-bindings
// §3.1.2 leaves confidentiality and integrity to the environment of use,
// typically TLS in the substrate protocol (and §3.6.5.2 does the same for
// the artifact resolution exchange). IdentityProvider and ServiceProvider
// choose TLS by default, and refuse http endpoints for the SOAP binding
// unless AllowInsecureSOAPEndpoints is set.
var ErrInsecureSOAPEndpoint = errors.New("the SOAP endpoint is not an https URL")

// checkSOAPEndpoint returns an error matching ErrInsecureSOAPEndpoint unless
// location is an https URL, or allowInsecure is set and it is an http URL.
func checkSOAPEndpoint(location string, allowInsecure bool) error {
	locationURL, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("invalid SOAP endpoint %q: %w", location, err)
	}
	switch {
	case locationURL.Scheme == "https":
		return nil
	case locationURL.Scheme == "http" && allowInsecure:
		return nil
	}
	return fmt.Errorf("%w: %q (set AllowInsecureSOAPEndpoints to allow plain http)", ErrInsecureSOAPEndpoint, location)
}

// soapContentType is the Content-Type of a SOAP 1.1 message (SOAP 1.1 §6.1.1).
const soapContentType = "text/xml; charset=utf-8"

// soapEnvelope returns a SOAP 1.1 Envelope whose Body holds el.
func soapEnvelope(el *etree.Element) *etree.Element {
	envelope := etree.NewElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", soapEnvelopeNamespace)
	body := etree.NewElement("soapenv:Body")
	envelope.AddChild(body)
	body.AddChild(el)
	return envelope
}

// setNoCacheHeaders sets the headers the SAML bindings ask of every HTTP
// message that carries a SAML message or artifact, so that neither the
// browser nor a proxy keeps a copy: "Include a Cache-Control header field
// set to "no-cache, no-store". Include a Pragma header field set to
// "no-cache"." (saml-bindings-2.0-os §3.2.3.2, §3.2.3.3, §3.4.5.1, §3.5.5.1
// and §3.6.5.1).
func setNoCacheHeaders(h http.Header) {
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("Pragma", "no-cache")
}

// postSOAPMessage sends envelope to location with the SAML SOAP binding,
// using httpClient and ctx, and returns the body of the response, which must
// have status 200 and be at most limit bytes.
func postSOAPMessage(ctx context.Context, httpClient *http.Client, location string, envelope *etree.Element, limit int64) ([]byte, error) {
	requestBody, err := elementToBytes(envelope)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, location, bytes.NewReader(requestBody)) //nolint:gosec // G704: location is an endpoint from the peer's metadata, never from the request being served
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", soapContentType)
	req.Header.Set("SOAPAction", soapActionSAML)
	setNoCacheHeaders(req.Header)

	resp, err := httpClient.Do(req) //nolint:gosec // G704: location is an endpoint from the peer's metadata, never from the request being served
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.DefaultLogger.Printf("Error while closing SOAP response body: %v", err)
		}
	}()
	// A SOAP fault is sent with a 500 status (SOAP 1.1 §6.2); it is not
	// parsed, since it carries no SAML response.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d (%s)", resp.StatusCode, resp.Status)
	}
	buf, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, fmt.Errorf("response %w", err)
	}
	return buf, nil
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

// soapBodyElement parses soapXML as a SOAP 1.1 envelope and returns the SAML
// protocol element named tag (such as "Response" or "LogoutRequest") that
// must be the only element of its Body. Each element is matched by its
// namespace, not just its local name. A Body that holds a SOAP Fault is an
// error, and so is a mandatory header entry (see
// checkNoMandatorySOAPHeader).
func soapBodyElement(soapXML []byte, tag string) (*etree.Element, error) {
	if err := xmlroundtrip.Validate(soapXML); err != nil {
		return nil, fmt.Errorf("invalid xml: %s", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(soapXML); err != nil {
		return nil, fmt.Errorf("cannot parse SOAP message: %s", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("invalid xml: no root")
	}
	if root.NamespaceURI() != soapEnvelopeNamespace || root.Tag != "Envelope" {
		return nil, errors.New("expected a SOAP Envelope")
	}
	if err := checkNoMandatorySOAPHeader(root); err != nil {
		return nil, err
	}
	bodyEl, err := findOneChild(root, soapEnvelopeNamespace, "Body")
	if err != nil {
		return nil, err
	}
	if fault, err := findChild(bodyEl, soapEnvelopeNamespace, "Fault"); err != nil || fault != nil {
		return nil, errors.New("the SOAP Body holds a Fault")
	}
	if n := len(bodyEl.ChildElements()); n != 1 {
		return nil, fmt.Errorf("expected exactly one element in the SOAP Body, found %d", n)
	}
	return findOneChild(bodyEl, "urn:oasis:names:tc:SAML:2.0:protocol", tag)
}

// checkNoMandatorySOAPHeader fails if envelope, a SOAP 1.1 Envelope, has a
// header entry with mustUnderstand="1". The saml packages understand no
// SOAP header, and a receiver that does not understand a mandatory header
// entry must not process the message (SOAP 1.1 §4.2.3). That holds for
// every SOAP message received, requests and responses alike.
func checkNoMandatorySOAPHeader(envelope *etree.Element) error {
	header, err := findChild(envelope, soapEnvelopeNamespace, "Header")
	if err != nil || header == nil {
		return err
	}
	for _, entry := range header.ChildElements() {
		for i := range entry.Attr {
			attr := &entry.Attr[i]
			if attr.Key == "mustUnderstand" && attr.NamespaceURI() == soapEnvelopeNamespace && attr.Value == "1" {
				return fmt.Errorf("cannot understand the mandatory SOAP header %s", entry.FullTag())
			}
		}
	}
	return nil
}
