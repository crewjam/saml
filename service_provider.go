package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/crewjam/go-xmlsec"

	"github.com/crewjam/saml/metadata"
)

// ServiceProvider implements SAML Service provider.
//
// In SAML, service providers delegate responsibility for identifying
// clients to an identity provider. If you are writing an application
// that uses passwords (or whatever) stored somewhere else, then you
// are service provider.
//
// See the example directory for an example of a web application using
// the service provider interface.
type ServiceProvider struct {
	// Key is the RSA private key we use to sign requests.
	Key string

	// Certificate is the RSA public part of Key.
	Certificate string

	// MetadataURL is the full URL to the metadata endpoint on this host,
	// i.e. https://example.com/saml/metadata
	MetadataURL string

	// AcsURL is the full URL to the SAML Assertion Customer Service endpoint
	// on this host, i.e. https://example.com/saml/acs
	AcsURL string

	// IDPMetadata is the metadata from the identity provider.
	IDPMetadata *metadata.Metadata
}

var timeNow = time.Now       // thunk for testing
var randReader = rand.Reader // thunk for testing

// MaxIssueDelay is the longest allowed time between when a SAML assertion is
// issued by the IDP and the time it is received by ParseResponse. (In practice
// this is the maximum allowed clock drift between the SP and the IDP).
const MaxIssueDelay = time.Second * 90

// DefaultValidDuration is how long we assert that the SP metadata is valid.
const DefaultValidDuration = time.Hour * 24 * 2

// DefaultCacheDuration is how long we ask the IDP to cache the SP metadata.
const DefaultCacheDuration = time.Hour * 24 * 1

// Metadata returns the service provider metadata
func (sp *ServiceProvider) Metadata() *metadata.Metadata {
	if cert, _ := pem.Decode([]byte(sp.Certificate)); cert != nil {
		sp.Certificate = base64.StdEncoding.EncodeToString(cert.Bytes)
	}

	return &metadata.Metadata{
		EntityID:   sp.MetadataURL,
		ValidUntil: timeNow().Add(DefaultValidDuration),
		SPSSODescriptor: &metadata.SPSSODescriptor{
			AuthnRequestsSigned:        false,
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: []metadata.KeyDescriptor{
				metadata.KeyDescriptor{
					Use: "signing",
					KeyInfo: metadata.KeyInfo{
						Certificate: sp.Certificate,
					},
				},
				metadata.KeyDescriptor{
					Use: "encryption",
					KeyInfo: metadata.KeyInfo{
						Certificate: sp.Certificate,
					},
					EncryptionMethods: []metadata.EncryptionMethod{
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
						metadata.EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
					},
				},
			},
			AssertionConsumerService: []metadata.IndexedEndpoint{{
				Binding:  metadata.HTTPPostBinding,
				Location: sp.AcsURL,
				Index:    1,
			}},
		},
	}
}

// MakeRedirectAuthenticationRequest creates a SAML authentication request using
// the HTTP-Redirect binding. It returns a URL that we will redirect the user to
// in order to start the auth process.
func (sp *ServiceProvider) MakeRedirectAuthenticationRequest(relayState string) (*url.URL, error) {
	idpURL, err := url.Parse(sp.getIDPRedirectURL())
	if err != nil {
		return nil, fmt.Errorf("cannot parse IDP redirect url: %s", err)
	}

	req, err := sp.makeAuthenticationRequest(idpURL)
	if err != nil {
		return nil, err
	}

	w := &bytes.Buffer{}
	w1 := base64.NewEncoder(base64.StdEncoding, w)
	w2, _ := flate.NewWriter(w1, 9)
	if err := xml.NewEncoder(w2).Encode(req); err != nil {
		return nil, err
	}
	w2.Close()
	w1.Close()

	query := url.Values{}
	query.Set("SAMLRequest", string(w.Bytes()))
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	idpURL.RawQuery = query.Encode()

	return idpURL, nil
}

// getIDPRedirectURL returns URL for the IDP's HTTP-Redirect binding or an empty string
// if one is not specified.
func (sp *ServiceProvider) getIDPRedirectURL() string {
	for _, singleSignOnService := range sp.IDPMetadata.IDPSSODescriptor.SingleSignOnService {
		if singleSignOnService.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			return singleSignOnService.Location
		}
	}
	return ""
}

// getIDPPostURL returns URL for the IDP's HTTP-POST binding or an empty string if one
// is not specified.
func (sp *ServiceProvider) getIDPPostURL() string {
	for _, singleSignOnService := range sp.IDPMetadata.IDPSSODescriptor.SingleSignOnService {
		if singleSignOnService.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			return singleSignOnService.Location
		}
	}
	return ""
}

// getIDPSigningCert returns the certificate which we can use to verify things
// signed by the IDP in PEM format, or nil if no such certificate is found.
func (sp *ServiceProvider) getIDPSigningCert() []byte {
	cert := ""

	for _, keyDescriptor := range sp.IDPMetadata.IDPSSODescriptor.KeyDescriptor {
		if keyDescriptor.Use == "signing" {
			cert = keyDescriptor.KeyInfo.Certificate
			break
		}
	}

	// If there are no explicitly signing certs, just return the first
	// non-empty cert we find.
	if cert == "" {
		for _, keyDescriptor := range sp.IDPMetadata.IDPSSODescriptor.KeyDescriptor {
			if keyDescriptor.Use == "" && keyDescriptor.KeyInfo.Certificate != "" {
				cert = keyDescriptor.KeyInfo.Certificate
				break
			}
		}
	}

	if cert == "" {
		return nil
	}

	// cleanup whitespace and re-encode a PEM
	cert = regexp.MustCompile("\\s+").ReplaceAllString(cert, "")
	certBytes, _ := base64.StdEncoding.DecodeString(cert)
	certBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes})
	return certBytes
}

// makeAuthenticationRequest produces a new spAuthRequest object for idpURL.
func (sp *ServiceProvider) makeAuthenticationRequest(idpURL *url.URL) (*spAuthRequest, error) {
	req := spAuthRequest{
		AssertionConsumerServiceURL: sp.AcsURL,
		Destination:                 idpURL.String(),
		ID:                          fmt.Sprintf("id-%x", randomBytes(16)),
		IssueInstant:                timeNow(),
		Version:                     "2.0",
		Issuer: spAuthReqIssuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Text:   sp.MetadataURL,
		},
		NameIDPolicy: spAuthReqNameIdPolicy{
			AllowCreate: true,
			// TODO(ross): figure out exactly policy we need
			// urn:mace:shibboleth:1.0:nameIdentifier
			// urn:oasis:names:tc:SAML:2.0:nameid-format:transient
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
		},
	}
	return &req, nil
}

// MakePostAuthenticationRequest creates a SAML authentication request using
// the HTTP-POST binding. It returns HTML text representing an HTML form that
// can be sent presented to a browser to initiate the login process.
func (sp *ServiceProvider) MakePostAuthenticationRequest(relayState string) ([]byte, error) {
	idpURL, err := url.Parse(sp.getIDPPostURL())
	if err != nil {
		return nil, fmt.Errorf("cannot parse IDP post url: %s", err)
	}

	req, err := sp.makeAuthenticationRequest(idpURL)
	if err != nil {
		return nil, err
	}

	reqBuf, err := xml.Marshal(req)
	if err != nil {
		panic(err)
	}
	encodedReqBuf := base64.StdEncoding.EncodeToString(reqBuf)

	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<form method="post" action="{{.URL}}">` +
		`<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />` +
		`<input type="hidden" name="RelayState" value="{{.RelayState}}" />` +
		`<input type="submit" value="Submit" />` +
		`</form>`))
	data := struct {
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		URL:         idpURL.String(),
		SAMLRequest: encodedReqBuf,
		RelayState:  relayState,
	}

	rv := bytes.Buffer{}
	if err := tmpl.Execute(&rv, data); err != nil {
		panic(err)
	}

	return rv.Bytes(), nil
}

// AssertionAttributes is a list of AssertionAttribute
type AssertionAttributes []AssertionAttribute

// Get returns the assertion attribute whose Name or FriendlyName
// matches name, or nil if no matching attribute is found.
func (aa AssertionAttributes) Get(name string) *AssertionAttribute {
	for _, attr := range aa {
		if attr.Name == name {
			return &attr
		}
		if attr.FriendlyName == name {
			return &attr
		}
	}
	return nil
}

// AssertionAttribute represents an attribute of the user extracted from
// a SAML Assertion.
type AssertionAttribute struct {
	FriendlyName string
	Name         string
	Value        string
}

// InvalidResponseError is the error produced by ParseResponse when it fails.
// The underlying error is in PrivateErr. Response is the response as it was
// known at the time validation failed. Now is the time that was used to validate
// time-dependent parts of the assertion.
type InvalidResponseError struct {
	PrivateErr error
	Response   string
	Now        time.Time
}

func (ivr *InvalidResponseError) Error() string {
	return fmt.Sprintf("Authentication failed")
}

// ParseResponse extracts the SAML IDP response received in req, validates
// it, and returns the verified attributes of the request.
//
// This function handles decrypting the message, verifying the digital
// signature on the assertion, and verifying that the specified conditions
// and properties are met.
//
// If the function fails it will return an InvalidResponseError whose
// properties are useful in describing which part of the parsing process
// failed. However, to discourage inadvertent disclosure the diagnostic
// information, the Error() method returns a static string.
func (sp *ServiceProvider) ParseResponse(req *http.Request, requestID string) (AssertionAttributes, error) {
	now := timeNow()
	retErr := &InvalidResponseError{
		Now:      now,
		Response: req.PostForm.Get("SAMLResponse"),
	}

	rawResponseBuf, err := base64.StdEncoding.DecodeString(req.PostForm.Get("SAMLResponse"))
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot parse base64: %s", err)
		return nil, retErr
	}
	retErr.Response = string(rawResponseBuf)

	// do some validation first before we decrypt
	resp := spResponse{}
	if err := xml.Unmarshal(rawResponseBuf, &resp); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal response: %s", err)
		return nil, retErr
	}
	if resp.Destination != sp.AcsURL {
		retErr.PrivateErr = fmt.Errorf("`Destination` does not match AcsURL (expected %q)", sp.AcsURL)
		return nil, retErr
	}
	if requestID != "" && resp.InResponseTo != requestID {
		retErr.PrivateErr = fmt.Errorf("`InResponseTo` does not match requestID (expected %q)", requestID)
		return nil, retErr
	}
	if resp.IssueInstant.Add(MaxIssueDelay).Before(now) {
		retErr.PrivateErr = fmt.Errorf("IssueInstant expired at %s", resp.IssueInstant.Add(MaxIssueDelay))
		return nil, retErr
	}
	if resp.Issuer.Value != sp.IDPMetadata.EntityID {
		retErr.PrivateErr = fmt.Errorf("Issuer does not match the IDP metadata (expected %q)", sp.IDPMetadata.EntityID)
		return nil, retErr
	}
	if resp.Status.StatusCode.Value != spStatusSuccess {
		retErr.PrivateErr = fmt.Errorf("Status code was not %s", spStatusSuccess)
		return nil, retErr
	}

	// decrypt the response
	plaintextAssertion, err := xmlsec.Decrypt([]byte(sp.Key), resp.EncryptedAssertion.EncryptedData)
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("failed to decrypt response: %s", err)
		return nil, retErr
	}
	retErr.Response = string(plaintextAssertion)

	log.Printf("XXX plaintextAssertion: `%s` XXX", string(plaintextAssertion))

	if err := xmlsec.Verify(sp.getIDPSigningCert(), plaintextAssertion,
		xmlsec.SignatureOptions{
			XMLID: []xmlsec.XMLIDOption{{
				ElementName:      "Assertion",
				ElementNamespace: "urn:oasis:names:tc:SAML:2.0:assertion",
				AttributeName:    "ID",
			}},
		}); err != nil {
		retErr.PrivateErr = fmt.Errorf("failed to verify signature on response: %s", err)
		return nil, retErr
	}

	assertion := &spAssertion{}
	xml.Unmarshal(plaintextAssertion, assertion)
	log.Printf("XXX assertion: `%#v` XXX", resp)

	if err := sp.validateAssertion(assertion, requestID, now); err != nil {
		retErr.PrivateErr = fmt.Errorf("assertion invalid: %s", err)
		return nil, retErr
	}

	// Extract properties from the SAML assertion
	attributes := []AssertionAttribute{}
	for _, x := range assertion.AttributeStatement.Attributes {
		for _, v := range x.Values {
			attributes = append(attributes, AssertionAttribute{
				FriendlyName: x.FriendlyName,
				Name:         x.Name,
				Value:        v.Value,
			})
		}
	}

	return attributes, nil
}

// validateAssertion checks that the conditions specified in assertion match
// the requirements to accept. If validation fails, it returns an error describing
// the failure. (The digital signature on the assertion is not checked -- this
// should be done before calling this function).
func (sp *ServiceProvider) validateAssertion(assertion *spAssertion, requestID string, now time.Time) error {
	if assertion.IssueInstant.Add(MaxIssueDelay).Before(now) {
		return fmt.Errorf("expired on %s", assertion.IssueInstant.Add(MaxIssueDelay))
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		return fmt.Errorf("issuer is not %q", sp.IDPMetadata.EntityID)
	}
	if assertion.Subject.NameID.NameQualifier != sp.IDPMetadata.EntityID {
		return fmt.Errorf("Subject NameID NameQualifier is not %q", sp.IDPMetadata.EntityID)
	}
	if assertion.Subject.NameID.SPNameQualifier != sp.MetadataURL {
		return fmt.Errorf("Subject NameID SPNameQualifier is not %q", sp.MetadataURL)
	}
	if requestID != "" && assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo != requestID {
		return fmt.Errorf("SubjectConfirmation requestID is not %q", requestID)
	}
	if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != sp.AcsURL {
		return fmt.Errorf("SubjectConfirmation Recipient is not %s", sp.AcsURL)
	}
	if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Before(now) {
		return fmt.Errorf("SubjectConfirmationData is expired")
	}
	if assertion.Conditions.NotBefore.After(now) {
		return fmt.Errorf("Conditions is not yet valid")
	}
	if assertion.Conditions.NotOnOrAfter.Before(now) {
		return fmt.Errorf("Conditions is expired")
	}
	if assertion.Conditions.AudienceRestriction.Audience.Value != sp.MetadataURL {
		return fmt.Errorf("Conditions AudienceRestriction is not %q", sp.MetadataURL)
	}
	return nil
}
