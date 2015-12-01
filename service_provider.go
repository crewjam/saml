package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/crewjam/go-xmlsec/xmldsig"
	"github.com/crewjam/go-xmlsec/xmlenc"
)

type ServiceProvider struct {
	Key         string
	Certificate string

	MetadataURL string
	LogoutURL   string
	AcsURL      string

	IDPMetadata *Metadata
}

var timeNow = time.Now
var randReader = rand.Reader

const DefaultValidDuration = time.Hour * 24 * 2
const DefaultCacheDuration = time.Hour * 24 * 7

type Assertion struct {
	Email string /// XXX
}

func (sp *ServiceProvider) Metadata() *Metadata {
	if cert, _ := pem.Decode([]byte(sp.Certificate)); cert != nil {
		sp.Certificate = base64.StdEncoding.EncodeToString(cert.Bytes)
	}

	return &Metadata{
		EntityID:   sp.MetadataURL,
		ValidUntil: timeNow().Add(DefaultValidDuration),
		SPSSODescriptor: &SPSSODescriptor{
			AuthnRequestsSigned:        false,
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: []KeyDescriptor{
				KeyDescriptor{
					KeyInfo: KeyInfo{
						Certificate: sp.Certificate,
					},
					EncryptionMethods: []EncryptionMethod{
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
						EncryptionMethod{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
					},
				},
			},
			SingleLogoutService: []Endpoint{{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				Location: sp.LogoutURL,
			}},
			AssertionConsumerService: []IndexedEndpoint{{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: sp.AcsURL,
				Index:    1,
			}},
		},
	}
}

func (sp *ServiceProvider) redirectSign(message string) (string, error) {
	hash := sha1.Sum([]byte(message))

	block, _ := pem.Decode([]byte(sp.Key))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	sig, err := rsa.SignPKCS1v15(randReader, privateKey, crypto.SHA1, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (sp *ServiceProvider) MakeRedirectAuthenticationRequest(relayState string) (*url.URL, error) {
	idpURL, err := url.Parse(sp.IDPRedirectURL())
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

	if false {
		query.Set("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
		idpURL.RawQuery = query.Encode()

		signature, err := sp.redirectSign(idpURL.RawQuery)
		if err != nil {
			return nil, err
		}
		query.Set("Signature", signature)
	}
	idpURL.RawQuery = query.Encode()

	ioutil.WriteFile("auth_request", []byte(idpURL.String()), 0644)

	return idpURL, nil
}

func (sp *ServiceProvider) IDPRedirectURL() string {
	for _, singleSignOnService := range sp.IDPMetadata.IDPSSODescriptor.SingleSignOnService {
		if singleSignOnService.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" {
			return singleSignOnService.Location
		}
	}
	return ""
}

func (sp *ServiceProvider) IDPPostURL() string {
	for _, singleSignOnService := range sp.IDPMetadata.IDPSSODescriptor.SingleSignOnService {
		if singleSignOnService.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
			return singleSignOnService.Location
		}
	}
	return ""
}

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

func (sp *ServiceProvider) makeAuthenticationRequest(idpURL *url.URL) (*spAuthRequest, error) {
	id := make([]byte, 16)
	if _, err := randReader.Read(id); err != nil {
		return nil, err
	}

	req := spAuthRequest{
		AssertionConsumerServiceURL: sp.AcsURL,
		Destination:                 idpURL.String(),
		ID:                          fmt.Sprintf("id-%x", id),
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

func (sp *ServiceProvider) MakePostAuthenticationRequest(relayState string) (*http.Request, error) {

	panic("not implemented")
}

var MaxIssueDelay = time.Second * 90

type AssertionAttributes []AssertionAttribute

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

type AssertionAttribute struct {
	FriendlyName string
	Name         string
	Value        string
}

type InvalidResponseError struct {
	PrivateErr error
	Response   string
	Now        time.Time
}

func (ivr *InvalidResponseError) Error() string {
	return fmt.Sprintf("Authentication failed: %s", ivr.PrivateErr) // XXX
}

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
	assertionBuf, err := xmlenc.Decrypt([]byte(sp.Key), rawResponseBuf)
	if err != nil {
		retErr.PrivateErr = fmt.Errorf("failed to decrypt response: %s", err)
		return nil, retErr
	}
	retErr.Response = string(assertionBuf)

	if err := xmldsig.Verify(sp.getIDPSigningCert(), assertionBuf,
		xmldsig.Options{
			XMLID: []xmldsig.XMLIDOption{{
				ElementName:      "Assertion",
				ElementNamespace: "urn:oasis:names:tc:SAML:2.0:assertion",
				AttributeName:    "ID",
			}},
		}); err != nil {
		retErr.PrivateErr = fmt.Errorf("failed to verify signature on response: %s", err)
		return nil, retErr
	}

	assertion := spAssertion{}
	if err := xml.Unmarshal(assertionBuf, &assertion); err != nil {
		retErr.PrivateErr = fmt.Errorf("cannot unmarshal assertion: %s", err)
		return nil, retErr
	}

	if err := sp.validateAssertion(&assertion, requestID, now); err != nil {
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

func (sp *ServiceProvider) validateAssertion(assertion *spAssertion, requestID string, now time.Time) error {
	// Validate the assertion
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
