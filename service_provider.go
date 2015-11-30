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
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/go-xmlsec/xmldsig"
	"github.com/crewjam/go-xmlsec/xmlenc"
	"github.com/kr/pretty"
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
					Use: "encryption",
					KeyInfo: KeyInfo{
						Certificate: sp.Certificate,
					},
				},
				KeyDescriptor{
					Use: "signing",
					KeyInfo: KeyInfo{
						Certificate: sp.Certificate,
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
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hash[:])
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

	if false {
		req.Signature = &xmldsig.Signature{}
		req.Signature.CanonicalizationMethod.Algorithm = "http://www.w3.org/2001/10/xml-exc-c14n#"
		req.Signature.SignatureMethod.Algorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
		req.Signature.ReferenceTransforms = []xmldsig.Method{
			{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
			{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
		}
		req.Signature.DigestMethod.Algorithm = "http://www.w3.org/2000/09/xmldsig#sha1"

		reqBuf, err := xml.Marshal(req)
		if err != nil {
			return nil, err
		}
		log.Printf("req=%s", string(reqBuf))

		reqBuf, err = xmldsig.Sign([]byte(sp.Key), reqBuf)
		if err != nil {
			return nil, err
		}
		log.Printf("signed req=%s", string(reqBuf))
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

func (sp *ServiceProvider) getIDPSigningCert() string {
	for _, keyDescriptor := range sp.IDPMetadata.IDPSSODescriptor.KeyDescriptor {
		if keyDescriptor.Use == "signing" {
			return keyDescriptor.KeyInfo.Certificate
		}
	}

	// If there are no explicitly signing certs, just return the first
	// non-empty cert we find.
	for _, keyDescriptor := range sp.IDPMetadata.IDPSSODescriptor.KeyDescriptor {
		if keyDescriptor.Use == "" && keyDescriptor.KeyInfo.Certificate != "" {
			return keyDescriptor.KeyInfo.Certificate
		}
	}
	return ""
}

func (sp *ServiceProvider) makeAuthenticationRequest(idpURL *url.URL) (*spAuthRequest, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
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

var ErrInvalidResponse = errors.New("SAML response is invalid")

func (sp *ServiceProvider) ParseResponse(req *http.Request, requestID string) (AssertionAttributes, error) {
	buf, err := base64.StdEncoding.DecodeString(req.Form.Get("SAMLResponse"))
	if err != nil {
		log.Printf("SAMLResponse: cannot parse base64: %q", req.Form.Get("SAMLResponse"))
		return nil, ErrInvalidResponse
	}

	// do some validation first before we decrypt
	resp := spResponse{}
	if err := xml.Unmarshal(buf, &resp); err != nil {
		log.Printf("Unmarshal: %s", err)
		return nil, err
	}
	//pretty.Print(resp)

	if resp.Destination != sp.AcsURL {
		// this response isn't for us... forged?
		log.Printf("resp.Destination != sp.AcsURL")
		return nil, ErrInvalidResponse
	}
	if requestID != "" && resp.InResponseTo != requestID {
		// this response isn't for us... f	orged?
		log.Printf("err 2")
		return nil, ErrInvalidResponse
	}
	if resp.IssueInstant.Add(MaxIssueDelay).Before(timeNow()) {
		// the response has expired
		log.Printf("err 3")
		return nil, ErrInvalidResponse
	}
	if resp.Issuer.Value != sp.IDPMetadata.EntityID {
		// the response is not from our IDP
		log.Printf("err 4")
		return nil, ErrInvalidResponse
	}
	if resp.Status.StatusCode.Value != spStatusSuccess {
		// the response is not success
		log.Printf("err 5: %q!=%q", resp.Status.StatusCode.Value, spStatusSuccess)
		return nil, ErrInvalidResponse
	}

	// decrypt the response if needed
	if resp.EncryptedAssertion != nil {
		var err error
		buf, err = xmlenc.Decrypt([]byte(sp.Key), buf)
		if err != nil {
			log.Printf("err 6: %s", err)
			return nil, err
		}
		log.Printf("buf=%s", string(buf))

		resp = spResponse{}
		if err := xml.Unmarshal(buf, &resp); err != nil {
			log.Printf("err 7: %s", err)
			return nil, err
		}
		resp.Assertion = resp.EncryptedAssertion.Assertion
		resp.EncryptedAssertion = nil
	}
	//pretty.Print(resp.Assertion)

	/*
			XXX: DO NOT COMIT XXX XXX XXX

		// Verify the signature on the assertion
		assertionBuf, err := xml.Marshal(resp.Assertion)
		if err != nil {
			log.Printf("err 8: %s", err)
			return nil, err
		}


			idpSigningCert := sp.getIDPSigningCert()
			idpSigningCert = regexp.MustCompile("\\s+").ReplaceAllString(idpSigningCert, "")
			log.Printf("sp.getIDPSigningCert(): %q", idpSigningCert)
			if err := xmldsig.Verify([]byte(idpSigningCert), assertionBuf); err != nil {
				log.Printf("err 10: %s", err)
				return nil, err
			}
	*/

	assertion := resp.Assertion // only assign once we have a valid signature
	pretty.Print(assertion)

	// Validate the assertion
	if assertion.IssueInstant.Add(MaxIssueDelay).Before(timeNow()) {
		// the response has expired
		log.Printf("err 11")
		return nil, ErrInvalidResponse
	}
	if assertion.Issuer.Value != sp.IDPMetadata.EntityID {
		// the response is not from our IDP
		log.Printf("err 12")
		return nil, ErrInvalidResponse
	}
	if assertion.Subject.NameID.NameQualifier != sp.IDPMetadata.EntityID {
		// this response isn't for us... forged?
		log.Printf("err 13")
		return nil, ErrInvalidResponse
	}
	if assertion.Subject.NameID.SPNameQualifier != sp.MetadataURL {
		// this response isn't for us... forged?
		log.Printf("err 14")
		return nil, ErrInvalidResponse
	}
	if requestID != "" && assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo != requestID {
		// this response isn't for us... frged?
		log.Printf("err 15")
		return nil, ErrInvalidResponse
	}
	if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient != sp.AcsURL {
		// this response isn't for us... forged?
		log.Printf("err 16")
		return nil, ErrInvalidResponse
	}
	if assertion.Subject.SubjectConfirmation.SubjectConfirmationData.NotOnOrAfter.Before(timeNow()) {
		// expired
		log.Printf("err 17")
		return nil, ErrInvalidResponse
	}
	if assertion.Conditions.NotBefore.After(timeNow()) {
		// not valid yet
		log.Printf("err 18")
		return nil, ErrInvalidResponse
	}
	if assertion.Conditions.NotOnOrAfter.Before(timeNow()) {
		// not valid yet
		log.Printf("err 19")
		return nil, ErrInvalidResponse
	}
	if assertion.Conditions.AudienceRestriction.Audience.Value != sp.MetadataURL {
		// not valid yet
		log.Printf("err 20")
		return nil, ErrInvalidResponse
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
