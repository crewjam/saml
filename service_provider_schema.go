package saml

import (
	"encoding/xml"
	"time"

	"github.com/crewjam/go-xmlsec/xmldsig"
)

type spAuthRequest struct {
	XMLName                     xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	AssertionConsumerServiceURL string                `xml:",attr"`
	Destination                 string                `xml:",attr"`
	ID                          string                `xml:",attr"`
	IssueInstant                time.Time             `xml:",attr"`
	ProtocolBinding             string                `xml:",attr"`
	Version                     string                `xml:",attr"`
	Issuer                      spAuthReqIssuer       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature                   *xmldsig.Signature    `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	NameIDPolicy                spAuthReqNameIdPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

type spAuthReqIssuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:",attr"`
	Text    string   `xml:",chardata"`
}

type spAuthReqNameIdPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	AllowCreate bool     `xml:",attr"`
	Format      string   `xml:",chardata"`
}

type spResponse struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Destination        string    `xml:",attr"`
	ID                 string    `xml:",attr"`
	InResponseTo       string    `xml:",attr"`
	IssueInstant       time.Time `xml:",attr"`
	Version            string    `xml:",attr"`
	Issuer             *spIssuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status             *spStatus `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	EncryptedAssertion *spEncryptedAssertion
	Assertion          *spAssertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

type spIssuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}

type spStatus struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode spStatusCode
}

type spStatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:",attr"`
}

const spStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

type spEncryptedAssertion struct {
	Assertion *spAssertion
}

type spAssertion struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string    `xml:",attr"`
	IssueInstant       time.Time `xml:",attr"`
	Version            string    `xml:",attr"`
	Issuer             *spIssuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature          *xmldsig.Signature
	Subject            *spSubject
	Conditions         *spConditions
	AuthnStatement     *spAuthnStatement
	AttributeStatement *spAttributeStatement
}

type spSubject struct {
	XMLName             xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              *spNameID
	SubjectConfirmation *spSubjectConfirmation
}

type spNameID struct {
	Format          string `xml:",attr"`
	NameQualifier   string `xml:",attr"`
	SPNameQualifier string `xml:",attr"`
	Value           string `xml:",chardata"`
}

type spSubjectConfirmation struct {
	Method                  string `xml:",attr"`
	SubjectConfirmationData spSubjectConfirmationData
}

type spSubjectConfirmationData struct {
	Address      string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	NotOnOrAfter time.Time `xml:",attr"`
	Recipient    string    `xml:",attr"`
}

type spConditions struct {
	NotBefore           time.Time `xml:",attr"`
	NotOnOrAfter        time.Time `xml:",attr"`
	AudienceRestriction *spAudienceRestriction
}

type spAudienceRestriction struct {
	Audience *spAudience
}

type spAudience struct {
	Value string `xml:",chardata"`
}

type spAuthnStatement struct {
	AuthnInstance   time.Time `xml:",attr"`
	SessionIndex    string    `xml:",attr"`
	SubjectLocality spSubjectLocality
	AuthnContext    spAuthnContext
}

type spSubjectLocality struct {
	Address string `xml:",attr"`
}

type spAuthnContext struct {
	AuthnContextClassRef *spAuthnContextClassRef
}

type spAuthnContextClassRef struct {
	Value string `xml:",chardata"`
}

type spAttributeStatement struct {
	Attributes []spAttribute `xml:"Attribute"`
}

type spAttribute struct {
	FriendlyName string             `xml:",attr"`
	Name         string             `xml:",attr"`
	NameFormat   string             `xml:",attr"`
	Values       []spAttributeValue `xml:"AttributeValue"`
}

type spAttributeValue struct {
	Type   string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value  string `xml:",chardata"`
	NameID *spNameID
}
