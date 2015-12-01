package saml

import (
	"encoding/xml"
	"time"
)

type EntitiesDescriptor struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	EntityDescriptor []*Metadata
}

type Metadata struct {
	XMLName          xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	ValidUntil       time.Time         `xml:"validUntil,attr"`
	CacheDuration    time.Duration     `xml:"cacheDuration,attr,omitempty"`
	EntityID         string            `xml:"entityID,attr"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor"`
	// Organization -- TODO
	// Contacts -- TODO
	//Signature *xmldsig.Signature
}

type KeyDescriptor struct {
	Use               string             `xml:"use,attr"`
	KeyInfo           KeyInfo            `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type KeyInfo struct {
	XMLName     xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	Certificate string   `xml:"X509Data>X509Certificate"`
}

type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}
type IndexedEndpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
	Index    int    `xml:"index,attr"`
}

type SPSSODescriptor struct {
	XMLName                    xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	AuthnRequestsSigned        bool              `xml:",attr"`
	WantAssertionsSigned       bool              `xml:",attr"`
	ProtocolSupportEnumeration string            `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              []KeyDescriptor   `xml:"KeyDescriptor"`
	ArtifactResolutionService  []IndexedEndpoint `xml:"ArtifactResolutionService"`
	SingleLogoutService        []Endpoint        `xml:"SingleLogoutService"`
	ManageNameIDService        []Endpoint
	NameIDFormat               []string          `xml:"NameIDFormat"`
	AssertionConsumerService   []IndexedEndpoint `xml:"AssertionConsumerService"`
	AttributeConsumingService  []interface{}
}

type IDPSSODescriptor struct {
	XMLName                    xml.Name        `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	ProtocolSupportEnumeration string          `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              []KeyDescriptor `xml:"KeyDescriptor"`
	NameIDFormat               []string        `xml:"NameIDFormat"`
	SingleSignOnService        []Endpoint      `xml:"SingleSignOnService"`
}
