package saml

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// HTTPPostBinding is the official URN for the HTTP-POST binding (transport)
const HTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

// HTTPRedirectBinding is the official URN for the HTTP-Redirect binding (transport)
const HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

// HTTPArtifactBinding is the official URN for the HTTP-Artifact binding (transport)
const HTTPArtifactBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

// SOAPBinding is the official URN for the SOAP binding (transport)
const SOAPBinding = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

// SOAPBindingV1 is the URN for the SOAP binding in SAML 1.0
const SOAPBindingV1 = "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding"

// EntitiesDescriptor represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.1
type EntitiesDescriptor struct {
	XMLName             xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	ID                  *string        `xml:",attr,omitempty"`
	ValidUntil          *time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration       *time.Duration `xml:"cacheDuration,attr,omitempty"`
	Name                *string        `xml:",attr,omitempty"`
	Signature           *etree.Element
	Extensions          *Extensions          `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions,omitempty"`
	EntitiesDescriptors []EntitiesDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	EntityDescriptors   []EntityDescriptor   `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
}

// MarshalXML implements xml.Marshaler
func (m EntitiesDescriptor) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	var validUntil *RelaxedTime
	var cacheDuration *Duration
	if m.ValidUntil != nil {
		vu := RelaxedTime(*m.ValidUntil)
		validUntil = &vu
	}
	if m.CacheDuration != nil {
		cd := Duration(*m.CacheDuration)
		cacheDuration = &cd
	}
	type Alias EntitiesDescriptor
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration *Duration        `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		ValidUntil:    validUntil,
		CacheDuration: cacheDuration,
		Signature:     (*etreeElementXML)(m.Signature),
		Alias:         (*Alias)(&m),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (m *EntitiesDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias EntitiesDescriptor
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration *Duration        `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	m.Signature = (*etree.Element)(aux.Signature)
	if aux.ValidUntil != nil {
		t := time.Time(*aux.ValidUntil)
		m.ValidUntil = &t
	}
	if aux.CacheDuration != nil {
		d := time.Duration(*aux.CacheDuration)
		m.CacheDuration = &d
	}
	return nil
}

// Metadata as been renamed to EntityDescriptor
//
// This change was made to be consistent with the rest of the API which uses names
// from the SAML specification for types.
//
// This is a tombstone to help you discover this fact. You should update references
// to saml.Metadata to be saml.EntityDescriptor.
var Metadata = struct{}{}

// EntityDescriptor represents the SAML EntityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2
type EntityDescriptor struct {
	XMLName                       xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID                      string        `xml:"entityID,attr"`
	ID                            string        `xml:",attr,omitempty"`
	ValidUntil                    time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration                 time.Duration `xml:"cacheDuration,attr,omitempty"`
	Signature                     *etree.Element
	Extensions                    *Extensions                    `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions,omitempty"`
	RoleDescriptors               []RoleDescriptor               `xml:"RoleDescriptor"`
	IDPSSODescriptors             []IDPSSODescriptor             `xml:"IDPSSODescriptor"`
	SPSSODescriptors              []SPSSODescriptor              `xml:"SPSSODescriptor"`
	AuthnAuthorityDescriptors     []AuthnAuthorityDescriptor     `xml:"AuthnAuthorityDescriptor"`
	AttributeAuthorityDescriptors []AttributeAuthorityDescriptor `xml:"AttributeAuthorityDescriptor"`
	PDPDescriptors                []PDPDescriptor                `xml:"PDPDescriptor"`
	AffiliationDescriptor         *AffiliationDescriptor
	Organization                  *Organization
	ContactPerson                 *ContactPerson
	AdditionalMetadataLocations   []string `xml:"AdditionalMetadataLocation"`
}

// MarshalXML implements xml.Marshaler
func (m EntityDescriptor) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	// validUntil is optional (saml-metadata-2.0-os §2.3.2). A zero ValidUntil
	// means "not set" and must be omitted rather than rendered as
	// 0001-01-01T00:00:00Z, which consumers would treat as already expired.
	var validUntil *RelaxedTime
	if !m.ValidUntil.IsZero() {
		vu := RelaxedTime(m.ValidUntil)
		validUntil = &vu
	}
	roleDescriptors := make([]roleDescriptorXML, len(m.RoleDescriptors))
	for i := range m.RoleDescriptors {
		roleDescriptors[i] = roleDescriptorXML(m.RoleDescriptors[i])
	}
	type Alias EntityDescriptor
	aux := &struct {
		ValidUntil      *RelaxedTime        `xml:"validUntil,attr,omitempty"`
		CacheDuration   Duration            `xml:"cacheDuration,attr,omitempty"`
		Signature       *etreeElementXML    `xml:"Signature"`
		RoleDescriptors []roleDescriptorXML `xml:"RoleDescriptor"`
		*Alias
	}{
		ValidUntil:      validUntil,
		CacheDuration:   Duration(m.CacheDuration),
		Signature:       (*etreeElementXML)(m.Signature),
		RoleDescriptors: roleDescriptors,
		Alias:           (*Alias)(&m),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (m *EntityDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias EntityDescriptor
	aux := &struct {
		ValidUntil      RelaxedTime         `xml:"validUntil,attr,omitempty"`
		CacheDuration   Duration            `xml:"cacheDuration,attr,omitempty"`
		Signature       *etreeElementXML    `xml:"Signature"`
		RoleDescriptors []roleDescriptorXML `xml:"RoleDescriptor"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	m.Signature = (*etree.Element)(aux.Signature)
	for _, rd := range aux.RoleDescriptors {
		m.RoleDescriptors = append(m.RoleDescriptors, RoleDescriptor(rd))
	}
	m.ValidUntil = time.Time(aux.ValidUntil)
	m.CacheDuration = time.Duration(aux.CacheDuration)
	return nil
}

// signMetadata returns ed as an XML element carrying an enveloped signature
// made with signingContext (saml-metadata-2.0-os §3).
//
// The signature references the EntityDescriptor by its ID attribute; one is
// generated if ed does not have one. ed itself is not modified. The returned
// element must be serialized as-is: re-indenting it changes the signed
// content.
func signMetadata(ed *EntityDescriptor, signingContext *dsig.SigningContext) (*etree.Element, error) {
	unsigned := *ed
	unsigned.Signature = nil
	if unsigned.ID == "" {
		unsigned.ID = fmt.Sprintf("id-%x", randomBytes(20))
	}

	buf, err := xml.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(buf); err != nil {
		return nil, err
	}

	el := doc.Root()
	sigEl, err := signingContext.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}

	// The metadata schema requires ds:Signature to be the first child of
	// EntityDescriptor. The enveloped-signature transform removes it before
	// the digest is computed, so its position does not affect validity.
	el.InsertChildAt(0, sigEl)
	return el, nil
}

// defaultSignatureMethod returns the signature method used when none is
// configured: SHA-256 with ECDSA for an ECDSA key, and with RSA otherwise.
// SHA-1 based methods are deprecated for XML signatures.
func defaultSignatureMethod(publicKey crypto.PublicKey) string {
	if _, ok := publicKey.(*ecdsa.PublicKey); ok {
		return dsig.ECDSASHA256SignatureMethod
	}
	return dsig.RSASHA256SignatureMethod
}

// Organization represents the SAML Organization object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2.1
type Organization struct {
	OrganizationNames        []LocalizedName `xml:"OrganizationName"`
	OrganizationDisplayNames []LocalizedName `xml:"OrganizationDisplayName"`
	OrganizationURLs         []LocalizedURI  `xml:"OrganizationURL"`
}

// LocalizedName represents the SAML type localizedNameType.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.4
type LocalizedName struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// LocalizedURI represents the SAML type localizedURIType.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.5
type LocalizedURI struct {
	Lang  string `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	Value string `xml:",chardata"`
}

// ContactPerson represents the SAML element ContactPerson.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.2.2
type ContactPerson struct {
	ContactType      string `xml:"contactType,attr"`
	Company          string
	GivenName        string
	SurName          string
	EmailAddresses   []string `xml:"EmailAddress"`
	TelephoneNumbers []string `xml:"TelephoneNumber"`
}

// RoleDescriptor represents the SAML element RoleDescriptor.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.1
type RoleDescriptor struct {
	ID                         string        `xml:",attr,omitempty"`
	ValidUntil                 *time.Time    `xml:"validUntil,attr,omitempty"`
	CacheDuration              time.Duration `xml:"cacheDuration,attr,omitempty"`
	ProtocolSupportEnumeration string        `xml:"protocolSupportEnumeration,attr"`
	ErrorURL                   string        `xml:"errorURL,attr,omitempty"`
	Signature                  *etree.Element
	Extensions                 *Extensions     `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions,omitempty"`
	KeyDescriptors             []KeyDescriptor `xml:"KeyDescriptor,omitempty"`
	Organization               *Organization   `xml:"Organization,omitempty"`
	ContactPeople              []ContactPerson `xml:"ContactPerson,omitempty"`
}

// marshalRoleDescriptorAttrs and unmarshalRoleDescriptorAttrs convert the
// RoleDescriptor attributes whose XML representation differs from the
// default encoding of their Go types: cacheDuration is an xsd:duration (e.g.
// "PT1H") rather than a count of nanoseconds, and validUntil may use any of
// the time formats accepted by RelaxedTime.
//
// They are used by the MarshalXML and UnmarshalXML methods of the concrete
// role descriptor types, whose auxiliary structs declare validUntil and
// cacheDuration at a shallower depth than the embedded RoleDescriptor so that
// they take precedence over RoleDescriptor.ValidUntil and
// RoleDescriptor.CacheDuration. RoleDescriptor itself cannot implement
// xml.Marshaler or xml.Unmarshaler, because those methods would be promoted to
// every type that embeds it.
func marshalRoleDescriptorAttrs(m *RoleDescriptor) (*RelaxedTime, Duration) {
	var validUntil *RelaxedTime
	if m.ValidUntil != nil {
		vu := RelaxedTime(*m.ValidUntil)
		validUntil = &vu
	}
	return validUntil, Duration(m.CacheDuration)
}

func unmarshalRoleDescriptorAttrs(m *RoleDescriptor, validUntil *RelaxedTime, cacheDuration Duration) {
	if validUntil != nil {
		t := time.Time(*validUntil)
		m.ValidUntil = &t
	}
	m.CacheDuration = time.Duration(cacheDuration)
}

// KeyDescriptor represents the XMLSEC object of the same name
type KeyDescriptor struct {
	Use               string             `xml:"use,attr"`
	KeyInfo           KeyInfo            `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	EncryptionMethods []EncryptionMethod `xml:"EncryptionMethod"`
}

// EncryptionMethod represents the XMLSEC object of the same name
type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr"`
	// KeySize is the optional xenc:KeySize child, which states the key size
	// in bits for algorithms that allow more than one.
	KeySize *int `xml:"http://www.w3.org/2001/04/xmlenc# KeySize,omitempty"`
}

// AlgSupportNamespace is the namespace of the SAML V2.0 Metadata Profile for
// Algorithm Support.
//
// See https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.html
const AlgSupportNamespace = "urn:oasis:names:tc:SAML:metadata:algsupport"

// Extensions represents the SAML metadata element md:Extensions, which holds
// extension elements from namespaces other than the SAML metadata namespace.
//
// Elements this package knows are decoded into their own fields. Any other
// element is kept in Other, so that it is not lost when metadata is parsed and
// then written out again. Elements are written in field order, so the order
// of elements in Other relative to the known elements is not preserved.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.3.1
type Extensions struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions"`

	// SigningMethods and DigestMethods are the alg:SigningMethod and
	// alg:DigestMethod elements of the Metadata Profile for Algorithm Support.
	SigningMethods []SigningMethod `xml:"urn:oasis:names:tc:SAML:metadata:algsupport SigningMethod"`
	DigestMethods  []DigestMethod  `xml:"urn:oasis:names:tc:SAML:metadata:algsupport DigestMethod"`

	// ShibbolethScopes are the shibmd:Scope elements an identity provider
	// publishes in its IDPSSODescriptor or AttributeAuthorityDescriptor.
	ShibbolethScopes []ShibbolethScope `xml:"urn:mace:shibboleth:metadata:1.0 Scope"`

	// Other holds the extension elements that have no field of their own.
	Other []ExtensionElement `xml:",any"`
}

// SigningMethod represents the alg:SigningMethod element: an XML Signature
// algorithm the entity supports, with optional bounds on the key size, in
// bits, it supports for that algorithm.
//
// See https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.html §2.4
type SigningMethod struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:metadata:algsupport SigningMethod"`
	Algorithm  string   `xml:"Algorithm,attr"`
	MinKeySize int      `xml:"MinKeySize,attr,omitempty"`
	MaxKeySize int      `xml:"MaxKeySize,attr,omitempty"`
}

// DigestMethod represents the alg:DigestMethod element: an XML Signature
// digest algorithm the entity supports.
//
// See https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-algsupport-v1.0-cs01.html §2.3
type DigestMethod struct {
	XMLName   xml.Name `xml:"urn:oasis:names:tc:SAML:metadata:algsupport DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// ShibbolethMetadataNamespace is the namespace of the Shibboleth metadata
// extensions, such as shibmd:Scope.
const ShibbolethMetadataNamespace = "urn:mace:shibboleth:metadata:1.0"

// ShibbolethScope represents the shibmd:Scope metadata extension element. An
// identity provider uses it to list the security domains (scopes) it is
// authoritative for, such as the "example.com" in a scoped attribute value
// like "staff@example.com". When Regexp is true, Value is a regular
// expression rather than a literal scope.
//
// See https://shibboleth.atlassian.net/wiki/spaces/SC/pages/1912406916/ShibMetaExt
type ShibbolethScope struct {
	XMLName xml.Name `xml:"urn:mace:shibboleth:metadata:1.0 Scope"`
	Regexp  bool     `xml:"regexp,attr"`
	Value   string   `xml:",chardata"`
}

// ExtensionElement is a generic XML element, used for extension elements
// that this package does not model. Names are kept with their namespace URIs
// rather than their prefixes, so the element can be written out again with
// its namespaces intact. Character data is kept, but its position relative to
// child elements (mixed content) is not.
type ExtensionElement struct {
	XMLName  xml.Name
	Attrs    []xml.Attr         `xml:",any,attr"`
	CharData string             `xml:",chardata"`
	Children []ExtensionElement `xml:",any"`
}

// UnmarshalXML implements xml.Unmarshaler
func (m *ExtensionElement) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias ExtensionElement
	if err := d.DecodeElement((*Alias)(m), &start); err != nil {
		return err
	}
	// Drop namespace declarations. The decoder has already resolved names
	// to namespace URIs, and the encoder declares the namespaces it needs;
	// re-encoding the declarations as attributes would produce bogus ones.
	attrs := m.Attrs[:0]
	for _, attr := range m.Attrs {
		if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
			continue
		}
		attrs = append(attrs, attr)
	}
	m.Attrs = attrs
	if len(m.Attrs) == 0 {
		m.Attrs = nil
	}
	// Whitespace between child elements is indentation, not content.
	if len(m.Children) > 0 && strings.TrimSpace(m.CharData) == "" {
		m.CharData = ""
	}
	return nil
}

// KeyInfo represents the XMLSEC object of the same name
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data `xml:"X509Data"`
}

// X509Data represents the XMLSEC object of the same name
type X509Data struct {
	XMLName          xml.Name          `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificates []X509Certificate `xml:"X509Certificate"`
}

// X509Certificate represents the XMLSEC object of the same name
type X509Certificate struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
	Data    string   `xml:",chardata"`
}

// Endpoint represents the SAML EndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.2
type Endpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr,omitempty"`
}

func checkEndpointLocation(binding string, location string) (string, error) {
	// Within the SAML standard, the complex type EndpointType describes a
	// SAML protocol binding endpoint at which a SAML entity can be sent
	// protocol messages. In particular, the location of an endpoint type is
	// defined as follows in the Metadata for the OASIS Security Assertion
	// Markup Language (SAML) V2.0 - 2.2.2 Complex Type EndpointType:
	//
	//   Location [Required] A required URI attribute that specifies the
	//   location of the endpoint. The allowable syntax of this URI depends
	//   on the protocol binding.
	switch binding {
	case HTTPPostBinding,
		HTTPRedirectBinding,
		HTTPArtifactBinding,
		SOAPBinding,
		SOAPBindingV1:
		locationURL, err := url.Parse(location)
		if err != nil {
			return "", fmt.Errorf("invalid url %q: %w", location, err)
		}
		switch locationURL.Scheme {
		case "http", "https":
		// ok
		default:
			return "", fmt.Errorf("invalid url scheme %q for binding %q",
				locationURL.Scheme, binding)
		}
	default:
		// We don't know what form location should take, but the protocol
		// requires that we validate its syntax.
		//
		// In practice, lots of metadata contains random bindings, for example
		// "urn:mace:shibboleth:1.0:profiles:AuthnRequest" from our own test suite.
		//
		// We can't fail, but we also can't allow a location parameter whose syntax we
		// cannot verify. The least-bad course of action here is to set location to
		// and empty string, and hope the caller doesn't care need it.
		location = ""
	}

	return location, nil
}

// UnmarshalXML implements xml.Unmarshaler
func (m *Endpoint) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Endpoint
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}

	var err error
	m.Location, err = checkEndpointLocation(m.Binding, m.Location)
	if err != nil {
		return err
	}
	if m.ResponseLocation != "" {
		m.ResponseLocation, err = checkEndpointLocation(m.Binding, m.ResponseLocation)
		if err != nil {
			return err
		}
	}

	return nil
}

// IndexedEndpoint represents the SAML IndexedEndpointType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.2.3
type IndexedEndpoint struct {
	Binding          string  `xml:"Binding,attr"`
	Location         string  `xml:"Location,attr"`
	ResponseLocation *string `xml:"ResponseLocation,attr,omitempty"`
	Index            int     `xml:"index,attr"`
	IsDefault        *bool   `xml:"isDefault,attr"`
}

// UnmarshalXML implements xml.Unmarshaler
func (m *IndexedEndpoint) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias IndexedEndpoint
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}

	var err error
	m.Location, err = checkEndpointLocation(m.Binding, m.Location)
	if err != nil {
		return err
	}
	if m.ResponseLocation != nil {
		responseLocation, err := checkEndpointLocation(m.Binding, *m.ResponseLocation)
		if err != nil {
			return err
		}
		if responseLocation != "" {
			m.ResponseLocation = &responseLocation
		} else {
			m.ResponseLocation = nil
		}
	}

	return nil
}

// SSODescriptor represents the SAML complex type SSODescriptor
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.2
type SSODescriptor struct {
	RoleDescriptor
	ArtifactResolutionServices []IndexedEndpoint `xml:"ArtifactResolutionService"`
	SingleLogoutServices       []Endpoint        `xml:"SingleLogoutService"`
	ManageNameIDServices       []Endpoint        `xml:"ManageNameIDService"`
	NameIDFormats              []NameIDFormat    `xml:"NameIDFormat"`
}

// IDPSSODescriptor represents the SAML IDPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.3
type IDPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	SSODescriptor
	WantAuthnRequestsSigned *bool `xml:",attr"`

	SingleSignOnServices       []Endpoint  `xml:"SingleSignOnService"`
	ArtifactResolutionServices []Endpoint  `xml:"ArtifactResolutionService"`
	NameIDMappingServices      []Endpoint  `xml:"NameIDMappingService"`
	AssertionIDRequestServices []Endpoint  `xml:"AssertionIDRequestService"`
	AttributeProfiles          []string    `xml:"AttributeProfile"`
	Attributes                 []Attribute `xml:"Attribute"`
}

// MarshalXML implements xml.Marshaler
func (m IDPSSODescriptor) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias IDPSSODescriptor
	validUntil, cacheDuration := marshalRoleDescriptorAttrs(&m.RoleDescriptor)
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		ValidUntil:    validUntil,
		CacheDuration: cacheDuration,
		Signature:     (*etreeElementXML)(m.Signature),
		Alias:         (*Alias)(&m),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (m *IDPSSODescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias IDPSSODescriptor
	// XMLName is declared here, rather than relying on the one in Alias,
	// because encoding/xml does not populate an XMLName field promoted
	// from an embedded struct when decoding.
	aux := &struct {
		XMLName       xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	m.XMLName = aux.XMLName
	unmarshalRoleDescriptorAttrs(&m.RoleDescriptor, aux.ValidUntil, aux.CacheDuration)
	m.Signature = (*etree.Element)(aux.Signature)
	return nil
}

// SPSSODescriptor represents the SAML SPSSODescriptorType object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.2
type SPSSODescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	SSODescriptor
	AuthnRequestsSigned        *bool                       `xml:",attr"`
	WantAssertionsSigned       *bool                       `xml:",attr"`
	AssertionConsumerServices  []IndexedEndpoint           `xml:"AssertionConsumerService"`
	AttributeConsumingServices []AttributeConsumingService `xml:"AttributeConsumingService"`
}

// MarshalXML implements xml.Marshaler
func (m SPSSODescriptor) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias SPSSODescriptor
	validUntil, cacheDuration := marshalRoleDescriptorAttrs(&m.RoleDescriptor)
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		ValidUntil:    validUntil,
		CacheDuration: cacheDuration,
		Signature:     (*etreeElementXML)(m.Signature),
		Alias:         (*Alias)(&m),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (m *SPSSODescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias SPSSODescriptor
	// XMLName is declared here, rather than relying on the one in Alias,
	// because encoding/xml does not populate an XMLName field promoted
	// from an embedded struct when decoding.
	aux := &struct {
		XMLName       xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	m.XMLName = aux.XMLName
	unmarshalRoleDescriptorAttrs(&m.RoleDescriptor, aux.ValidUntil, aux.CacheDuration)
	m.Signature = (*etree.Element)(aux.Signature)
	return nil
}

// AttributeConsumingService represents the SAML AttributeConsumingService object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.4.1
type AttributeConsumingService struct {
	Index               int                  `xml:"index,attr"`
	IsDefault           *bool                `xml:"isDefault,attr"`
	ServiceNames        []LocalizedName      `xml:"ServiceName"`
	ServiceDescriptions []LocalizedName      `xml:"ServiceDescription"`
	RequestedAttributes []RequestedAttribute `xml:"RequestedAttribute"`
}

// RequestedAttribute represents the SAML RequestedAttribute object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.4.2
type RequestedAttribute struct {
	Attribute
	IsRequired *bool `xml:"isRequired,attr"`
}

// AuthnAuthorityDescriptor represents the SAML AuthnAuthorityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.5
type AuthnAuthorityDescriptor struct {
	RoleDescriptor
	AuthnQueryServices         []Endpoint     `xml:"AuthnQueryService"`
	AssertionIDRequestServices []Endpoint     `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat `xml:"NameIDFormat"`
}

// MarshalXML implements xml.Marshaler
func (m AuthnAuthorityDescriptor) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AuthnAuthorityDescriptor
	validUntil, cacheDuration := marshalRoleDescriptorAttrs(&m.RoleDescriptor)
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		ValidUntil:    validUntil,
		CacheDuration: cacheDuration,
		Signature:     (*etreeElementXML)(m.Signature),
		Alias:         (*Alias)(&m),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (m *AuthnAuthorityDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnAuthorityDescriptor
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	unmarshalRoleDescriptorAttrs(&m.RoleDescriptor, aux.ValidUntil, aux.CacheDuration)
	m.Signature = (*etree.Element)(aux.Signature)
	return nil
}

// PDPDescriptor represents the SAML PDPDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.6
type PDPDescriptor struct {
	RoleDescriptor
	AuthzServices              []Endpoint     `xml:"AuthzService"`
	AssertionIDRequestServices []Endpoint     `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat `xml:"NameIDFormat"`
}

// MarshalXML implements xml.Marshaler
func (m PDPDescriptor) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias PDPDescriptor
	validUntil, cacheDuration := marshalRoleDescriptorAttrs(&m.RoleDescriptor)
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		ValidUntil:    validUntil,
		CacheDuration: cacheDuration,
		Signature:     (*etreeElementXML)(m.Signature),
		Alias:         (*Alias)(&m),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (m *PDPDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias PDPDescriptor
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	unmarshalRoleDescriptorAttrs(&m.RoleDescriptor, aux.ValidUntil, aux.CacheDuration)
	m.Signature = (*etree.Element)(aux.Signature)
	return nil
}

// AttributeAuthorityDescriptor represents the SAML AttributeAuthorityDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.4.7
type AttributeAuthorityDescriptor struct {
	RoleDescriptor
	AttributeServices          []Endpoint     `xml:"AttributeService"`
	AssertionIDRequestServices []Endpoint     `xml:"AssertionIDRequestService"`
	NameIDFormats              []NameIDFormat `xml:"NameIDFormat"`
	AttributeProfiles          []string       `xml:"AttributeProfile"`
	Attributes                 []Attribute    `xml:"Attribute"`
}

// MarshalXML implements xml.Marshaler
func (m AttributeAuthorityDescriptor) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AttributeAuthorityDescriptor
	validUntil, cacheDuration := marshalRoleDescriptorAttrs(&m.RoleDescriptor)
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		ValidUntil:    validUntil,
		CacheDuration: cacheDuration,
		Signature:     (*etreeElementXML)(m.Signature),
		Alias:         (*Alias)(&m),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (m *AttributeAuthorityDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AttributeAuthorityDescriptor
	aux := &struct {
		ValidUntil    *RelaxedTime     `xml:"validUntil,attr,omitempty"`
		CacheDuration Duration         `xml:"cacheDuration,attr,omitempty"`
		Signature     *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	unmarshalRoleDescriptorAttrs(&m.RoleDescriptor, aux.ValidUntil, aux.CacheDuration)
	m.Signature = (*etree.Element)(aux.Signature)
	return nil
}

// AffiliationDescriptor represents the SAML AffiliationDescriptor object.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf §2.5
type AffiliationDescriptor struct {
	AffiliationOwnerID string        `xml:"affiliationOwnerID,attr"`
	ID                 string        `xml:",attr"`
	ValidUntil         time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration      time.Duration `xml:"cacheDuration,attr"`
	Signature          *etree.Element
	Extensions         *Extensions     `xml:"urn:oasis:names:tc:SAML:2.0:metadata Extensions,omitempty"`
	AffiliateMembers   []string        `xml:"AffiliateMember"`
	KeyDescriptors     []KeyDescriptor `xml:"KeyDescriptor"`
}

// roleDescriptorXML encodes a RoleDescriptor, which cannot have MarshalXML
// and UnmarshalXML methods itself: they would be inherited by the
// descriptors that embed it.
type roleDescriptorXML RoleDescriptor

// MarshalXML implements xml.Marshaler, writing Signature as XML.
func (m roleDescriptorXML) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias roleDescriptorXML
	aux := &struct {
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Signature: (*etreeElementXML)(m.Signature),
		Alias:     (*Alias)(&m),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler, reading Signature as XML.
func (m *roleDescriptorXML) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias roleDescriptorXML
	aux := &struct {
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	m.Signature = (*etree.Element)(aux.Signature)
	return nil
}

// MarshalXML implements xml.Marshaler, writing Signature as XML.
func (m AffiliationDescriptor) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AffiliationDescriptor
	aux := &struct {
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Signature: (*etreeElementXML)(m.Signature),
		Alias:     (*Alias)(&m),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler, reading Signature as XML.
func (m *AffiliationDescriptor) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AffiliationDescriptor
	aux := &struct {
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	m.Signature = (*etree.Element)(aux.Signature)
	return nil
}
