package saml

import (
	"bytes"
	"compress/flate"
	"encoding/xml"
	"sort"
	"strconv"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// RequestedAuthnContext represents the SAML object of the same name, an indication of the
// requirements on the authentication process.
//
// The SAML schema allows one or more AuthnContextClassRef elements
// (saml-core section 3.3.2.2.1).
type RequestedAuthnContext struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
	Comparison string   `xml:",attr"`

	// AuthnContextClassRefs lists the requested authentication context
	// classes, in order of preference. When parsing, it holds every
	// AuthnContextClassRef element in the request.
	AuthnContextClassRefs []string `xml:"-"`

	// AuthnContextClassRef is a single requested authentication context
	// class. When marshaling it is used only if AuthnContextClassRefs is
	// empty. When parsing it is set to the first AuthnContextClassRef
	// element.
	//
	// Deprecated: use AuthnContextClassRefs, which can carry more than one
	// value.
	AuthnContextClassRef string `xml:"-"`
}

// ClassRefs returns the requested authentication context classes: the
// values of AuthnContextClassRefs if it is set, otherwise
// AuthnContextClassRef, if that is set.
func (r *RequestedAuthnContext) ClassRefs() []string {
	if len(r.AuthnContextClassRefs) > 0 {
		return r.AuthnContextClassRefs
	}
	if r.AuthnContextClassRef != "" {
		return []string{r.AuthnContextClassRef}
	}
	return nil
}

// Element returns an etree.Element representing the object in XML form.
func (r *RequestedAuthnContext) Element() *etree.Element {
	el := etree.NewElement("samlp:RequestedAuthnContext")
	el.CreateAttr("Comparison", r.Comparison)
	refs := r.ClassRefs()
	if len(refs) == 0 {
		// Preserve the historical output of a single, empty element.
		refs = []string{""}
	}
	for _, ref := range refs {
		elContext := etree.NewElement("saml:AuthnContextClassRef")
		elContext.SetText(ref)
		el.AddChild(elContext)
	}
	return el
}

// MarshalXML implements xml.Marshaler.
func (r RequestedAuthnContext) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type wire struct {
		XMLName               xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
		Comparison            string   `xml:",attr"`
		AuthnContextClassRefs []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	}
	refs := r.ClassRefs()
	if len(refs) == 0 {
		refs = []string{""}
	}
	if start.Name.Space == "" {
		start.Name.Space = "urn:oasis:names:tc:SAML:2.0:protocol"
	}
	return e.EncodeElement(wire{Comparison: r.Comparison, AuthnContextClassRefs: refs}, start)
}

// UnmarshalXML implements xml.Unmarshaler.
func (r *RequestedAuthnContext) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var w struct {
		XMLName               xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
		Comparison            string   `xml:",attr"`
		AuthnContextClassRefs []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	}
	if err := d.DecodeElement(&w, &start); err != nil {
		return err
	}
	*r = RequestedAuthnContext{
		XMLName:               w.XMLName,
		Comparison:            w.Comparison,
		AuthnContextClassRefs: w.AuthnContextClassRefs,
	}
	if len(w.AuthnContextClassRefs) > 0 {
		r.AuthnContextClassRef = w.AuthnContextClassRefs[0]
	}
	return nil
}

// AuthnRequest represents the SAML object of the same name, a request from a service provider
// to authenticate a user.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	Subject               *Subject
	NameIDPolicy          *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Conditions            *Conditions   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	RequestedAuthnContext *RequestedAuthnContext
	Scoping               *Scoping `xml:"urn:oasis:names:tc:SAML:2.0:protocol Scoping"`

	ForceAuthn                     *bool  `xml:",attr"`
	IsPassive                      *bool  `xml:",attr"`
	AssertionConsumerServiceIndex  string `xml:",attr"`
	AssertionConsumerServiceURL    string `xml:",attr"`
	ProtocolBinding                string `xml:",attr"`
	AttributeConsumingServiceIndex string `xml:",attr"`
	ProviderName                   string `xml:",attr"`
}

// LogoutRequest  represents the SAML object of the same name, a request from an IDP
// to destroy a user's session.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type LogoutRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`

	ID           string     `xml:",attr"`
	Version      string     `xml:",attr"`
	IssueInstant time.Time  `xml:",attr"`
	NotOnOrAfter *time.Time `xml:",attr"`
	Destination  string     `xml:",attr"`
	Issuer       *Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       *NameID    `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Signature    *etree.Element

	// EncryptedID is the saml:EncryptedID element that identifies the
	// principal instead of NameID (saml-core-2.0-os §2.2.4 and §3.7.1), or
	// nil. IdpLogoutRequest.Validate and ServiceProvider.ValidateLogoutRequest
	// decrypt it and set NameID to the result, or BaseID if it holds a
	// saml:BaseID.
	EncryptedID *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`

	// BaseID is the saml:BaseID element that identifies the principal
	// instead of NameID (saml-core-2.0-os §2.2.3 and §3.7.1), or nil. It is
	// kept as an element because the content of a BaseID is defined by its
	// xsi:type extension, which this package does not interpret. It is set
	// either as read, or by decrypting an EncryptedID. A request identified
	// by a BaseID is refused unless IdentityProvider.AcceptLogoutRequestBaseID
	// or ServiceProvider.AcceptLogoutRequestBaseID is set.
	BaseID *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`

	// A LogoutRequest carries zero or more SessionIndex elements
	// (saml-core-2.0-os §3.7.1). SessionIndex holds the first one, and
	// AdditionalSessionIndexes holds the rest, in document order. Use
	// AllSessionIndexes to read all of them.
	SessionIndex             *SessionIndex  `xml:"SessionIndex"`
	AdditionalSessionIndexes []SessionIndex `xml:"-"`
}

// AllSessionIndexes returns every SessionIndex of the request: SessionIndex,
// if set, followed by AdditionalSessionIndexes.
func (r *LogoutRequest) AllSessionIndexes() []SessionIndex {
	rv := make([]SessionIndex, 0, 1+len(r.AdditionalSessionIndexes))
	if r.SessionIndex != nil {
		rv = append(rv, *r.SessionIndex)
	}
	return append(rv, r.AdditionalSessionIndexes...)
}

// setSessionIndexes sets SessionIndex to the first of indexes and
// AdditionalSessionIndexes to the rest.
func (r *LogoutRequest) setSessionIndexes(indexes []SessionIndex) {
	r.SessionIndex = nil
	r.AdditionalSessionIndexes = nil
	if len(indexes) > 0 {
		first := indexes[0]
		r.SessionIndex = &first
	}
	if len(indexes) > 1 {
		r.AdditionalSessionIndexes = append([]SessionIndex(nil), indexes[1:]...)
	}
}

// Element returns an etree.Element representing the object in XML form.
func (r *LogoutRequest) Element() *etree.Element {
	el := etree.NewElement("samlp:LogoutRequest")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", formatTime(r.IssueInstant))
	if r.NotOnOrAfter != nil {
		el.CreateAttr("NotOnOrAfter", formatTime(*r.NotOnOrAfter))
	}
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	if r.BaseID != nil {
		el.AddChild(r.BaseID)
	}
	if r.NameID != nil {
		el.AddChild(r.NameID.Element())
	}
	if r.EncryptedID != nil {
		el.AddChild(r.EncryptedID)
	}
	for _, sessionIndex := range r.AllSessionIndexes() {
		el.AddChild(sessionIndex.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (r *LogoutRequest) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias LogoutRequest
	aux := &struct {
		IssueInstant RelaxedTime  `xml:",attr"`
		NotOnOrAfter *RelaxedTime `xml:",attr,omitempty"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// BaseID, NameID and EncryptedID are repeated so that they are
		// written before the SessionIndex elements.
		BaseID         *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`
		NameID         *NameID          `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
		EncryptedID    *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
		SessionIndexes []SessionIndex   `xml:"SessionIndex"`
		*Alias
	}{
		IssueInstant:   RelaxedTime(r.IssueInstant),
		NotOnOrAfter:   (*RelaxedTime)(r.NotOnOrAfter),
		Issuer:         r.Issuer,
		Signature:      (*etreeElementXML)(r.Signature),
		BaseID:         (*etreeElementXML)(r.BaseID),
		NameID:         r.NameID,
		EncryptedID:    (*etreeElementXML)(r.EncryptedID),
		SessionIndexes: r.AllSessionIndexes(),
		Alias:          (*Alias)(r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *LogoutRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias LogoutRequest
	aux := &struct {
		IssueInstant   RelaxedTime      `xml:",attr"`
		NotOnOrAfter   *RelaxedTime     `xml:",attr"`
		Signature      *etreeElementXML `xml:"Signature"`
		BaseID         *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`
		EncryptedID    *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
		SessionIndexes []SessionIndex   `xml:"SessionIndex"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.BaseID = (*etree.Element)(aux.BaseID)
	r.EncryptedID = (*etree.Element)(aux.EncryptedID)
	r.IssueInstant = time.Time(aux.IssueInstant)
	r.NotOnOrAfter = (*time.Time)(aux.NotOnOrAfter)
	r.setSessionIndexes(aux.SessionIndexes)
	return nil
}

// Bytes returns a byte array representation of the LogoutRequest
func (r *LogoutRequest) Bytes() ([]byte, error) {
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())

	buf, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// Deflate returns a compressed byte array of the LogoutRequest
func (r *LogoutRequest) Deflate() ([]byte, error) {
	buf, err := r.Bytes()
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	writer, err := flate.NewWriter(&b, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}

	if _, err := writer.Write(buf); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// Element returns an etree.Element representing the object in XML form.
func (r *AuthnRequest) Element() *etree.Element {
	el := etree.NewElement("samlp:AuthnRequest")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", formatTime(r.IssueInstant))
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	if r.Subject != nil {
		el.AddChild(r.Subject.Element())
	}
	if r.NameIDPolicy != nil {
		el.AddChild(r.NameIDPolicy.Element())
	}
	if r.Conditions != nil {
		el.AddChild(r.Conditions.Element())
	}
	if r.RequestedAuthnContext != nil {
		el.AddChild(r.RequestedAuthnContext.Element())
	}
	if r.Scoping != nil {
		el.AddChild(r.Scoping.Element())
	}
	if r.ForceAuthn != nil {
		el.CreateAttr("ForceAuthn", strconv.FormatBool(*r.ForceAuthn))
	}
	if r.IsPassive != nil {
		el.CreateAttr("IsPassive", strconv.FormatBool(*r.IsPassive))
	}
	if r.AssertionConsumerServiceIndex != "" {
		el.CreateAttr("AssertionConsumerServiceIndex", r.AssertionConsumerServiceIndex)
	}
	if r.AssertionConsumerServiceURL != "" {
		el.CreateAttr("AssertionConsumerServiceURL", r.AssertionConsumerServiceURL)
	}
	if r.ProtocolBinding != "" {
		el.CreateAttr("ProtocolBinding", r.ProtocolBinding)
	}
	if r.AttributeConsumingServiceIndex != "" {
		el.CreateAttr("AttributeConsumingServiceIndex", r.AttributeConsumingServiceIndex)
	}
	if r.ProviderName != "" {
		el.CreateAttr("ProviderName", r.ProviderName)
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (r *AuthnRequest) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias AuthnRequest
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Alias:        (*Alias)(r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *AuthnRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnRequest
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Issuer represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Issuer struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameQualifier   string   `xml:",attr"`
	SPNameQualifier string   `xml:",attr"`
	Format          string   `xml:",attr"`
	SPProvidedID    string   `xml:",attr"`
	Value           string   `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *Issuer) Element() *etree.Element {
	el := etree.NewElement("saml:Issuer")
	if a.NameQualifier != "" {
		el.CreateAttr("NameQualifier", a.NameQualifier)
	}
	if a.SPNameQualifier != "" {
		el.CreateAttr("SPNameQualifier", a.SPNameQualifier)
	}
	if a.Format != "" {
		el.CreateAttr("Format", a.Format)
	}
	if a.SPProvidedID != "" {
		el.CreateAttr("SPProvidedID", a.SPProvidedID)
	}
	el.SetText(a.Value)
	return el
}

// NameIDPolicy represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDPolicy struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format          *string  `xml:",attr"`
	SPNameQualifier *string  `xml:",attr"`
	AllowCreate     *bool    `xml:",attr"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *NameIDPolicy) Element() *etree.Element {
	el := etree.NewElement("samlp:NameIDPolicy")
	if a.Format != nil && *a.Format != "" {
		el.CreateAttr("Format", *a.Format)
	}
	if a.SPNameQualifier != nil {
		el.CreateAttr("SPNameQualifier", *a.SPNameQualifier)
	}
	if a.AllowCreate != nil {
		el.CreateAttr("AllowCreate", strconv.FormatBool(*a.AllowCreate))
	}
	return el
}

// Scoping represents the SAML object of the same name. It lets a requester
// specify the identity providers it trusts to authenticate the presenter,
// which proxying identity providers (gateways) use to pick a delegate IDP.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf § 3.4.1.2
type Scoping struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Scoping"`
	ProxyCount   *int     `xml:",attr"`
	IDPList      *IDPList `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPList"`
	RequesterIDs []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequesterID"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *Scoping) Element() *etree.Element {
	el := etree.NewElement("samlp:Scoping")
	if a.ProxyCount != nil {
		el.CreateAttr("ProxyCount", strconv.Itoa(*a.ProxyCount))
	}
	if a.IDPList != nil {
		el.AddChild(a.IDPList.Element())
	}
	for _, requesterID := range a.RequesterIDs {
		el.CreateElement("samlp:RequesterID").SetText(requesterID)
	}
	return el
}

// IDPList represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf § 3.4.1.3
type IDPList struct {
	XMLName     xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPList"`
	IDPEntries  []IDPEntry `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPEntry"`
	GetComplete string     `xml:"urn:oasis:names:tc:SAML:2.0:protocol GetComplete,omitempty"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *IDPList) Element() *etree.Element {
	el := etree.NewElement("samlp:IDPList")
	for i := range a.IDPEntries {
		el.AddChild(a.IDPEntries[i].Element())
	}
	if a.GetComplete != "" {
		el.CreateElement("samlp:GetComplete").SetText(a.GetComplete)
	}
	return el
}

// IDPEntry represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf § 3.4.1.3.1
type IDPEntry struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol IDPEntry"`
	ProviderID string   `xml:",attr"`
	Name       string   `xml:",attr,omitempty"`
	Loc        string   `xml:",attr,omitempty"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *IDPEntry) Element() *etree.Element {
	el := etree.NewElement("samlp:IDPEntry")
	el.CreateAttr("ProviderID", a.ProviderID)
	if a.Name != "" {
		el.CreateAttr("Name", a.Name)
	}
	if a.Loc != "" {
		el.CreateAttr("Loc", a.Loc)
	}
	return el
}

// ArtifactResolve represents the SAML object of the same name.
type ArtifactResolve struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResolve"`
	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Artifact     string `xml:"urn:oasis:names:tc:SAML:2.0:protocol Artifact"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *ArtifactResolve) Element() *etree.Element {
	el := etree.NewElement("samlp:ArtifactResolve")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")

	// Note: This namespace is not used by any element or attribute name, but
	// is required so that the AttributeValue type element can have a value like
	// "xs:string". If we don't declare it here, then it will be stripped by the
	// cannonicalizer. This could be avoided by providing a prefix list to the
	// cannonicalizer, but prefix lists do not appear to be implemented correctly
	// in some libraries, so the safest action is to always produce XML that is
	// (a) in canonical form and (b) does not require prefix lists.
	el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")

	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", formatTime(r.IssueInstant))
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		// ADFS requires that <Signature> come before <Artifact>.
		// ref: https://github.com/crewjam/saml/issues/535
		// ref: https://www.wiktorzychla.com/2017/09/adfs-and-saml2-artifact-binding-woes.html
		el.AddChild(r.Signature)
	}
	artifact := etree.NewElement("samlp:Artifact")
	artifact.SetText(r.Artifact)
	el.AddChild(artifact)
	return el
}

// SoapRequest returns a SOAP Envelope contining the ArtifactResolve request
func (r *ArtifactResolve) SoapRequest() *etree.Element {
	envelope := etree.NewElement("soapenv:Envelope")
	envelope.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	envelope.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	body := etree.NewElement("soapenv:Body")
	envelope.AddChild(body)
	body.AddChild(r.Element())
	return envelope
}

// MarshalXML implements xml.Marshaler
func (r *ArtifactResolve) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias ArtifactResolve
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Alias:        (*Alias)(r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *ArtifactResolve) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias ArtifactResolve
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// soapEnvelopeNamespace is the namespace of the SOAP 1.1 Envelope, the only
// SOAP version the SAML SOAP binding uses (saml-bindings §3.2.1).
const soapEnvelopeNamespace = "http://schemas.xmlsoap.org/soap/envelope/"

// AttributeQuery represents the SAML object of the same name, a request
// from a service provider to an attribute authority for attributes of a
// subject (saml-core §3.3.2.3).
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeQuery struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AttributeQuery"`

	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Subject names the principal whose attributes are requested.
	Subject *Subject `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`

	// Attributes, if any, names the attributes requested. An Attribute
	// with Values asks only for those values. If empty, the attribute
	// authority returns every attribute the requester may see.
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *AttributeQuery) Element() *etree.Element {
	el := etree.NewElement("samlp:AttributeQuery")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", formatTime(r.IssueInstant))
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	if r.Subject != nil {
		el.AddChild(r.Subject.Element())
	}
	for i := range r.Attributes {
		el.AddChild(r.Attributes[i].Element())
	}
	return el
}

// SoapRequest returns a SOAP 1.1 Envelope containing the AttributeQuery, as
// the SAML SOAP binding sends it (saml-bindings §3.2).
func (r *AttributeQuery) SoapRequest() *etree.Element {
	return soapEnvelope(r.Element())
}

// MarshalXML implements xml.Marshaler
func (r *AttributeQuery) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias AttributeQuery
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Alias:        (*Alias)(r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *AttributeQuery) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AttributeQuery
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// ArtifactResponse represents the SAML object of the same name.
type ArtifactResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResponse"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Status       Status   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Response     Response `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *ArtifactResponse) Element() *etree.Element {
	el := etree.NewElement("samlp:ArtifactResponse")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")

	// Note: This namespace is not used by any element or attribute name, but
	// is required so that the AttributeValue type element can have a value like
	// "xs:string". If we don't declare it here, then it will be stripped by the
	// cannonicalizer. This could be avoided by providing a prefix list to the
	// cannonicalizer, but prefix lists do not appear to be implemented correctly
	// in some libraries, so the safest action is to always produce XML that is
	// (a) in canonical form and (b) does not require prefix lists.
	el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")

	el.CreateAttr("ID", r.ID)
	if r.InResponseTo != "" {
		el.CreateAttr("InResponseTo", r.InResponseTo)
	}
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", formatTime(r.IssueInstant))
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	el.AddChild(r.Status.Element())
	el.AddChild(r.Response.Element())
	return el
}

// MarshalXML implements xml.Marshaler
func (r *ArtifactResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias ArtifactResponse
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Alias:        (*Alias)(r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *ArtifactResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias ArtifactResponse
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Response represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Response struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Status       Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

	// TODO(ross): more than one EncryptedAssertion is allowed
	EncryptedAssertion *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`

	// TODO(ross): more than one Assertion is allowed
	Assertion *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *Response) Element() *etree.Element {
	el := etree.NewElement("samlp:Response")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")

	// Note: This namespace is not used by any element or attribute name, but
	// is required so that the AttributeValue type element can have a value like
	// "xs:string". If we don't declare it here, then it will be stripped by the
	// cannonicalizer. This could be avoided by providing a prefix list to the
	// cannonicalizer, but prefix lists do not appear to be implemented correctly
	// in some libraries, so the safest action is to always produce XML that is
	// (a) in canonical form and (b) does not require prefix lists.
	el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")

	el.CreateAttr("ID", r.ID)
	if r.InResponseTo != "" {
		el.CreateAttr("InResponseTo", r.InResponseTo)
	}
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", formatTime(r.IssueInstant))
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	el.AddChild(r.Status.Element())
	if r.EncryptedAssertion != nil {
		el.AddChild(r.EncryptedAssertion)
	}
	if r.Assertion != nil {
		el.AddChild(r.Assertion.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (r *Response) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias Response
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Status is repeated so that it is written before EncryptedAssertion.
		Status             Status           `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
		EncryptedAssertion *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
		*Alias
	}{
		IssueInstant:       RelaxedTime(r.IssueInstant),
		Issuer:             r.Issuer,
		Signature:          (*etreeElementXML)(r.Signature),
		Status:             r.Status,
		EncryptedAssertion: (*etreeElementXML)(r.EncryptedAssertion),
		Alias:              (*Alias)(r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *Response) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Response
	aux := &struct {
		IssueInstant       RelaxedTime      `xml:",attr"`
		Signature          *etreeElementXML `xml:"Signature"`
		EncryptedAssertion *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.EncryptedAssertion = (*etree.Element)(aux.EncryptedAssertion)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Status represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Status struct {
	XMLName       xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode    StatusCode
	StatusMessage *StatusMessage
	StatusDetail  *StatusDetail
}

// Element returns an etree.Element representing the object in XML form.
func (s *Status) Element() *etree.Element {
	el := etree.NewElement("samlp:Status")
	el.AddChild(s.StatusCode.Element())
	if s.StatusMessage != nil {
		el.AddChild(s.StatusMessage.Element())
	}
	if s.StatusDetail != nil {
		el.AddChild(s.StatusDetail.Element())
	}
	return el
}

// StatusCode represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusCode struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value      string   `xml:",attr"`
	StatusCode *StatusCode
}

// Element returns an etree.Element representing the object in XML form.
func (s *StatusCode) Element() *etree.Element {
	el := etree.NewElement("samlp:StatusCode")
	el.CreateAttr("Value", s.Value)
	if s.StatusCode != nil {
		el.AddChild(s.StatusCode.Element())
	}
	return el
}

// StatusSuccess means the request succeeded. Additional information MAY be returned in the <StatusMessage> and/or <StatusDetail> elements.
//
// TODO(ross): this value is mostly constant, but is mutated in tests. Fix the hacky test so this can be const.
var StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

const (
	// The permissible top-level <StatusCode> values are as follows:

	// StatusRequester means the request could not be performed due to an error on the part of the requester.
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"

	// StatusResponder means the request could not be performed due to an error on the part of the SAML responder or SAML authority.
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"

	// StatusVersionMismatch means the SAML responder could not process the request because the version of the request message was incorrect.
	StatusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

	// The following second-level status codes are referenced at various places in this specification. Additional
	// second-level status codes MAY be defined in future versions of the SAML specification. System entities
	// are free to define more specific status codes by defining appropriate URI references.

	// StatusAuthnFailed means the responding provider was unable to successfully authenticate the principal.
	StatusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	// StatusInvalidAttrNameOrValue means Unexpected or invalid content was encountered within a <saml:Attribute> or <saml:AttributeValue> element.
	StatusInvalidAttrNameOrValue = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"

	// StatusInvalidNameIDPolicy means the responding provider cannot or will not support the requested name identifier policy.
	StatusInvalidNameIDPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"

	// StatusNoAuthnContext means the specified authentication context requirements cannot be met by the responder.
	StatusNoAuthnContext = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"

	// StatusNoAvailableIDP is used by an intermediary to indicate that none of the supported identity provider <Loc> elements in an <IDPList> can be resolved or that none of the supported identity providers are available.
	StatusNoAvailableIDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"

	// StatusNoPassive means Indicates the responding provider cannot authenticate the principal passively, as has been requested.
	StatusNoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive" //nolint:gosec

	// StatusNoSupportedIDP is used by an intermediary to indicate that none of the identity providers in an <IDPList> are supported by the intermediary.
	StatusNoSupportedIDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"

	// StatusPartialLogout is used by a session authority to indicate to a session participant that it was not able to propagate logout to all other session participants.
	StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

	// StatusProxyCountExceeded means Indicates that a responding provider cannot authenticate the principal directly and is not permitted to proxy the request further.
	StatusProxyCountExceeded = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"

	// StatusRequestDenied means the SAML responder or SAML authority is able to process the request but has chosen not to respond. This status code MAY be used when there is concern about the security context of the request message or the sequence of request messages received from a particular requester.
	StatusRequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

	// StatusRequestUnsupported means the SAML responder or SAML authority does not support the request.
	StatusRequestUnsupported = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

	// StatusRequestVersionDeprecated means the SAML responder cannot process any requests with the protocol version specified in the request.
	StatusRequestVersionDeprecated = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated" //nolint:gosec

	// StatusRequestVersionTooHigh means the SAML responder cannot process the request because the protocol version specified in the request message is a major upgrade from the highest protocol version supported by the responder.
	StatusRequestVersionTooHigh = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"

	// StatusRequestVersionTooLow means the SAML responder cannot process the request because the protocol version specified in the request message is too low.
	StatusRequestVersionTooLow = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"

	// StatusResourceNotRecognized means the resource value provided in the request message is invalid or unrecognized.
	StatusResourceNotRecognized = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"

	// StatusTooManyResponses means the response message would contain more elements than the SAML responder is able to return.
	StatusTooManyResponses = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"

	// StatusUnknownAttrProfile means an entity that has no knowledge of a particular attribute profile has been presented with an attribute means drawn from that profile.
	StatusUnknownAttrProfile = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"

	// StatusUnknownPrincipal means the responding provider does not recognize the principal specified or implied by the request.
	StatusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

	// StatusUnsupportedBinding means the SAML responder cannot properly fulfill the request using the protocol binding specified in the request.
	StatusUnsupportedBinding = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)

// StatusMessage represents the SAML element StatusMessage.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.2.2.3
type StatusMessage struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusMessage"`
	Value   string   `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (sm StatusMessage) Element() *etree.Element {
	el := etree.NewElement("samlp:StatusMessage")
	el.SetText(sm.Value)
	return el
}

// StatusDetail represents the SAML element StatusDetail.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.2.2.4
type StatusDetail struct {
	Children []*etree.Element
}

// Element returns an etree.Element representing the object in XML form.
func (sm StatusDetail) Element() *etree.Element {
	el := etree.NewElement("samlp:StatusDetail")
	for _, child := range sm.Children {
		el.AddChild(child)
	}
	return el
}

// MarshalXML implements xml.Marshaler, writing Children as XML.
//
// encoding/xml cannot marshal an *etree.Element itself, so without this
// method the children were written as their struct fields.
func (sm StatusDetail) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	for _, child := range sm.Children {
		if err := encodeEtreeElement(e, child, nil); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// UnmarshalXML implements xml.Unmarshaler, reading every child element into
// Children. Text between the children is ignored.
//
// Each child keeps its prefixes. Namespaces declared on StatusDetail are
// declared again on each child, which no longer has StatusDetail as a
// parent. A prefix declared further out cannot be recovered and is replaced
// by a generated one bound to the same namespace.
func (sm *StatusDetail) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	scope := map[string]string{}
	for _, attr := range start.Attr {
		switch {
		case attr.Name.Space == "xmlns":
			scope[attr.Name.Local] = attr.Value
		case attr.Name.Space == "" && attr.Name.Local == "xmlns":
			scope[""] = attr.Value
		}
	}
	prefixes := make([]string, 0, len(scope))
	for prefix := range scope {
		prefixes = append(prefixes, prefix)
	}
	sort.Strings(prefixes)

	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			child, err := decodeEtreeElement(d, tok, scope)
			if err != nil {
				return err
			}
			for _, prefix := range prefixes {
				key := xmlnsAttrName(prefix)
				if child.SelectAttr(key) == nil {
					child.CreateAttr(key, scope[prefix])
				}
			}
			sm.Children = append(sm.Children, child)
		case xml.EndElement:
			return nil
		}
	}
}

// Assertion represents the SAML element Assertion.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.3.3
type Assertion struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID           string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Version      string    `xml:",attr"`
	Issuer       Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Subject      *Subject
	Conditions   *Conditions `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	// Advice *Advice
	// Statements []Statement
	AuthnStatements []AuthnStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	// AuthzDecisionStatements []AuthzDecisionStatement
	AttributeStatements []AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *Assertion) Element() *etree.Element {
	el := etree.NewElement("saml:Assertion")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("ID", a.ID)
	el.CreateAttr("IssueInstant", formatTime(a.IssueInstant))
	el.AddChild(a.Issuer.Element())
	if a.Signature != nil {
		el.AddChild(a.Signature)
	}
	if a.Subject != nil {
		el.AddChild(a.Subject.Element())
	}
	if a.Conditions != nil {
		el.AddChild(a.Conditions.Element())
	}
	for _, authnStatement := range a.AuthnStatements {
		el.AddChild(authnStatement.Element())
	}
	for _, attributeStatement := range a.AttributeStatements {
		el.AddChild(attributeStatement.Element())
	}
	err := etreeutils.TransformExcC14n(el, canonicalizerPrefixList, false)
	if err != nil {
		panic(err)
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (a *Assertion) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias Assertion
	aux := &struct {
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    Issuer           `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Issuer:    a.Issuer,
		Signature: (*etreeElementXML)(a.Signature),
		Alias:     (*Alias)(a),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (a *Assertion) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Assertion
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.Signature = (*etree.Element)(aux.Signature)
	a.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Subject represents the SAML element Subject.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.4.1
type Subject struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`

	// BaseID is the saml:BaseID element (saml-core §2.2.3) that identifies
	// the subject in place of NameID, or nil. It is kept as an element
	// because the content of a BaseID is defined by its xsi:type extension,
	// which this package does not interpret. It is set either as read, or
	// by decrypting an EncryptedID that holds a BaseID. The service
	// provider refuses an assertion whose Subject is a BaseID unless
	// ServiceProvider.AcceptAssertionBaseID is set.
	BaseID *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`

	NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`

	// EncryptedID is the saml:EncryptedID element (saml-core §2.2.4) that
	// identifies the subject in place of NameID, as received.
	//
	// When the service provider accepts an assertion whose Subject has an
	// EncryptedID, it decrypts it with its decryption keys and sets NameID
	// to the NameID it holds (or BaseID to the BaseID it holds), then
	// clears EncryptedID.
	EncryptedID *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`

	SubjectConfirmations []SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *Subject) Element() *etree.Element {
	el := etree.NewElement("saml:Subject")
	if a.BaseID != nil {
		el.AddChild(a.BaseID.Copy())
	}
	if a.NameID != nil {
		el.AddChild(a.NameID.Element())
	}
	if a.EncryptedID != nil {
		el.AddChild(a.EncryptedID.Copy())
	}
	for _, v := range a.SubjectConfirmations {
		el.AddChild(v.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (a *Subject) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias Subject
	aux := &struct {
		// BaseID, NameID and EncryptedID are repeated so that they are
		// written in the order the schema requires.
		BaseID      *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`
		NameID      *NameID          `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
		EncryptedID *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
		*Alias
	}{
		BaseID:      (*etreeElementXML)(a.BaseID),
		NameID:      a.NameID,
		EncryptedID: (*etreeElementXML)(a.EncryptedID),
		Alias:       (*Alias)(a),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (a *Subject) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Subject
	aux := &struct {
		BaseID      *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion BaseID"`
		EncryptedID *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.XMLName = start.Name
	a.BaseID = (*etree.Element)(aux.BaseID)
	a.EncryptedID = (*etree.Element)(aux.EncryptedID)
	return nil
}

// NameID represents the SAML element NameID.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.2.3
type NameID struct {
	NameQualifier   string `xml:",attr"`
	SPNameQualifier string `xml:",attr"`
	Format          string `xml:",attr"`
	SPProvidedID    string `xml:",attr"`
	Value           string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *NameID) Element() *etree.Element {
	el := etree.NewElement("saml:NameID")
	if a.NameQualifier != "" {
		el.CreateAttr("NameQualifier", a.NameQualifier)
	}
	if a.SPNameQualifier != "" {
		el.CreateAttr("SPNameQualifier", a.SPNameQualifier)
	}
	if a.Format != "" {
		el.CreateAttr("Format", a.Format)
	}
	if a.SPProvidedID != "" {
		el.CreateAttr("SPProvidedID", a.SPProvidedID)
	}
	if a.Value != "" {
		el.SetText(a.Value)
	}
	return el
}

// SessionIndex represents the SAML element SessionIndex.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §3.7.1
type SessionIndex struct {
	Value string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (s *SessionIndex) Element() *etree.Element {
	el := etree.NewElement("samlp:SessionIndex")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	if s.Value != "" {
		el.SetText(s.Value)
	}
	return el
}

// SubjectConfirmation represents the SAML element SubjectConfirmation.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.4.1.1
type SubjectConfirmation struct {
	Method string `xml:",attr"`
	// BaseID               *BaseID  ... TODO
	NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`

	// EncryptedID is the saml:EncryptedID element (saml-core §2.2.4) that
	// identifies the confirming entity in place of NameID, as received. The
	// service provider decrypts it into NameID, as for Subject.EncryptedID.
	EncryptedID *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`

	SubjectConfirmationData *SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *SubjectConfirmation) Element() *etree.Element {
	el := etree.NewElement("saml:SubjectConfirmation")
	el.CreateAttr("Method", a.Method)
	if a.NameID != nil {
		el.AddChild(a.NameID.Element())
	}
	if a.EncryptedID != nil {
		el.AddChild(a.EncryptedID.Copy())
	}
	if a.SubjectConfirmationData != nil {
		el.AddChild(a.SubjectConfirmationData.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (a *SubjectConfirmation) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias SubjectConfirmation
	aux := &struct {
		EncryptedID *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
		*Alias
	}{
		EncryptedID: (*etreeElementXML)(a.EncryptedID),
		Alias:       (*Alias)(a),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (a *SubjectConfirmation) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias SubjectConfirmation
	aux := &struct {
		EncryptedID *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.EncryptedID = (*etree.Element)(aux.EncryptedID)
	return nil
}

// SubjectConfirmationData represents the SAML element SubjectConfirmationData.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.4.1.2
type SubjectConfirmationData struct {
	NotBefore    time.Time `xml:",attr"`
	NotOnOrAfter time.Time `xml:",attr"`
	Recipient    string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Address      string    `xml:",attr"`
}

// Element returns an etree.Element representing the object in XML form.
func (s *SubjectConfirmationData) Element() *etree.Element {
	el := etree.NewElement("saml:SubjectConfirmationData")
	if !s.NotBefore.IsZero() {
		el.CreateAttr("NotBefore", formatTime(s.NotBefore))
	}
	if !s.NotOnOrAfter.IsZero() {
		el.CreateAttr("NotOnOrAfter", formatTime(s.NotOnOrAfter))
	}
	if s.Recipient != "" {
		el.CreateAttr("Recipient", s.Recipient)
	}
	if s.InResponseTo != "" {
		el.CreateAttr("InResponseTo", s.InResponseTo)
	}
	if s.Address != "" {
		el.CreateAttr("Address", s.Address)
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (s *SubjectConfirmationData) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias SubjectConfirmationData
	aux := &struct {
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		NotOnOrAfter: RelaxedTime(s.NotOnOrAfter),
		Alias:        (*Alias)(s),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (s *SubjectConfirmationData) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias SubjectConfirmationData
	aux := &struct {
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	s.NotOnOrAfter = time.Time(aux.NotOnOrAfter)
	return nil
}

// Conditions represents the SAML element Conditions.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.5.1
type Conditions struct {
	NotBefore            time.Time             `xml:",attr"`
	NotOnOrAfter         time.Time             `xml:",attr"`
	AudienceRestrictions []AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	OneTimeUse           *OneTimeUse           `xml:"urn:oasis:names:tc:SAML:2.0:assertion OneTimeUse"`
	ProxyRestriction     *ProxyRestriction     `xml:"urn:oasis:names:tc:SAML:2.0:assertion ProxyRestriction"`

	// UnknownConditions holds, in document order, the names of the child
	// elements of an unmarshalled Conditions that this package does not
	// understand: anything but AudienceRestriction, OneTimeUse and
	// ProxyRestriction, including a saml:Condition extended with xsi:type.
	// saml-core §2.5.1.1 makes such an assertion Indeterminate, so the
	// ServiceProvider rejects it if RejectUnknownConditions is set (or
	// ValidateUnknownConditions refuses it); otherwise they are ignored.
	// Element and MarshalXML do not reproduce these elements.
	UnknownConditions []xml.Name `xml:"-"`
}

// Element returns an etree.Element representing the object in XML form.
func (c *Conditions) Element() *etree.Element {
	el := etree.NewElement("saml:Conditions")
	if !c.NotBefore.IsZero() {
		el.CreateAttr("NotBefore", formatTime(c.NotBefore))
	}
	if !c.NotOnOrAfter.IsZero() {
		el.CreateAttr("NotOnOrAfter", formatTime(c.NotOnOrAfter))
	}
	for _, v := range c.AudienceRestrictions {
		el.AddChild(v.Element())
	}
	if c.OneTimeUse != nil {
		el.AddChild(c.OneTimeUse.Element())
	}
	if c.ProxyRestriction != nil {
		el.AddChild(c.ProxyRestriction.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (c *Conditions) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Conditions
	aux := &struct {
		NotBefore    RelaxedTime `xml:",attr"`
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		NotBefore:    RelaxedTime(c.NotBefore),
		NotOnOrAfter: RelaxedTime(c.NotOnOrAfter),
		Alias:        (*Alias)(c),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (c *Conditions) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Conditions
	aux := &struct {
		NotBefore    RelaxedTime `xml:",attr"`
		NotOnOrAfter RelaxedTime `xml:",attr"`
		Unknown      []struct {
			XMLName xml.Name
		} `xml:",any"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	c.NotBefore = time.Time(aux.NotBefore)
	c.NotOnOrAfter = time.Time(aux.NotOnOrAfter)
	c.UnknownConditions = nil
	for _, el := range aux.Unknown {
		c.UnknownConditions = append(c.UnknownConditions, el.XMLName)
	}
	return nil
}

// AudienceRestriction represents the SAML element AudienceRestriction.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.5.1.4
//
// An AudienceRestriction lists one or more audiences, and is satisfied when
// the relying party is any one of them. Audience holds the first one, and
// AdditionalAudiences holds the rest, in document order.
type AudienceRestriction struct {
	Audience            Audience   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
	AdditionalAudiences []Audience `xml:"-"`
}

// AllAudiences returns every audience in the restriction: Audience followed
// by AdditionalAudiences.
func (a *AudienceRestriction) AllAudiences() []Audience {
	return append([]Audience{a.Audience}, a.AdditionalAudiences...)
}

// Element returns an etree.Element representing the object in XML form.
func (a *AudienceRestriction) Element() *etree.Element {
	el := etree.NewElement("saml:AudienceRestriction")
	for _, v := range a.AllAudiences() {
		el.AddChild(v.Element())
	}
	return el
}

// audienceRestrictionXML is the encoding/xml form of AudienceRestriction,
// with all its Audience elements in one list.
type audienceRestrictionXML struct {
	Audiences []Audience `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// MarshalXML implements xml.Marshaler
func (a *AudienceRestriction) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(audienceRestrictionXML{Audiences: a.AllAudiences()}, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (a *AudienceRestriction) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var aux audienceRestrictionXML
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	*a = AudienceRestriction{}
	if len(aux.Audiences) > 0 {
		a.Audience = aux.Audiences[0]
	}
	if len(aux.Audiences) > 1 {
		a.AdditionalAudiences = aux.Audiences[1:]
	}
	return nil
}

// Audience represents the SAML element Audience.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.5.1.4
type Audience struct {
	Value string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *Audience) Element() *etree.Element {
	el := etree.NewElement("saml:Audience")
	el.SetText(a.Value)
	return el
}

// OneTimeUse represents the SAML element OneTimeUse.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.5.1.5
type OneTimeUse struct{}

// Element returns an etree.Element representing the object in XML form.
func (a *OneTimeUse) Element() *etree.Element {
	return etree.NewElement("saml:OneTimeUse")
}

// ProxyRestriction represents the SAML element ProxyRestriction.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.5.1.6
type ProxyRestriction struct {
	Count     *int       `xml:",attr,omitempty"`
	Audiences []Audience `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *ProxyRestriction) Element() *etree.Element {
	el := etree.NewElement("saml:ProxyRestriction")
	if a.Count != nil {
		el.CreateAttr("Count", strconv.Itoa(*a.Count))
	}
	for _, v := range a.Audiences {
		el.AddChild(v.Element())
	}
	return el
}

// AuthnStatement represents the SAML element AuthnStatement.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.2
type AuthnStatement struct {
	AuthnInstant        time.Time        `xml:",attr"`
	SessionIndex        string           `xml:",attr"`
	SessionNotOnOrAfter *time.Time       `xml:",attr,omitempty"`
	SubjectLocality     *SubjectLocality `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectLocality"`
	AuthnContext        AuthnContext     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *AuthnStatement) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnStatement")
	el.CreateAttr("AuthnInstant", formatTime(a.AuthnInstant))
	if a.SessionIndex != "" {
		el.CreateAttr("SessionIndex", a.SessionIndex)
	}
	if a.SessionNotOnOrAfter != nil {
		el.CreateAttr("SessionNotOnOrAfter", formatTime(*a.SessionNotOnOrAfter))
	}
	if a.SubjectLocality != nil {
		el.AddChild(a.SubjectLocality.Element())
	}
	el.AddChild(a.AuthnContext.Element())
	return el
}

// MarshalXML implements xml.Marshaler
func (a *AuthnStatement) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AuthnStatement
	aux := &struct {
		AuthnInstant        RelaxedTime  `xml:",attr"`
		SessionNotOnOrAfter *RelaxedTime `xml:",attr,omitempty"`
		*Alias
	}{
		AuthnInstant:        RelaxedTime(a.AuthnInstant),
		SessionNotOnOrAfter: (*RelaxedTime)(a.SessionNotOnOrAfter),
		Alias:               (*Alias)(a),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (a *AuthnStatement) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnStatement
	aux := &struct {
		AuthnInstant        RelaxedTime  `xml:",attr"`
		SessionNotOnOrAfter *RelaxedTime `xml:",attr,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.AuthnInstant = time.Time(aux.AuthnInstant)
	a.SessionNotOnOrAfter = (*time.Time)(aux.SessionNotOnOrAfter)
	return nil
}

// SubjectLocality represents the SAML element SubjectLocality.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.2.1
type SubjectLocality struct {
	Address string `xml:",attr"`
	DNSName string `xml:",attr"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *SubjectLocality) Element() *etree.Element {
	el := etree.NewElement("saml:SubjectLocality")
	if a.Address != "" {
		el.CreateAttr("Address", a.Address)
	}
	if a.DNSName != "" {
		el.CreateAttr("DNSName", a.DNSName)
	}
	return el
}

// AuthnContext represents the SAML element AuthnContext.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.2.2
type AuthnContext struct {
	AuthnContextClassRef      *AuthnContextClassRef     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
	AuthenticatingAuthorities []AuthenticatingAuthority `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthenticatingAuthority"`
	// AuthnContextDecl          *AuthnContextDecl        ... TODO
	// AuthnContextDeclRef       *AuthnContextDeclRef     ... TODO
}

// Element returns an etree.Element representing the object in XML form.
func (a *AuthnContext) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnContext")
	if a.AuthnContextClassRef != nil {
		el.AddChild(a.AuthnContextClassRef.Element())
	}

	for _, v := range a.AuthenticatingAuthorities {
		el.AddChild(v.Element())
	}
	return el
}

// AuthnContextClassRef represents the SAML element AuthnContextClassRef.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.2.2
type AuthnContextClassRef struct {
	Value string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *AuthnContextClassRef) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnContextClassRef")
	el.SetText(a.Value)
	return el
}

// AuthenticatingAuthority represents the SAML element AuthenticatingAuthority.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.2.2
type AuthenticatingAuthority struct {
	Value string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *AuthenticatingAuthority) Element() *etree.Element {
	el := etree.NewElement("saml:AuthenticatingAuthority")
	el.SetText(a.Value)
	return el
}

// AttributeStatement represents the SAML element AttributeStatement.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.3
type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *AttributeStatement) Element() *etree.Element {
	el := etree.NewElement("saml:AttributeStatement")
	for _, v := range a.Attributes {
		el.AddChild(v.Element())
	}
	return el
}

// Attribute represents the SAML element Attribute.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.3.1
type Attribute struct {
	FriendlyName string           `xml:",attr"`
	Name         string           `xml:",attr"`
	NameFormat   string           `xml:",attr"`
	Values       []AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *Attribute) Element() *etree.Element {
	el := etree.NewElement("saml:Attribute")
	if a.FriendlyName != "" {
		el.CreateAttr("FriendlyName", a.FriendlyName)
	}
	if a.Name != "" {
		el.CreateAttr("Name", a.Name)
	}
	if a.NameFormat != "" {
		el.CreateAttr("NameFormat", a.NameFormat)
	}
	for _, v := range a.Values {
		el.AddChild(v.Element())
	}
	return el
}

// AttributeValue represents the SAML element AttributeValue.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.3.1.1
type AttributeValue struct {
	Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`

	// Nil reports that the value is a SAML "null" value, carried as
	// xsi:nil="true" (or "1") on an empty element (saml-core §2.7.3.1.1).
	// It distinguishes a null value from an empty string. When Nil is set,
	// Element writes xsi:nil="true" and omits Value and NameID.
	Nil bool `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr,omitempty"`

	// Encoding is the x500:Encoding XML attribute (namespace X500AttributeNamespace)
	// that the X.500/LDAP attribute profile requires on each value, with the
	// value "LDAP" (saml-profiles §8.2.4). It is written only when set.
	Encoding string `xml:"urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500 Encoding,attr,omitempty"`

	Value  string  `xml:",chardata"`
	NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
}

// X500AttributeNamespace is the namespace of the x500:Encoding XML attribute
// defined by the X.500/LDAP attribute profile (saml-profiles §8.2.4).
const X500AttributeNamespace = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"

// X500EncodingLDAP is the x500:Encoding value the X.500/LDAP attribute
// profile requires (saml-profiles §8.2.4).
const X500EncodingLDAP = "LDAP"

// Element returns an etree.Element representing the object in XML form.
func (a *AttributeValue) Element() *etree.Element {
	el := etree.NewElement("saml:AttributeValue")
	el.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	el.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
	if a.Encoding != "" {
		el.CreateAttr("xmlns:x500", X500AttributeNamespace)
	}
	if a.Type != "" {
		el.CreateAttr("xsi:type", a.Type)
	}
	if a.Encoding != "" {
		el.CreateAttr("x500:Encoding", a.Encoding)
	}
	if a.Nil {
		// saml-core §2.7.3.1.1: a null value MUST be an empty element
		// carrying xsi:nil="true" or "1".
		el.CreateAttr("xsi:nil", "true")
		return el
	}
	if a.NameID != nil {
		el.AddChild(a.NameID.Element())
	}
	el.SetText(a.Value)
	return el
}

// LogoutResponse represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type LogoutResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr"`
	Consent      string    `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Status       Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

// Element returns an etree.Element representing the object in XML form.
func (r *LogoutResponse) Element() *etree.Element {
	el := etree.NewElement("samlp:LogoutResponse")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")

	el.CreateAttr("ID", r.ID)
	if r.InResponseTo != "" {
		el.CreateAttr("InResponseTo", r.InResponseTo)
	}
	el.CreateAttr("Version", r.Version)
	el.CreateAttr("IssueInstant", formatTime(r.IssueInstant))
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Consent != "" {
		el.CreateAttr("Consent", r.Consent)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	el.AddChild(r.Status.Element())
	return el
}

// MarshalXML implements xml.Marshaler
func (r *LogoutResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias LogoutResponse
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Alias:        (*Alias)(r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *LogoutResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias LogoutResponse
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}
