package saml

import (
	"bytes"
	"compress/flate"
	"encoding/xml"
	"fmt"
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
	Comparison string   `xml:",attr,omitempty"`

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

	// AuthnContextDeclRefs lists the requested authentication context
	// declarations, which a request may give instead of classes. When
	// parsing, it holds every AuthnContextDeclRef element in the request.
	// It is marshaled only when there are no classes, since the schema
	// allows one kind or the other.
	AuthnContextDeclRefs []string `xml:"-"`
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
	if len(refs) == 0 && len(r.AuthnContextDeclRefs) > 0 {
		for _, ref := range r.AuthnContextDeclRefs {
			el.CreateElement("saml:AuthnContextDeclRef").SetText(ref)
		}
		return el
	}
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
		Comparison            string   `xml:",attr,omitempty"`
		AuthnContextClassRefs []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
		AuthnContextDeclRefs  []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDeclRef"`
	}
	if start.Name.Space == "" {
		start.Name.Space = "urn:oasis:names:tc:SAML:2.0:protocol"
	}
	refs := r.ClassRefs()
	if len(refs) == 0 && len(r.AuthnContextDeclRefs) > 0 {
		return e.EncodeElement(wire{Comparison: r.Comparison, AuthnContextDeclRefs: r.AuthnContextDeclRefs}, start)
	}
	if len(refs) == 0 {
		refs = []string{""}
	}
	return e.EncodeElement(wire{Comparison: r.Comparison, AuthnContextClassRefs: refs}, start)
}

// UnmarshalXML implements xml.Unmarshaler.
func (r *RequestedAuthnContext) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var w struct {
		XMLName               xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
		Comparison            string   `xml:",attr"`
		AuthnContextClassRefs []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
		AuthnContextDeclRefs  []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDeclRef"`
	}
	if err := d.DecodeElement(&w, &start); err != nil {
		return err
	}
	*r = RequestedAuthnContext{
		XMLName:               w.XMLName,
		Comparison:            w.Comparison,
		AuthnContextClassRefs: w.AuthnContextClassRefs,
		AuthnContextDeclRefs:  w.AuthnContextDeclRefs,
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
	Destination  string    `xml:",attr,omitempty"`
	Consent      string    `xml:",attr,omitempty"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions is the samlp:Extensions element, if any, which holds
	// extension elements agreed between the parties (saml-core §3.2.1).
	Extensions *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

	Subject               *Subject
	NameIDPolicy          *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Conditions            *Conditions   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	RequestedAuthnContext *RequestedAuthnContext
	Scoping               *Scoping `xml:"urn:oasis:names:tc:SAML:2.0:protocol Scoping"`

	ForceAuthn                     *bool  `xml:",attr"`
	IsPassive                      *bool  `xml:",attr"`
	AssertionConsumerServiceIndex  string `xml:",attr,omitempty"`
	AssertionConsumerServiceURL    string `xml:",attr,omitempty"`
	ProtocolBinding                string `xml:",attr,omitempty"`
	AttributeConsumingServiceIndex string `xml:",attr,omitempty"`
	ProviderName                   string `xml:",attr,omitempty"`
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
	Destination  string     `xml:",attr,omitempty"`
	Issuer       *Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID       *NameID    `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`

	// Reason, if set, says why the principal is being logged out, as a
	// URI: LogoutReasonUser or LogoutReasonAdmin, or one agreed between
	// the parties (saml-core §3.7.1, §3.7.3).
	Reason    string `xml:",attr,omitempty"`
	Signature *etree.Element

	// Extensions is the samlp:Extensions element, if any, which holds
	// extension elements agreed between the parties (saml-core §3.2.1,
	// §3.2.2). It is kept as read; nothing in this package interprets it.
	Extensions *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

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
	if r.Reason != "" {
		el.CreateAttr("Reason", r.Reason)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		el.AddChild(r.Signature)
	}
	if r.Extensions != nil {
		el.AddChild(r.Extensions.Copy())
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
func (r LogoutRequest) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias LogoutRequest
	aux := &struct {
		IssueInstant RelaxedTime  `xml:",attr"`
		NotOnOrAfter *RelaxedTime `xml:",attr,omitempty"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Extensions is repeated so that it is written after Signature.
		Extensions *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
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
		Extensions:     (*etreeElementXML)(r.Extensions),
		BaseID:         (*etreeElementXML)(r.BaseID),
		NameID:         r.NameID,
		EncryptedID:    (*etreeElementXML)(r.EncryptedID),
		SessionIndexes: r.AllSessionIndexes(),
		Alias:          (*Alias)(&r),
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
		Extensions     *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
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
	r.Extensions = (*etree.Element)(aux.Extensions)
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
	if r.Extensions != nil {
		el.AddChild(r.Extensions.Copy())
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
func (r AuthnRequest) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias AuthnRequest
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Extensions is repeated so that it is written after Signature.
		Extensions *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Extensions:   (*etreeElementXML)(r.Extensions),
		Alias:        (*Alias)(&r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *AuthnRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnRequest
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		Extensions   *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.Extensions = (*etree.Element)(aux.Extensions)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Issuer represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Issuer struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameQualifier   string   `xml:",attr,omitempty"`
	SPNameQualifier string   `xml:",attr,omitempty"`
	Format          string   `xml:",attr,omitempty"`
	SPProvidedID    string   `xml:",attr,omitempty"`
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
	// Destination, if set, is the URL of the ArtifactResolutionService the
	// request is sent to, which the recipient must check (saml-core
	// §3.2.1).
	Destination string  `xml:",attr,omitempty"`
	Issuer      *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature   *etree.Element

	// Extensions is the samlp:Extensions element, if any, which holds
	// extension elements agreed between the parties (saml-core §3.2.1,
	// §3.2.2). It is kept as read; nothing in this package interprets it.
	Extensions *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
	Artifact   string         `xml:"urn:oasis:names:tc:SAML:2.0:protocol Artifact"`
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
	if r.Destination != "" {
		el.CreateAttr("Destination", r.Destination)
	}
	if r.Issuer != nil {
		el.AddChild(r.Issuer.Element())
	}
	if r.Signature != nil {
		// ADFS requires that <Signature> come before <Artifact>.
		// ref: https://github.com/crewjam/saml/issues/535
		// ref: https://www.wiktorzychla.com/2017/09/adfs-and-saml2-artifact-binding-woes.html
		el.AddChild(r.Signature)
	}
	if r.Extensions != nil {
		el.AddChild(r.Extensions.Copy())
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
func (r ArtifactResolve) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias ArtifactResolve
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Extensions is repeated so that it is written after Signature.
		Extensions *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Extensions:   (*etreeElementXML)(r.Extensions),
		Alias:        (*Alias)(&r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *ArtifactResolve) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias ArtifactResolve
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		Extensions   *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.Extensions = (*etree.Element)(aux.Extensions)
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
	Destination  string    `xml:",attr,omitempty"`
	Consent      string    `xml:",attr,omitempty"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions is the samlp:Extensions element, if any, which holds
	// extension elements agreed between the parties (saml-core §3.2.1,
	// §3.2.2). It is kept as read; nothing in this package interprets it.
	Extensions *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`

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
	if r.Extensions != nil {
		el.AddChild(r.Extensions.Copy())
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
func (r AttributeQuery) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias AttributeQuery
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Extensions is repeated so that it is written after Signature.
		Extensions *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Extensions:   (*etreeElementXML)(r.Extensions),
		Alias:        (*Alias)(&r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *AttributeQuery) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AttributeQuery
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		Extensions   *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.Extensions = (*etree.Element)(aux.Extensions)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// ArtifactResponse represents the SAML object of the same name.
type ArtifactResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResponse"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr,omitempty"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions is the samlp:Extensions element, if any, which holds
	// extension elements agreed between the parties (saml-core §3.2.1,
	// §3.2.2). It is kept as read; nothing in this package interprets it.
	Extensions *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
	Status     Status         `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Response   Response       `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
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
	if r.Extensions != nil {
		el.AddChild(r.Extensions.Copy())
	}
	el.AddChild(r.Status.Element())
	el.AddChild(r.Response.Element())
	return el
}

// MarshalXML implements xml.Marshaler
func (r ArtifactResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias ArtifactResponse
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Extensions is repeated so that it is written after Signature.
		Extensions *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Extensions:   (*etreeElementXML)(r.Extensions),
		Alias:        (*Alias)(&r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *ArtifactResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias ArtifactResponse
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		Extensions   *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.Extensions = (*etree.Element)(aux.Extensions)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Response represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Response struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr,omitempty"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr,omitempty"`
	Consent      string    `xml:",attr,omitempty"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions is the samlp:Extensions element, if any, which holds
	// extension elements agreed between the parties (saml-core §3.2.1,
	// §3.2.2). It is kept as read; nothing in this package interprets it, and
	// an assertion inside it is never read as one of the Response's.
	Extensions *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
	Status     Status         `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`

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
	if r.Extensions != nil {
		el.AddChild(r.Extensions.Copy())
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
func (r Response) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias Response
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Extensions is repeated so that it is written after Signature.
		Extensions *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		// Status is repeated so that it is written before EncryptedAssertion.
		Status             Status           `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
		EncryptedAssertion *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
		*Alias
	}{
		IssueInstant:       RelaxedTime(r.IssueInstant),
		Issuer:             r.Issuer,
		Signature:          (*etreeElementXML)(r.Signature),
		Extensions:         (*etreeElementXML)(r.Extensions),
		Status:             r.Status,
		EncryptedAssertion: (*etreeElementXML)(r.EncryptedAssertion),
		Alias:              (*Alias)(&r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *Response) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Response
	aux := &struct {
		IssueInstant       RelaxedTime      `xml:",attr"`
		Signature          *etreeElementXML `xml:"Signature"`
		Extensions         *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		EncryptedAssertion *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.Extensions = (*etree.Element)(aux.Extensions)
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

// The reasons for logout that saml-core §3.7.3 defines, for
// LogoutRequest.Reason.
const (
	// LogoutReasonUser means the user decided to end the session.
	LogoutReasonUser = "urn:oasis:names:tc:SAML:2.0:logout:user"
	// LogoutReasonAdmin means an administrator ended the session.
	LogoutReasonAdmin = "urn:oasis:names:tc:SAML:2.0:logout:admin"
)

// StatusSuccess means the request succeeded. Additional information MAY be returned in the <StatusMessage> and/or <StatusDetail> elements.
//
// It is a variable only so that tests can change it; it must not be
// modified otherwise. Like TimeNow, it is read without synchronization by
// every provider in the program.
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
	scope := newChildScope(start)
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			child, err := scope.decode(d, tok)
			if err != nil {
				return err
			}
			sm.Children = append(sm.Children, child)
		case xml.EndElement:
			return nil
		}
	}
}

// childScope holds the namespaces declared on an element whose children
// are read as detached *etree.Element values.
type childScope struct {
	scope    map[string]string // prefix ("" for the default namespace) to URI
	prefixes []string          // the keys of scope, sorted
}

func newChildScope(start xml.StartElement) childScope {
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
	return childScope{scope: scope, prefixes: prefixes}
}

// decode reads the child that tok starts as an *etree.Element. It keeps
// its prefixes, and the namespaces declared on its parent are declared
// again on it, since it no longer has that parent. A prefix declared
// further out cannot be recovered and is replaced by a generated one bound
// to the same namespace.
func (c childScope) decode(d *xml.Decoder, tok xml.StartElement) (*etree.Element, error) {
	child, err := decodeEtreeElement(d, tok, c.scope)
	if err != nil {
		return nil, err
	}
	for _, prefix := range c.prefixes {
		key := xmlnsAttrName(prefix)
		if child.SelectAttr(key) == nil {
			child.CreateAttr(key, c.scope[prefix])
		}
	}
	return child, nil
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

	// Advice is the saml:Advice element, if any (saml-core §2.6). It holds
	// additional information the issuer chose to include, possibly other
	// assertions. Nothing in this package verifies, validates or trusts
	// what it holds: an assertion inside Advice is never one of the
	// assertions of a Response, and ServiceProvider.ParseResponse returns
	// the outer assertion only. Advice is covered by the signature of the
	// assertion that holds it, but an assertion within it has not been
	// checked in any other way, and its own signature, if any, has not been
	// verified.
	Advice *Advice `xml:"urn:oasis:names:tc:SAML:2.0:assertion Advice"`

	// Statements []Statement
	AuthnStatements []AuthnStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`

	// AuthzDecisionStatements are the saml:AuthzDecisionStatement elements
	// of the assertion (saml-core §2.7.4). They are read and written, but
	// not interpreted by this package.
	AuthzDecisionStatements []AuthzDecisionStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthzDecisionStatement"`

	AttributeStatements []AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// Element returns an etree.Element representing the object in XML form,
// in exclusive canonical form.
//
// It panics if the assertion cannot be canonicalized, which happens when an
// element supplied as an *etree.Element (such as Signature, Subject.BaseID
// or an EncryptedID) uses a namespace prefix that it does not declare. Use
// CanonicalElement to get an error instead.
func (a *Assertion) Element() *etree.Element {
	el, err := a.CanonicalElement()
	if err != nil {
		panic(err)
	}
	return el
}

// CanonicalElement is like Element, but returns an error instead of
// panicking if the assertion cannot be canonicalized.
func (a *Assertion) CanonicalElement() (*etree.Element, error) {
	el := a.element()
	if err := etreeutils.TransformExcC14n(el, canonicalizerPrefixList, false); err != nil {
		return nil, fmt.Errorf("cannot canonicalize assertion: %w", err)
	}
	return el, nil
}

// element is Element without canonicalization, for an assertion held in
// another (in Advice or Evidence), which is canonicalized with it.
func (a *Assertion) element() *etree.Element {
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
	if a.Advice != nil {
		el.AddChild(a.Advice.Element())
	}
	for _, authnStatement := range a.AuthnStatements {
		el.AddChild(authnStatement.Element())
	}
	for i := range a.AuthzDecisionStatements {
		el.AddChild(a.AuthzDecisionStatements[i].Element())
	}
	for _, attributeStatement := range a.AttributeStatements {
		el.AddChild(attributeStatement.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler
func (a Assertion) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias Assertion
	aux := &struct {
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		IssueInstant RelaxedTime      `xml:",attr"`
		Issuer       Issuer           `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature    *etreeElementXML `xml:"Signature"`
		*Alias
	}{
		IssueInstant: RelaxedTime(a.IssueInstant),
		Issuer:       a.Issuer,
		Signature:    (*etreeElementXML)(a.Signature),
		Alias:        (*Alias)(&a),
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
func (a Subject) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
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
		Alias:       (*Alias)(&a),
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
	NameQualifier   string `xml:",attr,omitempty"`
	SPNameQualifier string `xml:",attr,omitempty"`
	Format          string `xml:",attr,omitempty"`
	SPProvidedID    string `xml:",attr,omitempty"`
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
func (a SubjectConfirmation) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias SubjectConfirmation
	aux := &struct {
		EncryptedID *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedID"`
		*Alias
	}{
		EncryptedID: (*etreeElementXML)(a.EncryptedID),
		Alias:       (*Alias)(&a),
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
	Recipient    string    `xml:",attr,omitempty"`
	InResponseTo string    `xml:",attr,omitempty"`
	Address      string    `xml:",attr,omitempty"`
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
func (s SubjectConfirmationData) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias SubjectConfirmationData
	aux := &struct {
		NotBefore    *RelaxedTime `xml:",attr,omitempty"`
		NotOnOrAfter *RelaxedTime `xml:",attr,omitempty"`
		*Alias
	}{
		NotBefore:    optionalRelaxedTime(s.NotBefore),
		NotOnOrAfter: optionalRelaxedTime(s.NotOnOrAfter),
		Alias:        (*Alias)(&s),
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler
func (s *SubjectConfirmationData) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias SubjectConfirmationData
	aux := &struct {
		NotBefore    RelaxedTime `xml:",attr"`
		NotOnOrAfter RelaxedTime `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	s.NotBefore = time.Time(aux.NotBefore)
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
func (c Conditions) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias Conditions
	aux := &struct {
		NotBefore    *RelaxedTime `xml:",attr,omitempty"`
		NotOnOrAfter *RelaxedTime `xml:",attr,omitempty"`
		*Alias
	}{
		NotBefore:    optionalRelaxedTime(c.NotBefore),
		NotOnOrAfter: optionalRelaxedTime(c.NotOnOrAfter),
		Alias:        (*Alias)(&c),
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
func (a AudienceRestriction) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
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
	SessionIndex        string           `xml:",attr,omitempty"`
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
func (a AuthnStatement) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type Alias AuthnStatement
	aux := &struct {
		AuthnInstant        RelaxedTime  `xml:",attr"`
		SessionNotOnOrAfter *RelaxedTime `xml:",attr,omitempty"`
		*Alias
	}{
		AuthnInstant:        RelaxedTime(a.AuthnInstant),
		SessionNotOnOrAfter: (*RelaxedTime)(a.SessionNotOnOrAfter),
		Alias:               (*Alias)(&a),
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
	Address string `xml:",attr,omitempty"`
	DNSName string `xml:",attr,omitempty"`
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
//
// The schema allows, in this order, an AuthnContextClassRef, then either an
// AuthnContextDecl or an AuthnContextDeclRef, then any number of
// AuthenticatingAuthority elements.
type AuthnContext struct {
	AuthnContextClassRef *AuthnContextClassRef `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`

	// AuthnContextDecl is the saml:AuthnContextDecl element, if any: an
	// authentication context declaration given by value. Its content (of
	// type xs:anyType, usually a declaration from one of the schemas of
	// saml-authn-context) is not interpreted by this package, so the whole
	// element is kept as read, with its attributes (such as xsi:type) and
	// children. A namespace prefix that is used only in an attribute value
	// (such as the "ac" of xsi:type="ac:...") may not stay bound: a
	// declaration on an ancestor is not carried over when the element is
	// unmarshalled, and exclusive canonicalization (which a signature on
	// the assertion uses, and which Assertion.Element applies) keeps a
	// declaration only where an element or attribute name uses it.
	AuthnContextDecl *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDecl"`

	// AuthnContextDeclRef is the saml:AuthnContextDeclRef element, if any:
	// a URI that refers to an authentication context declaration.
	AuthnContextDeclRef *AuthnContextDeclRef `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDeclRef"`

	AuthenticatingAuthorities []AuthenticatingAuthority `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthenticatingAuthority"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *AuthnContext) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnContext")
	if a.AuthnContextClassRef != nil {
		el.AddChild(a.AuthnContextClassRef.Element())
	}
	if a.AuthnContextDecl != nil {
		el.AddChild(a.AuthnContextDecl.Copy())
	}
	if a.AuthnContextDeclRef != nil {
		el.AddChild(a.AuthnContextDeclRef.Element())
	}
	for _, v := range a.AuthenticatingAuthorities {
		el.AddChild(v.Element())
	}
	return el
}

// MarshalXML implements xml.Marshaler, writing AuthnContextDecl as XML.
func (a AuthnContext) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	aux := struct {
		AuthnContextClassRef      *AuthnContextClassRef     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
		AuthnContextDecl          *etreeElementXML          `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDecl"`
		AuthnContextDeclRef       *AuthnContextDeclRef      `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDeclRef"`
		AuthenticatingAuthorities []AuthenticatingAuthority `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthenticatingAuthority"`
	}{
		AuthnContextClassRef:      a.AuthnContextClassRef,
		AuthnContextDecl:          (*etreeElementXML)(a.AuthnContextDecl),
		AuthnContextDeclRef:       a.AuthnContextDeclRef,
		AuthenticatingAuthorities: a.AuthenticatingAuthorities,
	}
	return e.EncodeElement(aux, start)
}

// UnmarshalXML implements xml.Unmarshaler, reading AuthnContextDecl as XML.
func (a *AuthnContext) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnContext
	aux := &struct {
		AuthnContextDecl *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextDecl"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(aux, &start); err != nil {
		return err
	}
	a.AuthnContextDecl = (*etree.Element)(aux.AuthnContextDecl)
	return nil
}

// AuthnContextDeclRef represents the SAML element AuthnContextDeclRef.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf §2.7.2.2
type AuthnContextDeclRef struct {
	Value string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *AuthnContextDeclRef) Element() *etree.Element {
	el := etree.NewElement("saml:AuthnContextDeclRef")
	el.SetText(a.Value)
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

// Advice represents the SAML element Advice (saml-core §2.6.1): additional
// information the issuer of an assertion chose to include, such as
// references to, or copies of, the assertions it relied on.
//
// Nothing in Advice is verified or validated by this package; see
// Assertion.Advice.
//
// The schema allows the children in any order. They are kept by kind, and
// written in field order, so the order of children of different kinds is
// not preserved.
type Advice struct {
	// AssertionIDRefs are the values of the saml:AssertionIDRef children.
	AssertionIDRefs []string
	// AssertionURIRefs are the values of the saml:AssertionURIRef children.
	AssertionURIRefs []string
	// Assertions are the saml:Assertion children. None of them has been
	// verified or validated.
	Assertions []Assertion
	// EncryptedAssertions are the saml:EncryptedAssertion children, as read.
	// They are not decrypted.
	EncryptedAssertions []*etree.Element
	// Other holds the children in namespaces other than the SAML assertion
	// namespace (the schema's <any namespace="##other">), as read.
	Other []*etree.Element
}

// Element returns an etree.Element representing the object in XML form.
func (a *Advice) Element() *etree.Element {
	el := etree.NewElement("saml:Advice")
	assertionRefsElement(el, a.AssertionIDRefs, a.AssertionURIRefs, a.Assertions, a.EncryptedAssertions)
	for _, other := range a.Other {
		el.AddChild(other.Copy())
	}
	return el
}

// MarshalXML implements xml.Marshaler.
func (a Advice) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := marshalAssertionRefs(e, a.AssertionIDRefs, a.AssertionURIRefs, a.Assertions, a.EncryptedAssertions); err != nil {
		return err
	}
	for _, other := range a.Other {
		if err := encodeEtreeElement(e, other, nil); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// UnmarshalXML implements xml.Unmarshaler. A child in the SAML assertion
// namespace other than those Advice allows is ignored.
func (a *Advice) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*a = Advice{}
	scope := newChildScope(start)
	return unmarshalAssertionRefs(d, func(tok xml.StartElement) (bool, error) {
		ok, err := unmarshalAssertionRef(d, tok, scope, &a.AssertionIDRefs, &a.AssertionURIRefs, &a.Assertions, &a.EncryptedAssertions)
		if ok || err != nil {
			return ok, err
		}
		if tok.Name.Space == samlAssertionNamespace {
			return false, nil
		}
		el, err := scope.decode(d, tok)
		if err != nil {
			return false, err
		}
		a.Other = append(a.Other, el)
		return true, nil
	})
}

// AuthzDecisionStatement represents the SAML element AuthzDecisionStatement
// (saml-core §2.7.4): the issuer's decision on whether the subject may
// perform Actions on Resource.
type AuthzDecisionStatement struct {
	// Resource is the URI of the resource the decision is about.
	Resource string `xml:",attr"`
	// Decision is AuthzDecisionPermit, AuthzDecisionDeny or
	// AuthzDecisionIndeterminate.
	Decision string `xml:",attr"`
	// Actions are the actions the decision is about; the schema requires
	// at least one.
	Actions []Action `xml:"urn:oasis:names:tc:SAML:2.0:assertion Action"`
	// Evidence, if set, is the evidence the issuer relied on.
	Evidence *Evidence `xml:"urn:oasis:names:tc:SAML:2.0:assertion Evidence"`
}

// The values of AuthzDecisionStatement.Decision (saml-core §2.7.4.1).
const (
	AuthzDecisionPermit        = "Permit"
	AuthzDecisionDeny          = "Deny"
	AuthzDecisionIndeterminate = "Indeterminate"
)

// Element returns an etree.Element representing the object in XML form.
func (a *AuthzDecisionStatement) Element() *etree.Element {
	el := etree.NewElement("saml:AuthzDecisionStatement")
	el.CreateAttr("Resource", a.Resource)
	el.CreateAttr("Decision", a.Decision)
	for i := range a.Actions {
		el.AddChild(a.Actions[i].Element())
	}
	if a.Evidence != nil {
		el.AddChild(a.Evidence.Element())
	}
	return el
}

// Action represents the SAML element Action (saml-core §2.7.4.2).
type Action struct {
	// Namespace is the URI of the namespace Value is interpreted in, such
	// as "urn:oasis:names:tc:SAML:1.0:action:rwedc" (saml-core §8.1). If
	// it is omitted, saml-core §2.7.4.2 says
	// "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation" is in effect.
	Namespace string `xml:",attr,omitempty"`
	Value     string `xml:",chardata"`
}

// Element returns an etree.Element representing the object in XML form.
func (a *Action) Element() *etree.Element {
	el := etree.NewElement("saml:Action")
	if a.Namespace != "" {
		el.CreateAttr("Namespace", a.Namespace)
	}
	el.SetText(a.Value)
	return el
}

// Evidence represents the SAML element Evidence (saml-core §2.7.4.3): the
// assertions an authorization decision relied on. As with Advice, nothing
// in it is verified or validated by this package. Children are kept by
// kind, so the order of children of different kinds is not preserved.
type Evidence struct {
	AssertionIDRefs     []string
	AssertionURIRefs    []string
	Assertions          []Assertion
	EncryptedAssertions []*etree.Element
}

// Element returns an etree.Element representing the object in XML form.
func (a *Evidence) Element() *etree.Element {
	el := etree.NewElement("saml:Evidence")
	assertionRefsElement(el, a.AssertionIDRefs, a.AssertionURIRefs, a.Assertions, a.EncryptedAssertions)
	return el
}

// MarshalXML implements xml.Marshaler.
func (a Evidence) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	if err := marshalAssertionRefs(e, a.AssertionIDRefs, a.AssertionURIRefs, a.Assertions, a.EncryptedAssertions); err != nil {
		return err
	}
	return e.EncodeToken(start.End())
}

// UnmarshalXML implements xml.Unmarshaler. Any other child is ignored.
func (a *Evidence) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*a = Evidence{}
	scope := newChildScope(start)
	return unmarshalAssertionRefs(d, func(tok xml.StartElement) (bool, error) {
		return unmarshalAssertionRef(d, tok, scope, &a.AssertionIDRefs, &a.AssertionURIRefs, &a.Assertions, &a.EncryptedAssertions)
	})
}

// assertionRefsElement adds to el the children that Advice and Evidence
// have in common.
func assertionRefsElement(el *etree.Element, idRefs, uriRefs []string, assertions []Assertion, encrypted []*etree.Element) {
	for _, ref := range idRefs {
		el.CreateElement("saml:AssertionIDRef").SetText(ref)
	}
	for _, ref := range uriRefs {
		el.CreateElement("saml:AssertionURIRef").SetText(ref)
	}
	for i := range assertions {
		el.AddChild(assertions[i].element())
	}
	for _, ea := range encrypted {
		el.AddChild(ea.Copy())
	}
}

// marshalAssertionRefs writes the children that Advice and Evidence have
// in common.
func marshalAssertionRefs(e *xml.Encoder, idRefs, uriRefs []string, assertions []Assertion, encrypted []*etree.Element) error {
	for _, ref := range idRefs {
		if err := e.EncodeElement(ref, xml.StartElement{Name: xml.Name{Space: samlAssertionNamespace, Local: "AssertionIDRef"}}); err != nil {
			return err
		}
	}
	for _, ref := range uriRefs {
		if err := e.EncodeElement(ref, xml.StartElement{Name: xml.Name{Space: samlAssertionNamespace, Local: "AssertionURIRef"}}); err != nil {
			return err
		}
	}
	for i := range assertions {
		if err := e.Encode(&assertions[i]); err != nil {
			return err
		}
	}
	for _, ea := range encrypted {
		if err := encodeEtreeElement(e, ea, nil); err != nil {
			return err
		}
	}
	return nil
}

// unmarshalAssertionRefs reads the children of an element up to its end,
// calling child for each one. A child that child does not read (it
// returns false) is skipped.
func unmarshalAssertionRefs(d *xml.Decoder, child func(tok xml.StartElement) (bool, error)) error {
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			read, err := child(tok)
			if err != nil {
				return err
			}
			if !read {
				if err := d.Skip(); err != nil {
					return err
				}
			}
		case xml.EndElement:
			return nil
		}
	}
}

// unmarshalAssertionRef reads tok, a child of Advice or Evidence, into the
// slice for its kind, reporting whether it was one of those kinds.
func unmarshalAssertionRef(d *xml.Decoder, tok xml.StartElement, scope childScope, idRefs, uriRefs *[]string, assertions *[]Assertion, encrypted *[]*etree.Element) (bool, error) {
	if tok.Name.Space != samlAssertionNamespace {
		return false, nil
	}
	switch tok.Name.Local {
	case "AssertionIDRef", "AssertionURIRef":
		var ref string
		if err := d.DecodeElement(&ref, &tok); err != nil {
			return false, err
		}
		if tok.Name.Local == "AssertionIDRef" {
			*idRefs = append(*idRefs, ref)
		} else {
			*uriRefs = append(*uriRefs, ref)
		}
	case "Assertion":
		var assertion Assertion
		if err := d.DecodeElement(&assertion, &tok); err != nil {
			return false, err
		}
		*assertions = append(*assertions, assertion)
	case "EncryptedAssertion":
		el, err := scope.decode(d, tok)
		if err != nil {
			return false, err
		}
		*encrypted = append(*encrypted, el)
	default:
		return false, nil
	}
	return true, nil
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
	FriendlyName string           `xml:",attr,omitempty"`
	Name         string           `xml:",attr"`
	NameFormat   string           `xml:",attr,omitempty"`
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
	Type string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr,omitempty"`

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

	// XML holds the element content of a value of a complex type, such as
	// an attribute whose values are XML structures (saml-core §2.7.3.1.1):
	// its child elements, other than a NameID, as XML in which each element
	// declares the namespaces that were in scope for it, so that prefixes in
	// its names and in QName values (such as xsi:type) still resolve.
	// Value then holds only the text directly inside the AttributeValue.
	// XML is empty for a value of a simple type, which is the usual case.
	//
	// The ServiceProvider sets XML on the assertions it returns; plain
	// xml.Unmarshal does not. When the value is written by Element, XML
	// is added after any NameID; if XML is not well-formed, Element leaves
	// it out, since it cannot return an error.
	XML string `xml:"-"`
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
	el.SetText(a.Value)
	if a.NameID != nil {
		el.AddChild(a.NameID.Element())
	}
	if a.XML != "" {
		doc := etree.NewDocument()
		if err := doc.ReadFromString(a.XML); err == nil {
			for _, child := range doc.Child {
				if child, ok := child.(*etree.Element); ok {
					el.AddChild(child)
				}
			}
		}
	}
	return el
}

// LogoutResponse represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type LogoutResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr,omitempty"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Destination  string    `xml:",attr,omitempty"`
	Consent      string    `xml:",attr,omitempty"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element

	// Extensions is the samlp:Extensions element, if any, which holds
	// extension elements agreed between the parties (saml-core §3.2.1,
	// §3.2.2). It is kept as read; nothing in this package interprets it.
	Extensions *etree.Element `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
	Status     Status         `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
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
	if r.Extensions != nil {
		el.AddChild(r.Extensions.Copy())
	}
	el.AddChild(r.Status.Element())
	return el
}

// MarshalXML implements xml.Marshaler
func (r LogoutResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	type Alias LogoutResponse
	aux := &struct {
		IssueInstant RelaxedTime `xml:",attr"`
		// Issuer is repeated so that it is written before Signature, as
		// the schema requires.
		Issuer    *Issuer          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
		Signature *etreeElementXML `xml:"Signature"`
		// Extensions is repeated so that it is written after Signature.
		Extensions *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		IssueInstant: RelaxedTime(r.IssueInstant),
		Issuer:       r.Issuer,
		Signature:    (*etreeElementXML)(r.Signature),
		Extensions:   (*etreeElementXML)(r.Extensions),
		Alias:        (*Alias)(&r),
	}
	return e.Encode(aux)
}

// UnmarshalXML implements xml.Unmarshaler
func (r *LogoutResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias LogoutResponse
	aux := &struct {
		IssueInstant RelaxedTime      `xml:",attr"`
		Signature    *etreeElementXML `xml:"Signature"`
		Extensions   *etreeElementXML `xml:"urn:oasis:names:tc:SAML:2.0:protocol Extensions"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.Signature = (*etree.Element)(aux.Signature)
	r.Extensions = (*etree.Element)(aux.Extensions)
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}
