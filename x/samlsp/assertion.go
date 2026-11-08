package samlsp

import (
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
)

// Assertion is a verified SAML assertion: the identity provider's statement
// about who the user is.
type Assertion struct {
	// ID is the assertion's ID. It is unique, so it can serve as a replay
	// cache key (see WithReplayState).
	ID string

	// Issuer is the entityID of the identity provider.
	Issuer string

	// NameID identifies the user. Keep it, with its Format and
	// qualifiers, for single logout (x/samlsp/slo). It is zero if the
	// assertion identifies the user with a BaseID (see Raw).
	NameID saml.NameID

	// BaseID is the saml:BaseID element that identifies the user instead
	// of a NameID, with AcceptBaseID; its meaning depends on its xsi:type.
	// It is nil otherwise.
	BaseID *etree.Element

	// Subject is NameID.Value. Its meaning depends on NameID.Format: a
	// transient NameID changes with every login.
	Subject string

	// InResponseTo is the ID of the AuthnRequest that the assertion
	// answers. It is empty for an unsolicited response.
	InResponseTo string

	// AuthnInstant is when the IdP authenticated the user.
	AuthnInstant time.Time

	// AuthnContextClassRef is how the IdP authenticated the user, such as
	// "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".
	AuthnContextClassRef AuthnContextClass

	// SessionIndexes name the user's session at the IdP. Keep them to pass
	// to x/samlsp/slo with slo.WithSessionIndex.
	SessionIndexes []string

	// SessionNotOnOrAfter, if not zero, is when the IdP asks the SP to end
	// the session it creates from this assertion.
	SessionNotOnOrAfter time.Time

	// NotOnOrAfter is the NotOnOrAfter of the assertion's Conditions: when
	// the assertion itself stops being valid. It says when the assertion can be
	// accepted, not how long a session may last.
	NotOnOrAfter time.Time

	// Attributes are the attributes the IdP sent about the user.
	Attributes Attributes

	// Raw is the assertion as package saml returned it.
	Raw *saml.Assertion
}

func newAssertion(a *saml.Assertion) *Assertion {
	out := &Assertion{
		ID:     a.ID,
		Issuer: a.Issuer.Value,
		Raw:    a,
	}
	if a.Subject != nil {
		if a.Subject.NameID != nil {
			out.NameID = *a.Subject.NameID
			out.Subject = a.Subject.NameID.Value
		}
		out.BaseID = a.Subject.BaseID
		for _, sc := range a.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil && sc.SubjectConfirmationData.InResponseTo != "" {
				out.InResponseTo = sc.SubjectConfirmationData.InResponseTo
				break
			}
		}
	}
	if a.Conditions != nil {
		out.NotOnOrAfter = a.Conditions.NotOnOrAfter
	}
	for i, s := range a.AuthnStatements {
		if i == 0 {
			out.AuthnInstant = s.AuthnInstant
			if s.AuthnContext.AuthnContextClassRef != nil {
				out.AuthnContextClassRef = AuthnContextClass(s.AuthnContext.AuthnContextClassRef.Value)
			}
		}
		if s.SessionIndex != "" {
			out.SessionIndexes = append(out.SessionIndexes, s.SessionIndex)
		}
		if s.SessionNotOnOrAfter != nil && (out.SessionNotOnOrAfter.IsZero() || s.SessionNotOnOrAfter.Before(out.SessionNotOnOrAfter)) {
			out.SessionNotOnOrAfter = *s.SessionNotOnOrAfter
		}
	}
	for _, st := range a.AttributeStatements {
		out.Attributes = append(out.Attributes, convertAttributes(st.Attributes)...)
	}
	return out
}

// convertAttributes returns attrs as Attributes.
func convertAttributes(attrs []saml.Attribute) Attributes {
	out := make(Attributes, 0, len(attrs))
	for _, attr := range attrs {
		values := make([]string, 0, len(attr.Values))
		types := make([]string, 0, len(attr.Values))
		xmls := make([]string, 0, len(attr.Values))
		hasXML := false
		for _, v := range attr.Values {
			switch {
			case v.Nil:
				continue
			case v.NameID != nil:
				values = append(values, v.NameID.Value)
			default:
				values = append(values, v.Value)
			}
			types = append(types, v.Type)
			xmls = append(xmls, v.XML)
			hasXML = hasXML || v.XML != ""
		}
		if !hasXML {
			xmls = nil
		}
		out = append(out, Attribute{
			Name:         attr.Name,
			FriendlyName: attr.FriendlyName,
			NameFormat:   attr.NameFormat,
			Values:       values,
			Types:        types,
			XML:          xmls,
		})
	}
	return out
}

// Attribute is a SAML attribute, with its values as strings.
type Attribute struct {
	// Name identifies the attribute, as NameFormat says how to read it:
	// for example "urn:oid:0.9.2342.19200300.100.1.3" (mail) with the URI
	// name format.
	Name       string
	NameFormat string

	// FriendlyName is an optional, human-readable form of Name, such as
	// "mail". It is for display only: it does not identify the attribute
	// (saml-core §2.7.3.1), so nothing in this package looks attributes up
	// by it.
	FriendlyName string

	// Values are the attribute's values, as text. A value that is a NameID,
	// such as that of eduPersonTargetedID, is its text content. Values that
	// are null (xsi:nil) are left out.
	Values []string

	// Types are the declared types (xsi:type) of Values, index for index,
	// as written: for example "xs:string" or "xsd:boolean". A type is ""
	// when it is not declared, which many IdPs do. DecodeAttributes does
	// not consult them.
	Types []string

	// XML holds, index for index with Values, the element content of each
	// value of a complex type (an XML structure rather than text), as
	// self-contained XML; it is "" for the usual values of a simple type.
	// Decode such values with an AttributeUnmarshaler. It is nil if no
	// value has element content.
	XML []string
}

// Attributes are the attributes of an assertion.
type Attributes []Attribute

// Values returns the values of every attribute whose Name is name, in the
// order they appear. FriendlyName is not matched.
func (as Attributes) Values(name string) []string {
	var values []string
	for _, a := range as {
		if a.Name == name {
			values = append(values, a.Values...)
		}
	}
	return values
}

// Get returns the first value of the attribute whose Name is name, or "" if
// there is none. FriendlyName is not matched.
func (as Attributes) Get(name string) string {
	if v := as.Values(name); len(v) > 0 {
		return v[0]
	}
	return ""
}
