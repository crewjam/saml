package samlsp

import (
	"fmt"
	"reflect"
	"time"

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
	// qualifiers, to pass to Config.LogoutRequest. It is zero if the
	// assertion identifies the user with a BaseID (see Raw).
	NameID saml.NameID

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
	// to Config.LogoutRequest with WithSessionIndex.
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
		for _, attr := range st.Attributes {
			values := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				switch {
				case v.Nil:
					continue
				case v.NameID != nil:
					values = append(values, v.NameID.Value)
				default:
					values = append(values, v.Value)
				}
			}
			out.Attributes = append(out.Attributes, Attribute{
				Name:         attr.Name,
				FriendlyName: attr.FriendlyName,
				NameFormat:   attr.NameFormat,
				Values:       values,
			})
		}
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

	Values []string
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

// DecodeAttributes stores the assertion's attributes in the struct that v
// points to. Each field to set has a tag with the Name of its attribute
// (not its FriendlyName, which does not identify it):
//
//	var user struct {
//		Email  string   `saml:"urn:oid:0.9.2342.19200300.100.1.3"`
//		Name   string   `saml:"urn:oid:2.16.840.1.113730.3.1.241"`
//		Groups []string `saml:"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"`
//	}
//	err := assertion.DecodeAttributes(&user)
//
// A string field receives the first value, and a []string field receives
// all values. A field whose attribute is absent is left unchanged.
func (a *Assertion) DecodeAttributes(v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() || rv.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("samlsp: DecodeAttributes needs a non-nil pointer to a struct, not %T", v)
	}
	rv = rv.Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		name, ok := f.Tag.Lookup("saml")
		if !ok || name == "" || name == "-" || !f.IsExported() {
			continue
		}
		values := a.Attributes.Values(name)
		if len(values) == 0 {
			continue
		}
		fv := rv.Field(i)
		switch {
		case fv.Kind() == reflect.String:
			fv.SetString(values[0])
		case fv.Kind() == reflect.Slice && fv.Type().Elem().Kind() == reflect.String:
			s := reflect.MakeSlice(fv.Type(), len(values), len(values))
			for j, value := range values {
				s.Index(j).SetString(value)
			}
			fv.Set(s)
		default:
			return fmt.Errorf("samlsp: DecodeAttributes: field %s has type %s, not string or []string", f.Name, f.Type)
		}
	}
	return nil
}
