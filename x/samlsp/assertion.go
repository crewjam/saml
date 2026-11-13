package samlsp

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
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

	// SPEntityID is the entityID of the service provider that accepted
	// the assertion: the entity ID given to New, or the EntityID a
	// ServiceProviderOption set. SubjectKey uses it in place of an omitted
	// SPNameQualifier.
	SPEntityID string

	// NameID identifies the user. Keep it, with its Format and
	// qualifiers, for single logout (x/samlsp/slo). It is zero if the
	// assertion identifies the user with a BaseID (see Raw), or not at
	// all: the identifier is optional (saml-core §2.4.1), and AD FS, for
	// one, sends none unless a claim rule issues a Name ID. Identify the
	// user by an attribute then.
	NameID saml.NameID

	// BaseID is the saml:BaseID element that identifies the user instead
	// of a NameID, with AcceptBaseID; its meaning depends on its xsi:type.
	// It is nil otherwise.
	BaseID *etree.Element

	// Subject is NameID.Value. Its meaning depends on NameID.Format: a
	// transient NameID, which this package requests by default, changes
	// with every login, and even a persistent one is unique only together
	// with the IdP that issued it and its qualifiers (saml-core §8.3.7).
	// It is empty if the assertion has no NameID, or one with an empty
	// value. Show it to people if it suits, but do not key accounts by it:
	// use SubjectKey.
	Subject string

	// InResponseTo is the ID of the AuthnRequest that the assertion
	// answers: the WithRequestID that its bearer SubjectConfirmationData
	// matched (saml-profiles §4.1.4.2), which package saml also requires
	// of the Response. It is empty for an unsolicited response, even if
	// the IdP put an InResponseTo in it that a ValidateRequestID hook
	// accepted.
	InResponseTo string

	// AuthnInstant is when the IdP authenticated the user.
	AuthnInstant time.Time

	// AuthnContextClassRef is how the IdP authenticated the user, such as
	// "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".
	AuthnContextClassRef saml.AuthnContextClass

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

// bearerMethod is the Method of a bearer SubjectConfirmation.
const bearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // a URI, not a credential

// bearerCheck is what package saml checks of a bearer
// SubjectConfirmationData besides its InResponseTo (saml-profiles
// §4.1.4.3): its Recipient, its validity period, allowing skew, at the
// moment of the check, which was between start and end, and its Address
// (see saml.ServiceProvider.ClientAddress), with address.
type bearerCheck struct {
	recipient  string
	skew       time.Duration
	start, end time.Time
	address    func(*saml.SubjectConfirmationData) bool
}

// passes reports whether d passes c.
func (c bearerCheck) passes(d *saml.SubjectConfirmationData) bool {
	return d.Recipient == c.recipient &&
		!d.NotBefore.Add(-c.skew).After(c.end) &&
		c.start.Before(d.NotOnOrAfter.Add(c.skew)) &&
		(c.address == nil || c.address(d))
}

// newAssertion returns the Assertion for a, which package saml verified
// for the service provider spEntityID as answering one of requestIDs, or
// as unsolicited, by a bearer confirmation that passes check.
func newAssertion(a *saml.Assertion, spEntityID string, requestIDs []string, check bearerCheck) *Assertion {
	out := &Assertion{
		ID:         a.ID,
		Issuer:     a.Issuer.Value,
		SPEntityID: spEntityID,
		Raw:        a,
	}
	if a.Subject != nil {
		if a.Subject.NameID != nil {
			out.NameID = *a.Subject.NameID
			out.Subject = a.Subject.NameID.Value
		}
		out.BaseID = a.Subject.BaseID
		// Package saml accepted a bearer confirmation that answers one
		// of requestIDs, or none; report the request it answers. Another
		// confirmation, which package saml did not accept, may name
		// another request.
		for _, sc := range a.Subject.SubjectConfirmations {
			if sc.Method == bearerMethod && sc.SubjectConfirmationData != nil &&
				slices.Contains(requestIDs, sc.SubjectConfirmationData.InResponseTo) &&
				check.passes(sc.SubjectConfirmationData) {
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
				out.AuthnContextClassRef = saml.AuthnContextClass(s.AuthnContext.AuthnContextClassRef.Value)
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

// ErrNoSubjectKey is returned, wrapped, by SubjectKey and SubjectKeyParts
// when the assertion does not identify the user in a way that is stable
// across logins, such as with a transient NameID.
var ErrNoSubjectKey = errors.New("samlsp: the assertion has no stable subject key")

// SubjectKeyParts are the parts of a NameID that together identify a user
// across logins (saml-core §2.2.2, §8.3.7), with the defaults for omitted
// qualifiers filled in. Two SubjectKeyParts identify the same user exactly
// when they are equal (==). The strings are compared byte for byte, without
// any normalization of case or of URLs.
type SubjectKeyParts struct {
	// Issuer is the entityID of the identity provider that issued the
	// assertion.
	Issuer string

	// NameQualifier is the NameID's NameQualifier, or Issuer if it is
	// omitted.
	NameQualifier string

	// SPNameQualifier is the NameID's SPNameQualifier, or the entityID of
	// the service provider (Assertion.SPEntityID) if it is omitted.
	SPNameQualifier string

	// Format is the NameID's Format, or
	// "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" if it is
	// omitted (saml-core §8.3.1).
	Format string

	// Value is the NameID's value.
	Value string
}

// subjectKeyPrefix begins every key that Key returns. It would get a new
// version if the encoding ever changed, so that keys of one encoding never
// equal keys of another.
const subjectKeyPrefix = "samlsp-subject-v1"

// Key returns p encoded as one string, to store and compare as the key of
// a user's account. The encoding is fixed, so that stored keys stay valid:
//
//	samlsp-subject-v1:<n>:<Issuer>:<n>:<NameQualifier>:<n>:<SPNameQualifier>:<n>:<Format>:<n>:<Value>
//
// where each <n> is the length in bytes of the field that follows, in
// decimal without leading zeros, and each field is written as is. The
// lengths make the encoding unambiguous whatever the fields contain,
// colons included. For example, the persistent NameID "abc", with no
// qualifiers, that https://idp.example.com/ issued to
// https://sp.example.com/ has the key
//
//	samlsp-subject-v1:24:https://idp.example.com/:24:https://idp.example.com/:23:https://sp.example.com/:52:urn:oasis:names:tc:SAML:2.0:nameid-format:persistent:3:abc
//
// The key is valid UTF-8 if the fields are, as the text of an XML document
// is. It has no length limit: for a fixed-length column, store a hash of it
// (SHA-256, say).
func (p SubjectKeyParts) Key() string {
	var b strings.Builder
	b.WriteString(subjectKeyPrefix)
	for _, f := range []string{p.Issuer, p.NameQualifier, p.SPNameQualifier, p.Format, p.Value} {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

// SubjectKeyParts returns the parts of the assertion's NameID that
// identify the user across logins, with the defaults of saml-core §8.3.7
// for omitted qualifiers: NameQualifier defaults to Issuer, and
// SPNameQualifier to SPEntityID. The defaults apply whatever the Format,
// so that an IdP that writes a qualifier out and one that omits it give
// the same parts. SPProvidedID is left out: it is an alias that the SP set
// with the Name Identifier Management protocol, not part of the name
// (saml-core §2.2.2, §3.6).
//
// Issuer is always a part, even when NameQualifier is given: a
// NameQualifier is only the IdP's claim, and one IdP must not be able to
// name the users of another.
//
// It returns an error that matches ErrNoSubjectKey if the NameID is
// transient (saml-core §8.3.8), and so changes with every login; if the
// user is identified by a BaseID, whose meaning depends on an xsi:type
// that this package does not interpret, or by nothing; if the NameID's
// value or the Issuer is empty; or if SPNameQualifier is omitted and
// SPEntityID is empty, as it may be in an Assertion that ParseResponse did
// not make.
//
// Other formats are accepted, but are only as stable as the IdP keeps
// them: an email address (saml-core §8.3.2) or an unspecified NameID may
// change when the user's does, or be reassigned to another person. Prefer
// the persistent format (saml.PersistentNameIDFormat, with
// WithNameIDFormat) where the IdP offers it.
func (a *Assertion) SubjectKeyParts() (SubjectKeyParts, error) {
	switch {
	case a.BaseID != nil:
		return SubjectKeyParts{}, fmt.Errorf("%w: the user is identified by a BaseID; derive a key from Assertion.BaseID", ErrNoSubjectKey)
	case a.NameID.Value == "":
		return SubjectKeyParts{}, fmt.Errorf("%w: the assertion has no NameID value", ErrNoSubjectKey)
	case a.NameID.Format == string(saml.TransientNameIDFormat):
		return SubjectKeyParts{}, fmt.Errorf("%w: the NameID is transient, so it changes with every login; request another format with WithNameIDFormat", ErrNoSubjectKey)
	case a.Issuer == "":
		return SubjectKeyParts{}, fmt.Errorf("%w: the assertion has no Issuer", ErrNoSubjectKey)
	}
	p := SubjectKeyParts{
		Issuer:          a.Issuer,
		NameQualifier:   a.NameID.NameQualifier,
		SPNameQualifier: a.NameID.SPNameQualifier,
		Format:          a.NameID.Format,
		Value:           a.NameID.Value,
	}
	if p.NameQualifier == "" {
		p.NameQualifier = a.Issuer
	}
	if p.SPNameQualifier == "" {
		if a.SPEntityID == "" {
			return SubjectKeyParts{}, fmt.Errorf("%w: the NameID has no SPNameQualifier, and the Assertion no SPEntityID", ErrNoSubjectKey)
		}
		p.SPNameQualifier = a.SPEntityID
	}
	if p.Format == "" {
		p.Format = string(saml.UnspecifiedNameIDFormat)
	}
	return p, nil
}

// SubjectKey returns a string that identifies the user across logins, to
// key the user's account by: SubjectKeyParts, encoded by
// SubjectKeyParts.Key, whose encoding is fixed. Unlike Subject, it tells
// apart users of different IdPs, or of different qualifiers of one IdP,
// who share a NameID value.
//
// It returns an error that matches ErrNoSubjectKey if the assertion has no
// stable identifier, such as when its NameID is transient, which is what
// this package requests unless WithNameIDFormat says otherwise.
func (a *Assertion) SubjectKey() (string, error) {
	p, err := a.SubjectKeyParts()
	if err != nil {
		return "", err
	}
	return p.Key(), nil
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

// LegacyMap returns the attributes as a map keyed as the sessions of
// github.com/crewjam/saml/samlsp key them by default: by FriendlyName, or
// by Name when there is none. Attributes that share a key have their
// values merged, in order.
//
// It is for migrating from samlsp, so that configuration that names
// attributes by those keys, such as a FriendlyName like "mail", keeps
// working. Do not use it to decide what a user may do: a FriendlyName does
// not identify an attribute (saml-core §2.7.3.1), so one attribute can
// stand in for another. Use Get, Values or Decode, which match Name.
//
// Unlike samlsp, it leaves out null (xsi:nil) values, as Values does, and
// does not add the session indexes under "SessionIndex"; they are in
// Assertion.SessionIndexes.
//
// Deprecated: LegacyMap exists only to ease the move from samlsp. Name
// attributes by their Name, and use Get, Values or Decode.
func (as Attributes) LegacyMap() map[string][]string {
	m := make(map[string][]string, len(as))
	for _, a := range as {
		key := a.FriendlyName
		if key == "" {
			key = a.Name
		}
		m[key] = append(m[key], a.Values...)
	}
	return m
}

// LegacyGet returns the first value of the attribute whose Name is name,
// or, if there is none, of the first attribute whose FriendlyName is name.
// It returns "" if neither has a value. It is LegacyMap for one attribute,
// with Name first: a setting written for samlsp, which named attributes by
// FriendlyName, keeps matching, and one that names attributes by Name
// matches as Get does.
//
// Deprecated: LegacyGet exists only to ease the move from samlsp. Name
// attributes by their Name, and use Get.
func (as Attributes) LegacyGet(name string) string {
	if v := as.Get(name); v != "" {
		return v
	}
	for _, a := range as {
		if a.FriendlyName == name && len(a.Values) > 0 {
			return a.Values[0]
		}
	}
	return ""
}

// Get returns the first value of the attribute whose Name is name, or "" if
// there is none. FriendlyName is not matched. Which value an IdP sends
// first is not defined: for an attribute that may have several values,
// such as a role or a group, decide on all of them, with Values or a
// slice field of DecodeAttributes, not on the first.
func (as Attributes) Get(name string) string {
	if v := as.Values(name); len(v) > 0 {
		return v[0]
	}
	return ""
}
