package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
)

// An idpProfile makes a test IdP issue assertions shaped like those of a
// well-known IdP product: its entity ID, attribute names, NameID format,
// IDs, validity window, which elements are signed, and encryption
// algorithms. SPs often depend on
// these, by accident or design, so testing against each shape catches
// problems before a customer's real IdP does.
//
// The profiles imitate what these products send by default, as seen in
// their responses; gosaml.dev is not affiliated with their makers.
type idpProfile struct {
	Key         string
	Name        string
	Description string

	// Signing is the IdPConfig.ResponseSigning the profile sets.
	Signing string

	// SessionIndexIsAssertionID makes each assertion's SessionIndex its
	// own ID, as Entra ID does.
	SessionIndexIsAssertionID bool

	// Encryption is the IdPConfig.Encryption the profile sets.
	Encryption string

	// NewID makes the IDs of assertions, and NewSessionIndex the session
	// indexes of IdP sessions, in the profile's style. Either may be nil
	// for the default.
	NewID           func() string
	NewSessionIndex func() string

	// NotBefore and NotOnOrAfter, if not zero, set the assertion's
	// Conditions relative to its IssueInstant.
	NotBefore, NotOnOrAfter time.Duration
}

var idpProfiles = []idpProfile{
	{
		Key: "generic", Name: "Generic",
		Description: "This library's own defaults: the entity ID is the metadata URL, attributes have both URN and simple names, and both the Response and the assertion are signed.",
		Encryption:  "auto",
		Signing:     "both",
	},
	{
		Key: "okta", Name: "Okta-like",
		Description:     `Okta's shape: an entity ID like http://www.okta.com/exk…, IDs like id8495…, attributes named email, firstName, lastName and groups with the unspecified name format, an unspecified NameID holding the email address, both the Response and the assertion signed, and AES-256-CBC encryption.`,
		Encryption:      "cbc256",
		Signing:         "both",
		NewID:           func() string { return "id" + randomDigits(26) },
		NewSessionIndex: func() string { return "id" + randomDigits(26) + "_" + randomDigits(8) },
		NotBefore:       -5 * time.Minute, NotOnOrAfter: 5 * time.Minute,
	},
	{
		Key: "entra", Name: "Entra ID-like",
		Description:               `Microsoft Entra ID's shape: an entity ID like https://sts.windows.net/{tenant}/, assertion IDs that are _ and a GUID, each the session index of its assertion, claims named by schemas.xmlsoap.org and schemas.microsoft.com URIs with no name format, an emailAddress NameID, a validity of 70 minutes, only the assertion signed (not the Response), and AES-256-CBC encryption. That last pair is what SPs that refuse AES-CBC in an unsigned Response trip on.`,
		Encryption:                "cbc256",
		Signing:                   "assertion",
		NewID:                     func() string { return "_" + newGUID() },
		NewSessionIndex:           func() string { return "_" + newGUID() },
		SessionIndexIsAssertionID: true,
		NotBefore:                 -5 * time.Minute, NotOnOrAfter: 70 * time.Minute,
	},
	{
		Key: "shibboleth", Name: "Shibboleth-like",
		Description:     `Shibboleth IdP's shape: an entity ID ending in /idp/shibboleth, transient NameIDs, eduPerson and inetOrgPerson attributes named by urn:oid with the URI name format and friendly names, scoped eduPersonPrincipalName and pairwise-id (different for each SP), a shibmd:Scope in the metadata, only the Response signed (not the assertion), and AES-128-GCM encryption.`,
		Encryption:      "gcm128",
		Signing:         "response",
		NewID:           func() string { return "_" + randomHex(16) },
		NewSessionIndex: func() string { return "_" + randomHex(16) },
		NotOnOrAfter:    5 * time.Minute,
	},
}

func profileByKey(key string) idpProfile {
	for _, p := range idpProfiles {
		if p.Key == key {
			return p
		}
	}
	return idpProfiles[0]
}

// idpEntityIDFor returns the entity ID (Issuer) of an IdP: the metadata
// URL, or one shaped like the profile's product.
func (s *Server) idpEntityIDFor(id string, cfg *IdPConfig) string {
	switch cfg.Profile {
	case "okta":
		return "http://www.okta.com/exk" + cfg.ProfileKey
	case "entra":
		return "https://sts.windows.net/" + cfg.ProfileKey + "/"
	case "shibboleth":
		return s.BaseURL + "/idp/" + id + "/idp/shibboleth"
	}
	return s.idpEntityID(id)
}

// shibbolethScope is the scope of a Shibboleth-like IdP's scoped
// attributes, as published in its metadata.
func shibbolethScope(id string) string { return id + ".gosaml.dev" }

// assertionOption returns the WithAssertion that shapes an assertion as
// the profile does, or nil.
func (p idpProfile) assertionOption() samlidp.ResponseOption {
	if p.NewID == nil && !p.SessionIndexIsAssertionID && p.NotBefore == 0 && p.NotOnOrAfter == 0 {
		return nil
	}
	return samlidp.WithAssertion(func(a *saml.Assertion) error {
		if p.NewID != nil {
			a.ID = p.NewID()
		}
		if p.SessionIndexIsAssertionID {
			// Message.Participant follows, so single logout names it.
			for i := range a.AuthnStatements {
				a.AuthnStatements[i].SessionIndex = a.ID
			}
		}
		if a.Conditions != nil {
			if p.NotBefore != 0 {
				a.Conditions.NotBefore = a.IssueInstant.Add(p.NotBefore)
			}
			if p.NotOnOrAfter != 0 {
				a.Conditions.NotOnOrAfter = a.IssueInstant.Add(p.NotOnOrAfter)
			}
		}
		return nil
	})
}

// profileUsers returns the default users of an IdP with the profile.
func profileUsers(profile string, cfg *IdPConfig, id string) []User {
	type person struct {
		username, given, family string
		groups                  []string
	}
	people := []person{
		{"alice", "Alice", "Anderson", []string{"admins", "users"}},
		{"bob", "Bob", "Brown", []string{"users"}},
		{"carol", "Carol", "Clark", nil},
	}
	var users []User
	for _, p := range people {
		var u User
		switch profile {
		case "okta":
			mail := p.username + "@example.com"
			u = User{Username: p.username, NameID: mail, NameIDFormat: string(saml.UnspecifiedNameIDFormat), Attributes: []samlidp.Attribute{
				unspecifiedAttr("email", mail),
				unspecifiedAttr("firstName", p.given),
				unspecifiedAttr("lastName", p.family),
			}}
			if len(p.groups) > 0 {
				a := unspecifiedAttr("groups", "")
				a.Values = p.groups
				u.Attributes = append(u.Attributes, a)
			}
		case "entra":
			upn := p.username + "@contoso.example"
			tenant := cfg.ProfileKey
			u = User{Username: p.username, NameID: upn, NameIDFormat: string(saml.EmailAddressNameIDFormat), Attributes: []samlidp.Attribute{
				{Name: "http://schemas.microsoft.com/identity/claims/tenantid", Values: []string{tenant}},
				{Name: "http://schemas.microsoft.com/identity/claims/objectidentifier", Values: []string{stableGUID(tenant, p.username)}},
				{Name: "http://schemas.microsoft.com/identity/claims/displayname", Values: []string{p.given + " " + p.family}},
				{Name: "http://schemas.microsoft.com/identity/claims/identityprovider", Values: []string{"https://sts.windows.net/" + tenant + "/"}},
				{Name: "http://schemas.microsoft.com/claims/authnmethodsreferences", Values: []string{"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"}},
				{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", Values: []string{p.given}},
				{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", Values: []string{p.family}},
				{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Values: []string{upn}},
				{Name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", Values: []string{upn}},
			}}
			if len(p.groups) > 0 {
				var ids []string
				for _, g := range p.groups {
					ids = append(ids, stableGUID(tenant, "group:"+g))
				}
				u.Attributes = append(u.Attributes, samlidp.Attribute{Name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", Values: ids})
			}
		case "shibboleth":
			scope := shibbolethScope(id)
			mail := p.username + "@" + scope
			affiliation := []string{"member", "staff"}
			if len(p.groups) == 0 {
				affiliation = []string{"member", "student"}
			}
			var scoped []string
			for _, a := range affiliation {
				scoped = append(scoped, a+"@"+scope)
			}
			u = User{Username: p.username, NameID: p.username, NameIDFormat: string(saml.TransientNameIDFormat), Attributes: []samlidp.Attribute{
				uriAttr("urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "eduPersonPrincipalName", p.username+"@"+scope),
				// Its value is made for each SP when a Response is (see
				// pairwiseAttributes); this one is a placeholder.
				uriAttr(pairwiseIDName, "pairwise-id", "per-sp@"+scope),
				uriAttr("urn:oid:0.9.2342.19200300.100.1.1", "uid", p.username),
				uriAttr("urn:oid:0.9.2342.19200300.100.1.3", "mail", mail),
				uriAttr("urn:oid:2.5.4.42", "givenName", p.given),
				uriAttr("urn:oid:2.5.4.4", "sn", p.family),
				uriAttr("urn:oid:2.16.840.1.113730.3.1.241", "displayName", p.given+" "+p.family),
				{Name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.1", FriendlyName: "eduPersonAffiliation", NameFormat: uriNameFormat, Values: affiliation},
				{Name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.9", FriendlyName: "eduPersonScopedAffiliation", NameFormat: uriNameFormat, Values: scoped},
			}}
		default:
			return defaultUsers()
		}
		users = append(users, u)
	}
	return users
}

const uriNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

func unspecifiedAttr(name, value string) samlidp.Attribute {
	return samlidp.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified", Values: []string{value}}
}

// applyProfile resets an IdP's settings and users to the profile's.
func applyProfile(cfg *IdPConfig, id, profile string) {
	p := profileByKey(profile)
	cfg.Profile = p.Key
	switch p.Key {
	case "okta":
		cfg.ProfileKey = randomAlnum(16)
	case "entra":
		cfg.ProfileKey = newGUID()
	default:
		cfg.ProfileKey = ""
	}
	cfg.Encryption = p.Encryption
	cfg.ResponseSigning = p.Signing
	cfg.SignatureMethod = "sha256"
	cfg.Users = profileUsers(p.Key, cfg, id)
}

func randomDigits(n int) string {
	var b strings.Builder
	for range n {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteByte(byte('0' + d.Int64()))
	}
	return b.String()
}

func randomAlnum(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b strings.Builder
	for range n {
		i, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b.WriteByte(alphabet[i.Int64()])
	}
	return b.String()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newGUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant
	return formatGUID(b)
}

// stableGUID derives a GUID from its inputs, so a user keeps the same
// object ID across edits.
func stableGUID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x50 // version 5-like: name-based
	b[8] = b[8]&0x3f | 0x80
	return formatGUID(b)
}

func formatGUID(b []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// pairwiseIDName is the SAML pairwise-id attribute
// (saml-subject-id-attr-v1.0 §3.4).
const pairwiseIDName = "urn:oasis:names:tc:SAML:attribute:pairwise-id"

// pairwiseID is the unique part of a pairwise-id value: opaque, stable
// for the user at this IdP, and different for each SP, so that SPs cannot
// correlate a user by it.
func pairwiseID(idpID, username, sp string) string {
	sum := sha256.Sum256([]byte("pairwise\x00" + idpID + "\x00" + username + "\x00" + sp))
	return strings.ToUpper(hex.EncodeToString(sum[:16]))
}

// pairwiseAttributes returns attrs with the value of a pairwise-id
// attribute, if any, made for the SP sp: its scope (after the "@") is
// kept, and the part before it computed.
func pairwiseAttributes(attrs []samlidp.Attribute, idpID, username, sp string) []samlidp.Attribute {
	out := make([]samlidp.Attribute, len(attrs))
	copy(out, attrs)
	for i, a := range out {
		if a.Name != pairwiseIDName || len(a.Values) == 0 {
			continue
		}
		scope := a.Values[0]
		if at := strings.LastIndex(scope, "@"); at >= 0 {
			scope = scope[at+1:]
		}
		out[i].Values = []string{pairwiseID(idpID, username, sp) + "@" + scope}
	}
	return out
}
