package inspect

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 fingerprints are what IdP consoles display
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
)

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	nsSOAP11    = "http://schemas.xmlsoap.org/soap/envelope/"
)

// Certificate describes an X.509 certificate found in a message.
type Certificate struct {
	// Where says where in the message it is, such as "Signature of
	// Response" or "KeyDescriptor use=signing (IDPSSODescriptor)".
	Where string `json:"where"`

	Subject   string `json:"subject,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
	Serial    string `json:"serial,omitempty"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter  string `json:"notAfter,omitempty"`
	Key       string `json:"key,omitempty"`
	SHA1      string `json:"sha1,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	PEM       string `json:"pem,omitempty"`
	Expired   bool   `json:"expired,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Signature describes an XML signature found in a message. It is not
// verified.
type Signature struct {
	// Signs is the element the signature is in, which it should sign,
	// such as "Response ID=_abc".
	Signs string `json:"signs"`

	ReferenceURI     string `json:"referenceURI"`
	ReferenceMatches bool   `json:"referenceMatches"`
	SignatureMethod  string `json:"signatureMethod"`
	DigestMethod     string `json:"digestMethod"`
	Canonicalization string `json:"canonicalization"`
	Transforms       string `json:"transforms,omitempty"`
	HasCertificate   bool   `json:"hasCertificate"`
}

// parseXML describes an XML document.
func parseXML(doc []byte, param, encoding string, now time.Time) *Message {
	msg := &Message{Parameter: param, Encoding: encoding, Type: "unknown"}
	d := etree.NewDocument()
	d.ReadSettings.Permissive = false
	if err := d.ReadFromBytes(doc); err != nil {
		msg.Error = "not well-formed XML: " + err.Error()
		msg.XML = string(doc)
		return msg
	}
	root := d.Root()
	if root == nil {
		msg.Error = "the document has no root element"
		return msg
	}
	msg.XML = Pretty(doc)

	if root.Tag == "Envelope" && root.NamespaceURI() == nsSOAP11 {
		msg.Sections = append(msg.Sections, Section{Title: "SOAP envelope", Rows: []KV{{"Namespace", nsSOAP11}}})
		if body := child(root, nsSOAP11, "Body"); body != nil && len(body.ChildElements()) > 0 {
			root = body.ChildElements()[0]
		}
	}

	msg.Type = root.Tag
	msg.Namespace = root.NamespaceURI()
	d2 := &describer{msg: msg, now: now}
	d2.describe(root, "")
	d2.signatures(root)
	d2.certificates(root)
	return msg
}

type describer struct {
	msg *Message
	now time.Time
}

func (d *describer) warn(format string, args ...any) {
	d.msg.Warnings = append(d.msg.Warnings, fmt.Sprintf(format, args...))
}

func (d *describer) section(title string, rows []KV) {
	var kept []KV
	for _, r := range rows {
		if r.V != "" {
			kept = append(kept, r)
		}
	}
	if len(kept) > 0 {
		d.msg.Sections = append(d.msg.Sections, Section{Title: title, Rows: kept})
	}
}

// describe adds the sections of el, whose titles start with prefix.
func (d *describer) describe(el *etree.Element, prefix string) {
	ns := el.NamespaceURI()
	switch {
	case ns == nsProtocol && el.Tag == "AuthnRequest":
		var v saml.AuthnRequest
		if d.unmarshal(el, &v) {
			d.authnRequest(&v, prefix)
		}
	case ns == nsProtocol && el.Tag == "Response":
		var v saml.Response
		if d.unmarshal(el, &v) {
			d.header(prefix+"Response", v.ID, v.IssueInstant, v.Destination, v.InResponseTo, v.Issuer, v.Version)
			d.status(prefix, v.Status)
		}
		d.responseBody(el, prefix)
	case ns == nsProtocol && el.Tag == "LogoutRequest":
		var v saml.LogoutRequest
		if d.unmarshal(el, &v) {
			d.logoutRequest(&v, prefix)
		}
	case ns == nsProtocol && el.Tag == "LogoutResponse":
		var v saml.LogoutResponse
		if d.unmarshal(el, &v) {
			d.header(prefix+"LogoutResponse", v.ID, v.IssueInstant, v.Destination, v.InResponseTo, v.Issuer, v.Version)
			d.status(prefix, v.Status)
		}
	case ns == nsProtocol && el.Tag == "ArtifactResolve":
		var v saml.ArtifactResolve
		if d.unmarshal(el, &v) {
			d.header(prefix+"ArtifactResolve", v.ID, v.IssueInstant, "", "", v.Issuer, v.Version)
			d.section(prefix+"Artifact", []KV{{"Artifact", v.Artifact}})
		}
	case ns == nsProtocol && el.Tag == "ArtifactResponse":
		var v saml.ArtifactResponse
		if d.unmarshal(el, &v) {
			d.header(prefix+"ArtifactResponse", v.ID, v.IssueInstant, "", v.InResponseTo, v.Issuer, v.Version)
			d.status(prefix, v.Status)
		}
		for _, c := range el.ChildElements() {
			if c.NamespaceURI() == nsProtocol && c.Tag != "Status" && c.Tag != "Extensions" {
				d.describe(c, prefix+"Resolved "+c.Tag+": ")
			}
		}
	case ns == nsAssertion && el.Tag == "Assertion":
		d.assertion(el, prefix)
	case ns == nsAssertion && el.Tag == "EncryptedAssertion":
		d.encrypted(el, prefix+"EncryptedAssertion")
	case ns == nsMetadata && el.Tag == "EntityDescriptor":
		var v saml.EntityDescriptor
		if d.unmarshal(el, &v) {
			d.entityDescriptor(&v, prefix)
		}
	case ns == nsMetadata && el.Tag == "EntitiesDescriptor":
		var v saml.EntitiesDescriptor
		if d.unmarshal(el, &v) {
			d.entitiesDescriptor(&v, prefix)
		}
	default:
		var rows []KV
		for _, a := range el.Attr {
			if a.Space != "xmlns" && a.Key != "xmlns" {
				rows = append(rows, KV{a.FullKey(), a.Value})
			}
		}
		rows = append(rows, KV{"Namespace", ns})
		d.section(prefix+el.Tag, rows)
		if !strings.HasPrefix(ns, "urn:oasis:names:tc:SAML:") {
			d.warn("%s is not a SAML 2.0 element", el.Tag)
		}
	}
}

// unmarshal reads el into v with the library's types. el is detached
// with the namespaces it inherits, so it can be read on its own.
func (d *describer) unmarshal(el *etree.Element, v any) bool {
	doc := etree.NewDocument()
	doc.SetRoot(detach(el))
	b, err := doc.WriteToBytes()
	if err == nil {
		err = xml.Unmarshal(b, v)
	}
	if err != nil {
		d.warn("cannot read %s with the saml package: %v", el.Tag, err)
		return false
	}
	return true
}

// detach returns a copy of el that declares the namespaces el inherits
// from its ancestors.
func detach(el *etree.Element) *etree.Element {
	c := el.Copy()
	declared := map[string]bool{}
	for _, a := range c.Attr {
		if a.Space == "xmlns" {
			declared[a.Key] = true
		} else if a.Space == "" && a.Key == "xmlns" {
			declared[""] = true
		}
	}
	for p := el.Parent(); p != nil; p = p.Parent() {
		for _, a := range p.Attr {
			switch {
			case a.Space == "xmlns" && !declared[a.Key]:
				declared[a.Key] = true
				c.CreateAttr("xmlns:"+a.Key, a.Value)
			case a.Space == "" && a.Key == "xmlns" && !declared[""]:
				declared[""] = true
				c.CreateAttr("xmlns", a.Value)
			}
		}
	}
	return c
}

func child(el *etree.Element, ns, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			out = append(out, c)
		}
	}
	return out
}

func (d *describer) header(title, id string, issueInstant time.Time, destination, inResponseTo string, issuer *saml.Issuer, version string) {
	rows := []KV{
		{"ID", id},
		{"IssueInstant", d.when(issueInstant)},
		{"Issuer", issuerString(issuer)},
		{"Destination", destination},
		{"InResponseTo", inResponseTo},
	}
	if version != "2.0" {
		rows = append(rows, KV{"Version", version + " (expected 2.0)"})
	}
	d.section(title, rows)
	if id == "" {
		d.warn("%s has no ID", title)
	}
	if issuer == nil || issuer.Value == "" {
		d.warn("%s has no Issuer", title)
	}
	d.checkIssueInstant(title, issueInstant)
}

func (d *describer) checkIssueInstant(what string, t time.Time) {
	if t.IsZero() {
		return
	}
	switch age := d.now.Sub(t); {
	case age < -3*time.Minute:
		d.warn("%s was issued %s in the future: check the issuer's clock", what, roundDuration(-age))
	case age > 5*time.Minute:
		d.warn("%s was issued %s ago; most relying parties accept messages for only a few minutes", what, roundDuration(age))
	}
}

func issuerString(i *saml.Issuer) string {
	if i == nil {
		return ""
	}
	s := strings.TrimSpace(i.Value)
	if i.Format != "" && i.Format != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" {
		s += " (Format " + i.Format + ")"
	}
	return s
}

func (d *describer) status(prefix string, s saml.Status) {
	code := s.StatusCode.Value
	rows := []KV{{"StatusCode", code}}
	if s.StatusCode.StatusCode != nil {
		rows = append(rows, KV{"Second-level StatusCode", s.StatusCode.StatusCode.Value})
	}
	if s.StatusMessage != nil {
		rows = append(rows, KV{"StatusMessage", s.StatusMessage.Value})
	}
	if s.StatusDetail != nil {
		rows = append(rows, KV{"StatusDetail", "(present)"})
	}
	d.section(prefix+"Status", rows)
	if code != saml.StatusSuccess {
		second := ""
		if s.StatusCode.StatusCode != nil {
			second = " / " + shortURN(s.StatusCode.StatusCode.Value)
		}
		d.warn("the status is %s%s, not Success", shortURN(code), second)
	}
}

func (d *describer) authnRequest(v *saml.AuthnRequest, prefix string) {
	d.header(prefix+"AuthnRequest", v.ID, v.IssueInstant, v.Destination, "", v.Issuer, v.Version)
	rows := []KV{
		{"ProviderName", v.ProviderName},
		{"AssertionConsumerServiceURL", v.AssertionConsumerServiceURL},
		{"AssertionConsumerServiceIndex", v.AssertionConsumerServiceIndex},
		{"ProtocolBinding", v.ProtocolBinding},
		{"AttributeConsumingServiceIndex", v.AttributeConsumingServiceIndex},
		{"ForceAuthn", boolPtr(v.ForceAuthn)},
		{"IsPassive", boolPtr(v.IsPassive)},
	}
	d.section(prefix+"Request", rows)
	if v.AssertionConsumerServiceURL != "" && v.AssertionConsumerServiceIndex != "" {
		d.warn("the request has both AssertionConsumerServiceURL and AssertionConsumerServiceIndex, which saml-core §3.4.1 forbids")
	}
	if p := v.NameIDPolicy; p != nil {
		d.section(prefix+"NameIDPolicy", []KV{
			{"Format", strPtr(p.Format)},
			{"SPNameQualifier", strPtr(p.SPNameQualifier)},
			{"AllowCreate", boolPtr(p.AllowCreate)},
		})
	}
	if rac := v.RequestedAuthnContext; rac != nil {
		comparison := rac.Comparison
		if comparison == "" {
			comparison = "exact (default)"
		}
		d.section(prefix+"RequestedAuthnContext", []KV{
			{"Comparison", comparison},
			{"AuthnContextClassRef", strings.Join(rac.AuthnContextClassRefs, "\n")},
		})
	}
	if v.Subject != nil {
		d.subject(v.Subject, prefix+"Requested Subject")
	}
	if s := v.Scoping; s != nil {
		var rows []KV
		if s.ProxyCount != nil {
			rows = append(rows, KV{"ProxyCount", strconv.Itoa(*s.ProxyCount)})
		}
		if s.IDPList != nil {
			for _, e := range s.IDPList.IDPEntries {
				rows = append(rows, KV{"IDPEntry", e.ProviderID})
			}
		}
		for _, r := range s.RequesterIDs {
			rows = append(rows, KV{"RequesterID", r})
		}
		d.section(prefix+"Scoping", rows)
	}
	if v.Conditions != nil {
		d.conditions(v.Conditions, prefix+"Conditions")
	}
}

func (d *describer) logoutRequest(v *saml.LogoutRequest, prefix string) {
	d.header(prefix+"LogoutRequest", v.ID, v.IssueInstant, v.Destination, "", v.Issuer, v.Version)
	rows := []KV{{"Reason", v.Reason}}
	if v.NotOnOrAfter != nil {
		rows = append(rows, KV{"NotOnOrAfter", d.when(*v.NotOnOrAfter)})
		if !d.now.Before(*v.NotOnOrAfter) {
			d.warn("the LogoutRequest expired %s ago (NotOnOrAfter)", roundDuration(d.now.Sub(*v.NotOnOrAfter)))
		}
	}
	if v.NameID != nil {
		rows = append(rows, nameIDRows(v.NameID)...)
	}
	if v.EncryptedID != nil {
		rows = append(rows, KV{"EncryptedID", "(encrypted: the NameID can be read only with the recipient's private key)"})
	}
	if v.BaseID != nil {
		rows = append(rows, KV{"BaseID", v.BaseID.SelectAttrValue("xsi:type", "(present)")})
	}
	var idx []string
	if v.SessionIndex != nil {
		idx = append(idx, v.SessionIndex.Value)
	}
	for _, s := range v.AdditionalSessionIndexes {
		idx = append(idx, s.Value)
	}
	rows = append(rows, KV{"SessionIndex", strings.Join(idx, "\n")})
	d.section(prefix+"Logout", rows)
}

// responseBody describes the assertions of a Response, read as elements
// since a Response may hold several.
func (d *describer) responseBody(el *etree.Element, prefix string) {
	assertions := children(el, nsAssertion, "Assertion")
	encrypted := children(el, nsAssertion, "EncryptedAssertion")
	for i, a := range assertions {
		p := prefix
		if len(assertions)+len(encrypted) > 1 {
			p = fmt.Sprintf("%sAssertion %d: ", prefix, i+1)
		}
		d.assertion(a, p)
	}
	for i, e := range encrypted {
		title := prefix + "EncryptedAssertion"
		if len(encrypted) > 1 {
			title = fmt.Sprintf("%s %d", title, i+1)
		}
		d.encrypted(e, title)
	}

	responseSigned := child(el, nsDSig, "Signature") != nil
	anyAssertionSigned := false
	for _, a := range assertions {
		if child(a, nsDSig, "Signature") != nil {
			anyAssertionSigned = true
		}
	}
	switch {
	case len(assertions) == 0 && len(encrypted) == 0:
		// An error Response, described by its status.
	case !responseSigned && !anyAssertionSigned && len(encrypted) == 0:
		d.warn("neither the Response nor its assertion is signed: a service provider must refuse it")
	case !responseSigned && len(encrypted) > 0:
		d.msg.Warnings = append(d.msg.Warnings, "the Response is not signed and its assertion is encrypted: whether the assertion is signed can be seen only once it is decrypted")
	}
	if len(assertions)+len(encrypted) > 1 {
		d.warn("the Response carries %d assertions; most service providers accept exactly one", len(assertions)+len(encrypted))
	}
}

func (d *describer) assertion(el *etree.Element, prefix string) {
	var a saml.Assertion
	if !d.unmarshal(el, &a) {
		return
	}
	rows := []KV{
		{"ID", a.ID},
		{"IssueInstant", d.when(a.IssueInstant)},
		{"Issuer", issuerString(&a.Issuer)},
		{"Signed", yesNo(child(el, nsDSig, "Signature") != nil)},
	}
	d.section(prefix+"Assertion", rows)
	d.checkIssueInstant("the assertion", a.IssueInstant)
	if a.Subject != nil {
		d.subject(a.Subject, prefix+"Subject")
	} else {
		d.warn("the assertion has no Subject")
	}
	if a.Conditions != nil {
		d.conditions(a.Conditions, prefix+"Conditions")
	}
	for i, s := range a.AuthnStatements {
		title := prefix + "AuthnStatement"
		if len(a.AuthnStatements) > 1 {
			title = fmt.Sprintf("%s %d", title, i+1)
		}
		rows := []KV{
			{"AuthnInstant", d.when(s.AuthnInstant)},
			{"SessionIndex", s.SessionIndex},
		}
		if s.SessionNotOnOrAfter != nil {
			rows = append(rows, KV{"SessionNotOnOrAfter", d.when(*s.SessionNotOnOrAfter)})
		}
		if s.AuthnContext.AuthnContextClassRef != nil {
			rows = append(rows, KV{"AuthnContextClassRef", s.AuthnContext.AuthnContextClassRef.Value})
		}
		for _, aa := range s.AuthnContext.AuthenticatingAuthorities {
			rows = append(rows, KV{"AuthenticatingAuthority", aa.Value})
		}
		if s.SubjectLocality != nil {
			rows = append(rows, KV{"SubjectLocality", strings.TrimSpace(s.SubjectLocality.Address + " " + s.SubjectLocality.DNSName)})
		}
		d.section(title, rows)
	}
	var attrs []KV
	for _, st := range a.AttributeStatements {
		for _, at := range st.Attributes {
			attrs = append(attrs, KV{attributeLabel(at), attributeValues(at)})
		}
	}
	if len(attrs) > 0 {
		d.msg.Sections = append(d.msg.Sections, Section{Title: prefix + "Attributes", Rows: attrs})
	}
}

func attributeLabel(a saml.Attribute) string {
	label := a.Name
	if a.FriendlyName != "" && a.FriendlyName != a.Name {
		label = a.FriendlyName + " (" + a.Name + ")"
	}
	return label
}

func attributeValues(a saml.Attribute) string {
	var vals []string
	for _, v := range a.Values {
		switch {
		case v.Nil:
			vals = append(vals, "(nil)")
		case v.NameID != nil:
			vals = append(vals, "NameID "+v.NameID.Value)
		default:
			vals = append(vals, v.Value)
		}
	}
	if len(vals) == 0 {
		return "(no values)"
	}
	return strings.Join(vals, "\n")
}

func nameIDRows(n *saml.NameID) []KV {
	return []KV{
		{"NameID", n.Value},
		{"Format", n.Format},
		{"NameQualifier", n.NameQualifier},
		{"SPNameQualifier", n.SPNameQualifier},
		{"SPProvidedID", n.SPProvidedID},
	}
}

func (d *describer) subject(s *saml.Subject, title string) {
	var rows []KV
	if s.NameID != nil {
		rows = append(rows, nameIDRows(s.NameID)...)
	}
	if s.EncryptedID != nil {
		rows = append(rows, KV{"EncryptedID", "(encrypted: the NameID can be read only with the recipient's private key)"})
	}
	if s.BaseID != nil {
		rows = append(rows, KV{"BaseID", s.BaseID.SelectAttrValue("xsi:type", "(present)")})
	}
	for _, c := range s.SubjectConfirmations {
		rows = append(rows, KV{"SubjectConfirmation", c.Method})
		if cd := c.SubjectConfirmationData; cd != nil {
			rows = append(rows,
				KV{"  Recipient", cd.Recipient},
				KV{"  InResponseTo", cd.InResponseTo},
				KV{"  Address", cd.Address})
			if !cd.NotBefore.IsZero() {
				rows = append(rows, KV{"  NotBefore", d.when(cd.NotBefore)})
			}
			if !cd.NotOnOrAfter.IsZero() {
				rows = append(rows, KV{"  NotOnOrAfter", d.when(cd.NotOnOrAfter)})
				if !d.now.Before(cd.NotOnOrAfter) {
					d.warn("the SubjectConfirmationData expired %s ago (NotOnOrAfter)", roundDuration(d.now.Sub(cd.NotOnOrAfter)))
				}
			}
		}
	}
	d.section(title, rows)
}

func (d *describer) conditions(c *saml.Conditions, title string) {
	var rows []KV
	if !c.NotBefore.IsZero() {
		rows = append(rows, KV{"NotBefore", d.when(c.NotBefore)})
		if d.now.Before(c.NotBefore) {
			d.warn("the assertion is not valid for another %s (NotBefore): check the issuer's clock", roundDuration(c.NotBefore.Sub(d.now)))
		}
	}
	if !c.NotOnOrAfter.IsZero() {
		rows = append(rows, KV{"NotOnOrAfter", d.when(c.NotOnOrAfter)})
		if !d.now.Before(c.NotOnOrAfter) {
			d.warn("the assertion expired %s ago (Conditions NotOnOrAfter)", roundDuration(d.now.Sub(c.NotOnOrAfter)))
		}
	}
	for _, ar := range c.AudienceRestrictions {
		auds := []string{ar.Audience.Value}
		for _, a := range ar.AdditionalAudiences {
			auds = append(auds, a.Value)
		}
		rows = append(rows, KV{"Audience", strings.Join(auds, "\n")})
	}
	if c.OneTimeUse != nil {
		rows = append(rows, KV{"OneTimeUse", "yes"})
	}
	if c.ProxyRestriction != nil {
		rows = append(rows, KV{"ProxyRestriction", "yes"})
	}
	for _, u := range c.UnknownConditions {
		rows = append(rows, KV{"Unknown condition", u.Space + " " + u.Local})
		d.warn("the conditions include %s, which a strict service provider cannot evaluate and must refuse (saml-core §2.5.1.1)", u.Local)
	}
	d.section(title, rows)
}

func (d *describer) encrypted(el *etree.Element, title string) {
	rows := []KV{}
	ed := el.FindElement("./EncryptedData")
	if ed != nil {
		if m := ed.FindElement("./EncryptionMethod"); m != nil {
			alg := m.SelectAttrValue("Algorithm", "")
			rows = append(rows, KV{"Data encryption", algorithmName(alg)})
			if strings.Contains(alg, "-cbc") {
				d.warn("the assertion is encrypted with AES-CBC, which has no integrity protection; hardened service providers accept it only in a signed Response")
			}
		}
	}
	for _, ek := range el.FindElements(".//EncryptedKey") {
		if m := ek.FindElement("./EncryptionMethod"); m != nil {
			rows = append(rows, KV{"Key transport", algorithmName(m.SelectAttrValue("Algorithm", ""))})
			if dm := m.FindElement("./DigestMethod"); dm != nil {
				rows = append(rows, KV{"  OAEP digest", algorithmName(dm.SelectAttrValue("Algorithm", ""))})
			}
		}
		if r := ek.SelectAttrValue("Recipient", ""); r != "" {
			rows = append(rows, KV{"  Recipient", r})
		}
	}
	rows = append(rows, KV{"Contents", "encrypted to the service provider's key: it can be read only with that key"})
	d.section(title, rows)
}

func (d *describer) entityDescriptor(v *saml.EntityDescriptor, prefix string) {
	rows := []KV{{"entityID", v.EntityID}, {"ID", v.ID}}
	if !v.ValidUntil.IsZero() {
		rows = append(rows, KV{"validUntil", d.when(v.ValidUntil)})
		if !d.now.Before(v.ValidUntil) {
			d.warn("the metadata expired %s ago (validUntil)", roundDuration(d.now.Sub(v.ValidUntil)))
		}
	}
	if v.CacheDuration != 0 {
		rows = append(rows, KV{"cacheDuration", v.CacheDuration.String()})
	}
	var roles []string
	if len(v.IDPSSODescriptors) > 0 {
		roles = append(roles, "identity provider")
	}
	if len(v.SPSSODescriptors) > 0 {
		roles = append(roles, "service provider")
	}
	if len(v.AttributeAuthorityDescriptors) > 0 {
		roles = append(roles, "attribute authority")
	}
	rows = append(rows, KV{"Roles", strings.Join(roles, ", ")})
	d.section(prefix+"EntityDescriptor", rows)
	if v.EntityID == "" {
		d.warn("the EntityDescriptor has no entityID")
	}

	for i, idp := range v.IDPSSODescriptors {
		title := prefix + "IDPSSODescriptor"
		if len(v.IDPSSODescriptors) > 1 {
			title = fmt.Sprintf("%s %d", title, i+1)
		}
		rows := []KV{
			{"protocolSupportEnumeration", idp.ProtocolSupportEnumeration},
			{"WantAuthnRequestsSigned", boolPtr(idp.WantAuthnRequestsSigned)},
		}
		for _, e := range idp.SingleSignOnServices {
			rows = append(rows, KV{"SingleSignOnService", endpoint(e.Binding, e.Location)})
		}
		rows = append(rows, d.ssoDescriptorRows(idp.SSODescriptor)...)
		for _, a := range idp.Attributes {
			rows = append(rows, KV{"Attribute", attributeLabel(a)})
		}
		d.section(title, rows)
		d.roleWarnings(idp.SSODescriptor.RoleDescriptor, "IDPSSODescriptor")
		if len(idp.SingleSignOnServices) == 0 {
			d.warn("the IDPSSODescriptor has no SingleSignOnService")
		}
	}
	for i, sp := range v.SPSSODescriptors {
		title := prefix + "SPSSODescriptor"
		if len(v.SPSSODescriptors) > 1 {
			title = fmt.Sprintf("%s %d", title, i+1)
		}
		rows := []KV{
			{"protocolSupportEnumeration", sp.ProtocolSupportEnumeration},
			{"AuthnRequestsSigned", boolPtr(sp.AuthnRequestsSigned)},
			{"WantAssertionsSigned", boolPtr(sp.WantAssertionsSigned)},
		}
		for _, e := range sp.AssertionConsumerServices {
			label := fmt.Sprintf("AssertionConsumerService [%d]", e.Index)
			if e.IsDefault != nil && *e.IsDefault {
				label += " default"
			}
			rows = append(rows, KV{label, endpoint(e.Binding, e.Location)})
		}
		rows = append(rows, d.ssoDescriptorRows(sp.SSODescriptor)...)
		for _, acs := range sp.AttributeConsumingServices {
			for _, ra := range acs.RequestedAttributes {
				req := ""
				if ra.IsRequired != nil && *ra.IsRequired {
					req = " (required)"
				}
				rows = append(rows, KV{fmt.Sprintf("RequestedAttribute [%d]", acs.Index), attributeLabel(ra.Attribute) + req})
			}
		}
		d.section(title, rows)
		d.roleWarnings(sp.SSODescriptor.RoleDescriptor, "SPSSODescriptor")
		if len(sp.AssertionConsumerServices) == 0 {
			d.warn("the SPSSODescriptor has no AssertionConsumerService")
		}
	}
	if o := v.Organization; o != nil {
		var rows []KV
		for _, n := range o.OrganizationDisplayNames {
			rows = append(rows, KV{"DisplayName", n.Value})
		}
		for _, n := range o.OrganizationNames {
			rows = append(rows, KV{"Name", n.Value})
		}
		for _, n := range o.OrganizationURLs {
			rows = append(rows, KV{"URL", n.Value})
		}
		d.section(prefix+"Organization", rows)
	}
	var contacts []KV
	for _, c := range v.ContactPersons {
		who := strings.TrimSpace(strings.Join([]string{c.GivenName, c.SurName, strings.Join(c.EmailAddresses, ", ")}, " "))
		contacts = append(contacts, KV{c.ContactType, who})
	}
	d.section(prefix+"ContactPerson", contacts)
}

func (d *describer) ssoDescriptorRows(s saml.SSODescriptor) []KV {
	var rows []KV
	for _, e := range s.SingleLogoutServices {
		rows = append(rows, KV{"SingleLogoutService", endpoint(e.Binding, e.Location)})
	}
	for _, e := range s.ArtifactResolutionServices {
		rows = append(rows, KV{fmt.Sprintf("ArtifactResolutionService [%d]", e.Index), endpoint(e.Binding, e.Location)})
	}
	for _, f := range s.NameIDFormats {
		rows = append(rows, KV{"NameIDFormat", string(f)})
	}
	for _, k := range s.KeyDescriptors {
		use := k.Use
		if use == "" {
			use = "signing and encryption"
		}
		rows = append(rows, KV{"KeyDescriptor", fmt.Sprintf("%s, %d certificate(s)", use, len(k.KeyInfo.X509Data.X509Certificates))})
		for _, m := range k.EncryptionMethods {
			rows = append(rows, KV{"  EncryptionMethod", algorithmName(m.Algorithm)})
		}
	}
	return rows
}

func (d *describer) roleWarnings(r saml.RoleDescriptor, what string) {
	if r.ValidUntil != nil && !d.now.Before(*r.ValidUntil) {
		d.warn("the %s expired %s ago (validUntil)", what, roundDuration(d.now.Sub(*r.ValidUntil)))
	}
	if !strings.Contains(r.ProtocolSupportEnumeration, nsProtocol) {
		d.warn("the %s does not list SAML 2.0 (%s) in protocolSupportEnumeration", what, nsProtocol)
	}
	signing := false
	for _, k := range r.KeyDescriptors {
		if k.Use == "" || k.Use == "signing" {
			signing = true
		}
	}
	if !signing && what == "IDPSSODescriptor" {
		d.warn("the IDPSSODescriptor has no signing key: service providers cannot verify its assertions")
	}
}

func (d *describer) entitiesDescriptor(v *saml.EntitiesDescriptor, prefix string) {
	rows := []KV{{"Name", strPtr(v.Name)}, {"ID", strPtr(v.ID)}}
	if v.ValidUntil != nil {
		rows = append(rows, KV{"validUntil", d.when(*v.ValidUntil)})
		if !d.now.Before(*v.ValidUntil) {
			d.warn("the metadata expired %s ago (validUntil)", roundDuration(d.now.Sub(*v.ValidUntil)))
		}
	}
	var entities []KV
	var walk func(e *saml.EntitiesDescriptor)
	walk = func(e *saml.EntitiesDescriptor) {
		for _, ed := range e.EntityDescriptors {
			var roles []string
			if len(ed.IDPSSODescriptors) > 0 {
				roles = append(roles, "IdP")
			}
			if len(ed.SPSSODescriptors) > 0 {
				roles = append(roles, "SP")
			}
			entities = append(entities, KV{strings.Join(roles, "+"), ed.EntityID})
		}
		for i := range e.EntitiesDescriptors {
			walk(&e.EntitiesDescriptors[i])
		}
	}
	walk(v)
	rows = append(rows, KV{"Entities", strconv.Itoa(len(entities))})
	d.section(prefix+"EntitiesDescriptor", rows)
	if len(entities) == 1 && len(v.EntityDescriptors) == 1 {
		d.entityDescriptor(&v.EntityDescriptors[0], prefix)
		return
	}
	const maxListed = 500
	if len(entities) > maxListed {
		entities = append(entities[:maxListed], KV{"…", fmt.Sprintf("and %d more", len(entities)-maxListed)})
	}
	d.section(prefix+"Entities", entities)
}

// signatures describes every ds:Signature in the document.
func (d *describer) signatures(root *etree.Element) {
	var walk func(el *etree.Element)
	walk = func(el *etree.Element) {
		for _, c := range el.ChildElements() {
			if c.Tag == "Signature" && c.NamespaceURI() == nsDSig {
				d.signature(el, c)
				continue
			}
			walk(c)
		}
	}
	walk(root)
}

func (d *describer) signature(parent, sig *etree.Element) {
	id := parent.SelectAttrValue("ID", "")
	s := Signature{Signs: parent.Tag}
	if id != "" {
		s.Signs += " ID=" + id
	}
	if si := sig.FindElement("./SignedInfo"); si != nil {
		if m := si.FindElement("./CanonicalizationMethod"); m != nil {
			s.Canonicalization = algorithmName(m.SelectAttrValue("Algorithm", ""))
		}
		if m := si.FindElement("./SignatureMethod"); m != nil {
			s.SignatureMethod = algorithmName(m.SelectAttrValue("Algorithm", ""))
		}
		refs := si.FindElements("./Reference")
		if len(refs) != 1 {
			d.warn("the signature of %s has %d references; SAML requires exactly one (saml-core §5.4.2)", parent.Tag, len(refs))
		}
		if len(refs) > 0 {
			ref := refs[0]
			s.ReferenceURI = ref.SelectAttrValue("URI", "")
			s.ReferenceMatches = id != "" && s.ReferenceURI == "#"+id
			if m := ref.FindElement("./DigestMethod"); m != nil {
				s.DigestMethod = algorithmName(m.SelectAttrValue("Algorithm", ""))
			}
			var transforms []string
			for _, t := range ref.FindElements("./Transforms/Transform") {
				transforms = append(transforms, algorithmName(t.SelectAttrValue("Algorithm", "")))
			}
			s.Transforms = strings.Join(transforms, ", ")
		}
	}
	s.HasCertificate = sig.FindElement(".//X509Certificate") != nil
	if !s.ReferenceMatches {
		d.warn("the signature in %s references %q, not the element it is in: it does not protect %s", parent.Tag, s.ReferenceURI, parent.Tag)
	}
	if strings.Contains(s.SignatureMethod, "SHA-1") || strings.Contains(s.DigestMethod, "SHA-1") {
		d.warn("the signature of %s uses SHA-1, which hardened relying parties refuse", parent.Tag)
	}
	d.msg.Signatures = append(d.msg.Signatures, s)
}

// certificates describes every X.509 certificate in the document.
func (d *describer) certificates(root *etree.Element) {
	for _, el := range root.FindElements("//X509Certificate") {
		if el.NamespaceURI() != nsDSig {
			continue
		}
		c := describeCertificate(el.Text(), d.now)
		c.Where = certificateContext(el)
		if c.Expired {
			d.warn("the certificate in %s expired on %s", c.Where, c.NotAfter)
		}
		d.msg.Certificates = append(d.msg.Certificates, c)
	}
}

func certificateContext(el *etree.Element) string {
	for p := el.Parent(); p != nil; p = p.Parent() {
		switch p.Tag {
		case "KeyDescriptor":
			use := p.SelectAttrValue("use", "signing and encryption")
			role := ""
			if r := p.Parent(); r != nil {
				role = " in " + r.Tag
			}
			return "KeyDescriptor (" + use + ")" + role
		case "Signature":
			if s := p.Parent(); s != nil {
				return "Signature of " + s.Tag
			}
			return "Signature"
		case "EncryptedKey":
			return "EncryptedKey (the recipient's certificate)"
		}
	}
	return el.Parent().Tag
}

// DescribeCertificate describes a base64 DER certificate, as found in
// XML or in PEM.
func describeCertificate(text string, now time.Time) *Certificate {
	c := &Certificate{}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		c.Error = "not valid base64: " + err.Error()
		return c
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		c.Error = "not a valid certificate: " + err.Error()
		return c
	}
	sha1sum := sha1.Sum(der) //nolint:gosec // a fingerprint, not a signature
	sha256sum := sha256.Sum256(der)
	c.Subject = cert.Subject.String()
	c.Issuer = cert.Issuer.String()
	c.Serial = cert.SerialNumber.Text(16)
	c.NotBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	c.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	c.Expired = now.After(cert.NotAfter)
	c.SHA1 = colonHex(sha1sum[:])
	c.SHA256 = colonHex(sha256sum[:])
	c.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		c.Key = fmt.Sprintf("RSA %d bits", k.N.BitLen())
	case *ecdsa.PublicKey:
		c.Key = "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		c.Key = "Ed25519"
	default:
		c.Key = cert.PublicKeyAlgorithm.String()
	}
	return c
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func (d *describer) when(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	s := t.UTC().Format(time.RFC3339)
	switch delta := t.Sub(d.now); {
	case delta > time.Second:
		s += " (in " + roundDuration(delta) + ")"
	case delta < -time.Second:
		s += " (" + roundDuration(-delta) + " ago)"
	default:
		s += " (now)"
	}
	return s
}

func roundDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < 48*time.Hour:
		return strings.TrimSuffix(d.Round(time.Minute).String(), "0s")
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

func endpoint(binding, location string) string {
	return location + "\n" + shortURN(binding)
}

func shortURN(s string) string {
	if i := strings.LastIndex(s, ":"); i >= 0 && strings.HasPrefix(s, "urn:") {
		return s[i+1:]
	}
	return s
}

func boolPtr(b *bool) string {
	if b == nil {
		return ""
	}
	return strconv.FormatBool(*b)
}

func strPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var algorithms = map[string]string{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":                "RSA-SHA-1",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":         "RSA-SHA-256",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":         "RSA-SHA-384",
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":         "RSA-SHA-512",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":         "ECDSA-SHA-1",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":       "ECDSA-SHA-256",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":       "ECDSA-SHA-384",
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":       "ECDSA-SHA-512",
	"http://www.w3.org/2000/09/xmldsig#sha1":                    "SHA-1",
	"http://www.w3.org/2001/04/xmlenc#sha256":                   "SHA-256",
	"http://www.w3.org/2001/04/xmldsig-more#sha384":             "SHA-384",
	"http://www.w3.org/2001/04/xmlenc#sha512":                   "SHA-512",
	"http://www.w3.org/2001/10/xml-exc-c14n#":                   "Exclusive C14N",
	"http://www.w3.org/2001/10/xml-exc-c14n#WithComments":       "Exclusive C14N with comments",
	"http://www.w3.org/TR/2001/REC-xml-c14n-20010315":           "C14N 1.0",
	"http://www.w3.org/2006/12/xml-c14n11":                      "C14N 1.1",
	"http://www.w3.org/2000/09/xmldsig#enveloped-signature":     "enveloped signature",
	"http://www.w3.org/2001/04/xmlenc#aes128-cbc":               "AES-128-CBC",
	"http://www.w3.org/2001/04/xmlenc#aes192-cbc":               "AES-192-CBC",
	"http://www.w3.org/2001/04/xmlenc#aes256-cbc":               "AES-256-CBC",
	"http://www.w3.org/2009/xmlenc11#aes128-gcm":                "AES-128-GCM",
	"http://www.w3.org/2009/xmlenc11#aes192-gcm":                "AES-192-GCM",
	"http://www.w3.org/2009/xmlenc11#aes256-gcm":                "AES-256-GCM",
	"http://www.w3.org/2001/04/xmlenc#tripledes-cbc":            "3DES-CBC",
	"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p":           "RSA-OAEP (MGF1 SHA-1)",
	"http://www.w3.org/2009/xmlenc11#rsa-oaep":                  "RSA-OAEP",
	"http://www.w3.org/2001/04/xmlenc#rsa-1_5":                  "RSA PKCS#1 v1.5",
	"http://www.w3.org/2001/04/xmlenc#kw-aes128":                "AES-128 key wrap",
	"http://www.w3.org/2001/04/xmlenc#kw-aes256":                "AES-256 key wrap",
	"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":        "HTTP-Redirect",
	"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":            "HTTP-POST",
	"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign": "HTTP-POST-SimpleSign",
	"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact":        "HTTP-Artifact",
	"urn:oasis:names:tc:SAML:2.0:bindings:SOAP":                 "SOAP",
}

func algorithmName(uri string) string {
	if name, ok := algorithms[uri]; ok {
		return name + " (" + uri + ")"
	}
	return uri
}

// weakAlgorithm returns the name of the weak hash a signature algorithm
// URI uses, or "".
func weakAlgorithm(uri string) string {
	if strings.HasSuffix(uri, "sha1") {
		return "SHA-1"
	}
	return ""
}
