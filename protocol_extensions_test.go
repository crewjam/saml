package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

const protocolExtensions = `<samlp:Extensions><x:Hint xmlns:x="urn:example:ext" Level="2">hello</x:Hint></samlp:Extensions>`

// checkExtensions checks that ext is the samlp:Extensions element of
// protocolExtensions.
func checkExtensions(t *testing.T, ext *etree.Element) {
	t.Helper()
	assert.Assert(t, ext != nil)
	assert.Check(t, is.Equal(ext.Tag, "Extensions"))
	assert.Check(t, is.Equal(ext.NamespaceURI(), "urn:oasis:names:tc:SAML:2.0:protocol"))
	hint := ext.FindElement("./Hint")
	assert.Assert(t, hint != nil)
	assert.Check(t, is.Equal(hint.NamespaceURI(), "urn:example:ext"))
	assert.Check(t, is.Equal(hint.SelectAttrValue("Level", ""), "2"))
	assert.Check(t, is.Equal(hint.Text(), "hello"))
}

// The samlp:Extensions element of every request and response type
// (saml-core §3.2.1, §3.2.2) is kept when the message is unmarshalled, and
// written back after Signature, by MarshalXML and by Element. Before, only
// AuthnRequest kept it.
func TestProtocolMessageExtensionsRoundTrip(t *testing.T) {
	const open = `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1" Version="2.0" IssueInstant="2030-01-01T00:00:00Z"`
	const issuer = `<saml:Issuer>https://idp.example.com/</saml:Issuer>`
	const status = `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`
	type message interface {
		Element() *etree.Element
	}
	for _, tc := range []struct {
		name  string
		xml   string
		new   func() message
		ext   func(message) *etree.Element
		after string // the element written after Extensions
	}{
		{
			name:  "LogoutRequest",
			xml:   `<samlp:LogoutRequest ` + open + `>` + issuer + protocolExtensions + `<saml:NameID>alice</saml:NameID></samlp:LogoutRequest>`,
			new:   func() message { return &LogoutRequest{} },
			ext:   func(m message) *etree.Element { return m.(*LogoutRequest).Extensions },
			after: "NameID",
		},
		{
			name:  "LogoutResponse",
			xml:   `<samlp:LogoutResponse ` + open + `>` + issuer + protocolExtensions + status + `</samlp:LogoutResponse>`,
			new:   func() message { return &LogoutResponse{} },
			ext:   func(m message) *etree.Element { return m.(*LogoutResponse).Extensions },
			after: "Status",
		},
		{
			name:  "Response",
			xml:   `<samlp:Response ` + open + `>` + issuer + protocolExtensions + status + `</samlp:Response>`,
			new:   func() message { return &Response{} },
			ext:   func(m message) *etree.Element { return m.(*Response).Extensions },
			after: "Status",
		},
		{
			name:  "ArtifactResolve",
			xml:   `<samlp:ArtifactResolve ` + open + `>` + issuer + protocolExtensions + `<samlp:Artifact>AAQAAA==</samlp:Artifact></samlp:ArtifactResolve>`,
			new:   func() message { return &ArtifactResolve{} },
			ext:   func(m message) *etree.Element { return m.(*ArtifactResolve).Extensions },
			after: "Artifact",
		},
		{
			name:  "ArtifactResponse",
			xml:   `<samlp:ArtifactResponse ` + open + `>` + issuer + protocolExtensions + status + `</samlp:ArtifactResponse>`,
			new:   func() message { return &ArtifactResponse{} },
			ext:   func(m message) *etree.Element { return m.(*ArtifactResponse).Extensions },
			after: "Status",
		},
		{
			name:  "AttributeQuery",
			xml:   `<samlp:AttributeQuery ` + open + `>` + issuer + protocolExtensions + `<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></samlp:AttributeQuery>`,
			new:   func() message { return &AttributeQuery{} },
			ext:   func(m message) *etree.Element { return m.(*AttributeQuery).Extensions },
			after: "Subject",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.new()
			assert.NilError(t, xml.Unmarshal([]byte(tc.xml), m))
			checkExtensions(t, tc.ext(m))

			// Through the untrusted path the SP reads messages with.
			doc := etree.NewDocument()
			assert.NilError(t, doc.ReadFromString(tc.xml))
			untrusted := tc.new()
			assert.NilError(t, unmarshalElement(doc.Root(), untrusted))
			checkExtensions(t, tc.ext(untrusted))

			marshalled, err := xml.Marshal(m)
			assert.NilError(t, err)
			assert.Check(t, xmlroundtrip.Validate(marshalled))
			again := tc.new()
			assert.NilError(t, xml.Unmarshal(marshalled, again), string(marshalled))
			checkExtensions(t, tc.ext(again))
			ms := string(marshalled)
			extAt, afterAt := strings.Index(ms, ":Extensions"), strings.Index(ms, "<"+tc.after+" ")
			assert.Check(t, extAt > 0 && afterAt > extAt, ms)

			fromElement := spcovSerialize(t, m.Element())
			assert.Check(t, xmlroundtrip.Validate(fromElement))
			again = tc.new()
			assert.NilError(t, xml.Unmarshal(fromElement, again), string(fromElement))
			checkExtensions(t, tc.ext(again))
			el := m.Element()
			var names []string
			for _, child := range el.ChildElements() {
				names = append(names, child.Tag)
			}
			assert.Check(t, is.DeepEqual(names[:3], []string{"Issuer", "Extensions", tc.after}))
		})
	}
}

// The md:Extensions of an Organization and of a ContactPerson
// (saml-metadata §2.3.2.1, §2.3.2.2) are kept, and written first.
func TestOrganizationAndContactPersonExtensions(t *testing.T) {
	const in = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/">` +
		`<Organization><Extensions><x:Org xmlns:x="urn:example:ext">o</x:Org></Extensions>` +
		`<OrganizationName xml:lang="en">Example</OrganizationName>` +
		`<OrganizationDisplayName xml:lang="en">Example</OrganizationDisplayName>` +
		`<OrganizationURL xml:lang="en">https://example.com/</OrganizationURL></Organization>` +
		`<ContactPerson contactType="technical"><Extensions><x:Contact xmlns:x="urn:example:ext">c</x:Contact></Extensions>` +
		`<GivenName>Alice</GivenName><EmailAddress>mailto:alice@example.com</EmailAddress></ContactPerson>` +
		`</EntityDescriptor>`
	check := func(t *testing.T, ed *EntityDescriptor) {
		t.Helper()
		assert.Assert(t, ed.Organization != nil)
		assert.Assert(t, ed.Organization.Extensions != nil)
		assert.Assert(t, is.Len(ed.Organization.Extensions.Other, 1))
		assert.Check(t, is.Equal(ed.Organization.Extensions.Other[0].XMLName, xml.Name{Space: "urn:example:ext", Local: "Org"}))
		assert.Check(t, is.Len(ed.Organization.OrganizationNames, 1))
		assert.Assert(t, is.Len(ed.ContactPersons, 1))
		cp := ed.ContactPersons[0]
		assert.Assert(t, cp.Extensions != nil)
		assert.Assert(t, is.Len(cp.Extensions.Other, 1))
		assert.Check(t, is.Equal(cp.Extensions.Other[0].XMLName, xml.Name{Space: "urn:example:ext", Local: "Contact"}))
		assert.Check(t, is.Equal(cp.GivenName, "Alice"))
	}

	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(in), &ed))
	check(t, &ed)

	out, err := xml.Marshal(ed)
	assert.NilError(t, err)
	assert.Check(t, xmlroundtrip.Validate(out))
	s := string(out)
	assert.Check(t, strings.Index(s, "Org>") < strings.Index(s, "<OrganizationName"), s)
	assert.Check(t, strings.Index(s, "Contact>") < strings.Index(s, "<GivenName"), s)
	var again EntityDescriptor
	assert.NilError(t, xml.Unmarshal(out, &again), s)
	check(t, &again)
}
