package saml

import (
	"encoding/xml"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// metadataChildTags returns the local names of the child elements of the
// element at path in the XML document buf.
func metadataChildTags(t *testing.T, buf []byte, path string) []string {
	t.Helper()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	el := doc.FindElement(path)
	assert.Assert(t, el != nil, "no element at %s in %s", path, buf)
	var tags []string
	for _, child := range el.ChildElements() {
		tags = append(tags, child.Tag)
	}
	return tags
}

// TestMetadataRoundTrip checks that metadata survives being parsed and
// written out again, and that what is written follows the element order and
// attribute rules of saml-metadata-2.0-os (issue #809).
func TestMetadataRoundTrip(t *testing.T) {
	// saml-metadata-2.0-os §2.3.2: <ContactPerson> occurs zero or more
	// times; §2.3.2.2: Company, GivenName and SurName are optional.
	t.Run("ContactPerson is repeatable and its optional children are omitted", func(t *testing.T) {
		input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/">` +
			`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="1"/>` +
			`</SPSSODescriptor>` +
			`<ContactPerson contactType="technical"><GivenName>Alice</GivenName><EmailAddress>mailto:a@example.com</EmailAddress></ContactPerson>` +
			`<ContactPerson contactType="support"><SurName>Bob</SurName><EmailAddress>mailto:b@example.com</EmailAddress></ContactPerson>` +
			`</EntityDescriptor>`
		var ed EntityDescriptor
		assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
		assert.Check(t, is.DeepEqual(ed.ContactPersons, []ContactPerson{
			{ContactType: "technical", GivenName: "Alice", EmailAddresses: []string{"mailto:a@example.com"}},
			{ContactType: "support", SurName: "Bob", EmailAddresses: []string{"mailto:b@example.com"}},
		}))
		// The deprecated field is the first contact.
		assert.Assert(t, ed.ContactPerson != nil)
		assert.Check(t, ed.ContactPerson == &ed.ContactPersons[0])

		buf, err := xml.Marshal(ed)
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf),
			`<ContactPerson contactType="technical"><GivenName>Alice</GivenName><EmailAddress>mailto:a@example.com</EmailAddress></ContactPerson>`+
				`<ContactPerson contactType="support"><SurName>Bob</SurName><EmailAddress>mailto:b@example.com</EmailAddress></ContactPerson>`))
		assert.Check(t, !is.Contains(string(buf), `<Company>`)().Success())

		var ed2 EntityDescriptor
		assert.NilError(t, xml.Unmarshal(buf, &ed2))
		assert.Check(t, is.DeepEqual(ed2.ContactPersons, ed.ContactPersons))

		// Code that sets only the deprecated field still writes it.
		buf, err = xml.Marshal(EntityDescriptor{
			EntityID:      "https://sp.example.com/",
			ContactPerson: &ContactPerson{ContactType: "technical", EmailAddresses: []string{"mailto:a@example.com"}},
		})
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf),
			`<ContactPerson contactType="technical"><EmailAddress>mailto:a@example.com</EmailAddress></ContactPerson>`))

		// Replacing the deprecated field after parsing replaces the first
		// contact and keeps the others.
		ed.ContactPerson = &ContactPerson{ContactType: "administrative", Company: "Example"}
		buf, err = xml.Marshal(ed)
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(metadataChildTags(t, buf, "/EntityDescriptor"),
			[]string{"SPSSODescriptor", "ContactPerson", "ContactPerson"}))
		assert.Check(t, is.Contains(string(buf),
			`<ContactPerson contactType="administrative"><Company>Example</Company></ContactPerson>`+
				`<ContactPerson contactType="support">`))
	})

	// saml-metadata-2.0-os §2.3.2.3: the namespace attribute of
	// <AdditionalMetadataLocation> is required.
	t.Run("AdditionalMetadataLocation keeps its namespace", func(t *testing.T) {
		input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/">` +
			`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="1"/>` +
			`</SPSSODescriptor>` +
			`<AdditionalMetadataLocation namespace="urn:oasis:names:tc:SAML:2.0:metadata">https://sp.example.com/other.xml</AdditionalMetadataLocation>` +
			`</EntityDescriptor>`
		var ed EntityDescriptor
		assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
		assert.Check(t, is.DeepEqual(ed.AdditionalMetadataLocationElements, []AdditionalMetadataLocation{
			{Namespace: "urn:oasis:names:tc:SAML:2.0:metadata", Value: "https://sp.example.com/other.xml"},
		}))
		assert.Check(t, is.DeepEqual(ed.AdditionalMetadataLocations, []string{"https://sp.example.com/other.xml"}))

		buf, err := xml.Marshal(ed)
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf),
			`<AdditionalMetadataLocation namespace="urn:oasis:names:tc:SAML:2.0:metadata">https://sp.example.com/other.xml</AdditionalMetadataLocation>`))
		assert.Check(t, is.DeepEqual(metadataChildTags(t, buf, "/EntityDescriptor"),
			[]string{"SPSSODescriptor", "AdditionalMetadataLocation"}))

		// Code that sets only the deprecated field still writes it.
		buf, err = xml.Marshal(EntityDescriptor{
			EntityID:                    "https://sp.example.com/",
			AdditionalMetadataLocations: []string{"https://sp.example.com/other.xml"},
		})
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf),
			`<AdditionalMetadataLocation namespace="">https://sp.example.com/other.xml</AdditionalMetadataLocation>`))
	})

	// saml-metadata-2.0-os §2.4.2: ArtifactResolutionService is an
	// IndexedEndpointType in SSODescriptorType, so it comes before
	// SingleLogoutService and the IDPSSODescriptor's SingleSignOnService
	// (§2.4.3), and its index and isDefault attributes are kept.
	t.Run("IDPSSODescriptor ArtifactResolutionService is indexed and in schema order", func(t *testing.T) {
		input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/">` +
			`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/ars" index="7" isDefault="true"/>` +
			`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/>` +
			`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>` +
			`</IDPSSODescriptor></EntityDescriptor>`
		var ed EntityDescriptor
		assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
		idp := ed.IDPSSODescriptors[0]
		ars := idp.SSODescriptor.ArtifactResolutionServices
		assert.Assert(t, is.Len(ars, 1))
		assert.Check(t, is.Equal(7, ars[0].Index))
		assert.Assert(t, ars[0].IsDefault != nil)
		assert.Check(t, *ars[0].IsDefault)
		// The deprecated field still holds the endpoints.
		assert.Check(t, is.DeepEqual(idp.ArtifactResolutionServices, []Endpoint{
			{Binding: SOAPBinding, Location: "https://idp.example.com/ars"},
		}))

		buf, err := xml.Marshal(ed)
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf),
			`<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/ars" index="7" isDefault="true">`))
		assert.Check(t, is.DeepEqual(metadataChildTags(t, buf, "/EntityDescriptor/IDPSSODescriptor"),
			[]string{"ArtifactResolutionService", "SingleLogoutService", "SingleSignOnService"}))

		// Code that sets only the deprecated field still writes it, in
		// schema order and with an index.
		buf, err = xml.Marshal(IDPSSODescriptor{
			SSODescriptor: SSODescriptor{
				RoleDescriptor:       RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol"},
				SingleLogoutServices: []Endpoint{{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/slo"}},
			},
			SingleSignOnServices:       []Endpoint{{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/sso"}},
			ArtifactResolutionServices: []Endpoint{{Binding: SOAPBinding, Location: "https://idp.example.com/ars"}},
		})
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf),
			`<ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/ars" index="1">`))
		assert.Check(t, is.DeepEqual(metadataChildTags(t, buf, "/IDPSSODescriptor"),
			[]string{"ArtifactResolutionService", "SingleLogoutService", "SingleSignOnService"}))

		// The service provider finds an endpoint set only in the indexed
		// field.
		sp := ServiceProvider{IDPMetadata: &EntityDescriptor{IDPSSODescriptors: []IDPSSODescriptor{{
			SSODescriptor: SSODescriptor{ArtifactResolutionServices: []IndexedEndpoint{
				{Binding: SOAPBinding, Location: "https://idp.example.com/ars", Index: 1},
			}},
		}}}}
		assert.Check(t, is.Equal(sp.GetArtifactBindingLocation(SOAPBinding), "https://idp.example.com/ars"))
	})

	// saml-metadata-2.0-os §2.4.1: RoleDescriptorType is abstract, so a
	// <RoleDescriptor> element carries an xsi:type naming its concrete type.
	t.Run("RoleDescriptor keeps its xsi:type", func(t *testing.T) {
		const fedNS = "http://docs.oasis-open.org/wsfed/federation/200706"
		want := xml.Name{Space: fedNS, Local: "SecurityTokenServiceType"}
		for name, input := range map[string]string{
			"declared on RoleDescriptor": `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/">` +
				`<RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="` + fedNS + `" xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="` + fedNS + `"/>` +
				`</EntityDescriptor>`,
			"declared on EntityDescriptor": `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="` + fedNS + `" entityID="https://idp.example.com/">` +
				`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="` + fedNS + `"/>` +
				`</EntityDescriptor>`,
			"declared on EntitiesDescriptor": `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="` + fedNS + `">` +
				`<EntityDescriptor entityID="https://idp.example.com/">` +
				`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="` + fedNS + `"/>` +
				`</EntityDescriptor></EntitiesDescriptor>`,
		} {
			t.Run(name, func(t *testing.T) {
				var ed EntityDescriptor
				if name == "declared on EntitiesDescriptor" {
					var eds EntitiesDescriptor
					assert.NilError(t, xml.Unmarshal([]byte(input), &eds))
					ed = eds.EntityDescriptors[0]
				} else {
					assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
				}
				assert.Assert(t, is.Len(ed.RoleDescriptors, 1))
				assert.Check(t, is.Equal(ed.RoleDescriptors[0].XSIType, want))

				buf, err := xml.Marshal(ed)
				assert.NilError(t, err)
				assert.Check(t, is.Contains(string(buf), `xsi:type="xsitype:SecurityTokenServiceType"`))

				var ed2 EntityDescriptor
				assert.NilError(t, xml.Unmarshal(buf, &ed2))
				assert.Assert(t, is.Len(ed2.RoleDescriptors, 1))
				assert.Check(t, is.Equal(ed2.RoleDescriptors[0].XSIType, want))
			})
		}
	})

	// saml-metadata-2.0-os §2.3.2: EntityDescriptorType is a sequence of
	// ds:Signature, Extensions, then the role descriptors.
	t.Run("EntityDescriptor writes Extensions before RoleDescriptor", func(t *testing.T) {
		input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/">` +
			`<Extensions><x:Thing xmlns:x="urn:example:x">1</x:Thing></Extensions>` +
			`<RoleDescriptor protocolSupportEnumeration="urn:example:protocol"/>` +
			`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>` +
			`</IDPSSODescriptor>` +
			`<Organization><OrganizationName xml:lang="en">Example</OrganizationName><OrganizationDisplayName xml:lang="en">Example</OrganizationDisplayName><OrganizationURL xml:lang="en">https://example.com/</OrganizationURL></Organization>` +
			`</EntityDescriptor>`
		var ed EntityDescriptor
		assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
		buf, err := xml.Marshal(ed)
		assert.NilError(t, err)
		assert.Check(t, is.DeepEqual(metadataChildTags(t, buf, "/EntityDescriptor"),
			[]string{"Extensions", "RoleDescriptor", "IDPSSODescriptor", "Organization"}))
	})

	// saml-metadata-2.0-os §2.4.1.1: the use attribute of KeyDescriptor is
	// optional; leaving it out means the key is used for both purposes.
	t.Run("KeyDescriptor omits an unset use", func(t *testing.T) {
		input := `<KeyDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
			`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>MIIB</X509Certificate></X509Data></KeyInfo>` +
			`</KeyDescriptor>`
		var kd KeyDescriptor
		assert.NilError(t, xml.Unmarshal([]byte(input), &kd))
		assert.Check(t, is.Equal(kd.Use, ""))
		buf, err := xml.Marshal(kd)
		assert.NilError(t, err)
		assert.Check(t, !is.Contains(string(buf), `use=`)().Success(), string(buf))

		kd.Use = "signing"
		buf, err = xml.Marshal(kd)
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf), `<KeyDescriptor use="signing">`))
	})

	// saml-metadata-2.0-os §2.5: the ID attribute of AffiliationDescriptor
	// is optional, and an empty string is not a valid xs:ID.
	t.Run("AffiliationDescriptor omits an unset ID", func(t *testing.T) {
		input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://affiliation.example.com/">` +
			`<AffiliationDescriptor affiliationOwnerID="https://owner.example.com/"><AffiliateMember>https://sp.example.com/</AffiliateMember></AffiliationDescriptor>` +
			`</EntityDescriptor>`
		var ed EntityDescriptor
		assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
		buf, err := xml.Marshal(ed)
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf),
			`<AffiliationDescriptor affiliationOwnerID="https://owner.example.com/"><AffiliateMember>`))

		ed.AffiliationDescriptor.ID = "id-affiliation"
		buf, err = xml.Marshal(ed)
		assert.NilError(t, err)
		assert.Check(t, is.Contains(string(buf), `ID="id-affiliation"`))
	})
}
