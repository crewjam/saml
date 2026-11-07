package saml

import (
	"encoding/xml"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

const extensionsTestMetadata = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" entityID="https://idp.example.com/metadata">
  <md:Extensions>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" MinKeySize="2048" MaxKeySize="4096"/>
  </md:Extensions>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>
      <shibmd:Scope regexp="false">example.com</shibmd:Scope>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en">Example IdP</mdui:DisplayName>
      </mdui:UIInfo>
      <x:Flag xmlns:x="urn:example:x"/>
    </md:Extensions>
    <md:KeyDescriptor use="encryption">
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc">
        <xenc:KeySize>128</xenc:KeySize>
      </md:EncryptionMethod>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`

func TestMetadataExtensions(t *testing.T) {
	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(extensionsTestMetadata), &ed))

	assert.Assert(t, ed.Extensions != nil)
	assert.Check(t, is.DeepEqual(ed.Extensions.DigestMethods, []DigestMethod{{
		XMLName:   xml.Name{Space: AlgSupportNamespace, Local: "DigestMethod"},
		Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
	}}))
	assert.Check(t, is.DeepEqual(ed.Extensions.SigningMethods, []SigningMethod{{
		XMLName:    xml.Name{Space: AlgSupportNamespace, Local: "SigningMethod"},
		Algorithm:  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		MinKeySize: 2048,
		MaxKeySize: 4096,
	}}))
	assert.Check(t, is.Len(ed.Extensions.Other, 0))

	assert.Assert(t, is.Len(ed.IDPSSODescriptors, 1))
	idp := ed.IDPSSODescriptors[0]
	assert.Assert(t, idp.Extensions != nil)
	assert.Assert(t, is.Len(idp.Extensions.SigningMethods, 1))
	assert.Check(t, is.Equal(idp.Extensions.SigningMethods[0].Algorithm, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"))

	// Extension elements without a field of their own are kept, with their
	// namespaces, attributes, text and children.
	assert.Check(t, is.DeepEqual(idp.Extensions.Other, []ExtensionElement{
		{
			XMLName:  xml.Name{Space: "urn:mace:shibboleth:metadata:1.0", Local: "Scope"},
			Attrs:    []xml.Attr{{Name: xml.Name{Local: "regexp"}, Value: "false"}},
			CharData: "example.com",
		},
		{
			XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:metadata:ui", Local: "UIInfo"},
			Children: []ExtensionElement{{
				XMLName:  xml.Name{Space: "urn:oasis:names:tc:SAML:metadata:ui", Local: "DisplayName"},
				Attrs:    []xml.Attr{{Name: xml.Name{Space: "http://www.w3.org/XML/1998/namespace", Local: "lang"}, Value: "en"}},
				CharData: "Example IdP",
			}},
		},
		{
			// The namespace declaration is not kept as an attribute.
			XMLName: xml.Name{Space: "urn:example:x", Local: "Flag"},
		},
	}))

	assert.Assert(t, is.Len(idp.KeyDescriptors, 1))
	assert.Assert(t, is.Len(idp.KeyDescriptors[0].EncryptionMethods, 1))
	keySize := idp.KeyDescriptors[0].EncryptionMethods[0].KeySize
	assert.Assert(t, keySize != nil)
	assert.Check(t, is.Equal(*keySize, 128))

	// Everything survives marshalling and parsing again.
	buf, err := xml.Marshal(ed)
	assert.NilError(t, err)
	var ed2 EntityDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &ed2))
	assert.Check(t, is.DeepEqual(ed2.Extensions, ed.Extensions))
	assert.Assert(t, is.Len(ed2.IDPSSODescriptors, 1))
	assert.Check(t, is.DeepEqual(ed2.IDPSSODescriptors[0].Extensions, idp.Extensions))
	assert.Assert(t, is.Len(ed2.IDPSSODescriptors[0].KeyDescriptors, 1))
	assert.Check(t, is.DeepEqual(ed2.IDPSSODescriptors[0].KeyDescriptors[0].EncryptionMethods, idp.KeyDescriptors[0].EncryptionMethods))
}

func TestMetadataExtensionsRoundTripAllDescriptors(t *testing.T) {
	ext := func(alg string) *Extensions {
		return &Extensions{
			DigestMethods: []DigestMethod{{Algorithm: alg}},
			Other: []ExtensionElement{{
				XMLName:  xml.Name{Space: "urn:example:ext", Local: "Thing"},
				CharData: alg,
			}},
		}
	}
	role := func(alg string) RoleDescriptor {
		return RoleDescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			Extensions:                 ext(alg),
		}
	}

	in := EntitiesDescriptor{
		Extensions: ext("urn:example:entities"),
		EntityDescriptors: []EntityDescriptor{{
			EntityID:                      "https://example.com/metadata",
			Extensions:                    ext("urn:example:entity"),
			IDPSSODescriptors:             []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: role("urn:example:idp")}}},
			SPSSODescriptors:              []SPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: role("urn:example:sp")}}},
			AuthnAuthorityDescriptors:     []AuthnAuthorityDescriptor{{RoleDescriptor: role("urn:example:authn")}},
			AttributeAuthorityDescriptors: []AttributeAuthorityDescriptor{{RoleDescriptor: role("urn:example:attr")}},
			PDPDescriptors:                []PDPDescriptor{{RoleDescriptor: role("urn:example:pdp")}},
			AffiliationDescriptor: &AffiliationDescriptor{
				AffiliationOwnerID: "https://example.com/metadata",
				Extensions:         ext("urn:example:affiliation"),
			},
		}},
	}

	buf, err := xml.Marshal(in)
	assert.NilError(t, err)

	var out EntitiesDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &out))

	algOf := func(e *Extensions) string {
		if e == nil || len(e.DigestMethods) != 1 || len(e.Other) != 1 || e.Other[0].CharData != e.DigestMethods[0].Algorithm {
			return ""
		}
		return e.DigestMethods[0].Algorithm
	}
	assert.Check(t, is.Equal(algOf(out.Extensions), "urn:example:entities"))
	assert.Assert(t, is.Len(out.EntityDescriptors, 1))
	ed := out.EntityDescriptors[0]
	assert.Check(t, is.Equal(algOf(ed.Extensions), "urn:example:entity"))
	assert.Assert(t, is.Len(ed.IDPSSODescriptors, 1))
	assert.Check(t, is.Equal(algOf(ed.IDPSSODescriptors[0].Extensions), "urn:example:idp"))
	assert.Assert(t, is.Len(ed.SPSSODescriptors, 1))
	assert.Check(t, is.Equal(algOf(ed.SPSSODescriptors[0].Extensions), "urn:example:sp"))
	assert.Assert(t, is.Len(ed.AuthnAuthorityDescriptors, 1))
	assert.Check(t, is.Equal(algOf(ed.AuthnAuthorityDescriptors[0].Extensions), "urn:example:authn"))
	assert.Assert(t, is.Len(ed.AttributeAuthorityDescriptors, 1))
	assert.Check(t, is.Equal(algOf(ed.AttributeAuthorityDescriptors[0].Extensions), "urn:example:attr"))
	assert.Assert(t, is.Len(ed.PDPDescriptors, 1))
	assert.Check(t, is.Equal(algOf(ed.PDPDescriptors[0].Extensions), "urn:example:pdp"))
	assert.Assert(t, ed.AffiliationDescriptor != nil)
	assert.Check(t, is.Equal(algOf(ed.AffiliationDescriptor.Extensions), "urn:example:affiliation"))
}

func TestMetadataExtensionsOmittedWhenUnset(t *testing.T) {
	// md:Extensions comes after ds:Signature and before the other children,
	// and is not written at all when there are no extensions.
	buf, err := xml.Marshal(EntityDescriptor{
		EntityID: "https://example.com/metadata",
		SPSSODescriptors: []SPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptors:             []KeyDescriptor{{Use: "encryption", EncryptionMethods: []EncryptionMethod{{Algorithm: "urn:example:alg"}}}},
		}}}},
	})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(buf), `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/metadata">`+
		`<SPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`+
		`<KeyDescriptor use="encryption"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data xmlns="http://www.w3.org/2000/09/xmldsig#"></X509Data></KeyInfo>`+
		`<EncryptionMethod Algorithm="urn:example:alg"></EncryptionMethod></KeyDescriptor>`+
		`</SPSSODescriptor></EntityDescriptor>`))

	// Existing metadata without extensions still parses and re-encodes to
	// the same golden output.
	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal(golden.Get(t, "TestCanProduceSPMetadata_expected"), &ed))
	assert.Check(t, ed.Extensions == nil)
	assert.Assert(t, is.Len(ed.SPSSODescriptors, 1))
	assert.Check(t, ed.SPSSODescriptors[0].Extensions == nil)
}
