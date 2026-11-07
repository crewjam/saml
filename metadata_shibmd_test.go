package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

func TestIDPMetadataPublishesShibbolethScopes(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	// No scopes are published by default.
	metadata := test.IDP.Metadata()
	assert.Assert(t, is.Len(metadata.IDPSSODescriptors, 1))
	assert.Check(t, metadata.IDPSSODescriptors[0].Extensions == nil)
	buf, err := xml.Marshal(metadata)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(buf), "Extensions"))

	test.IDP.MetadataScopes = []ShibbolethScope{
		{Value: "example.com"},
		{Value: `^.+\.example\.org$`, Regexp: true},
	}
	metadata = test.IDP.Metadata()
	buf, err = xml.Marshal(metadata)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(buf), `<IDPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`+
		`<Extensions xmlns="urn:oasis:names:tc:SAML:2.0:metadata">`+
		`<Scope xmlns="urn:mace:shibboleth:metadata:1.0" regexp="false">example.com</Scope>`+
		`<Scope xmlns="urn:mace:shibboleth:metadata:1.0" regexp="true">^.+\.example\.org$</Scope>`+
		`</Extensions><KeyDescriptor use="signing">`))

	var parsed EntityDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &parsed))
	assert.Assert(t, is.Len(parsed.IDPSSODescriptors, 1))
	assert.Assert(t, parsed.IDPSSODescriptors[0].Extensions != nil)
	scopes := parsed.IDPSSODescriptors[0].Extensions.ShibbolethScopes
	assert.Assert(t, is.Len(scopes, 2))
	assert.Check(t, is.Equal(scopes[0].Value, "example.com"))
	assert.Check(t, !scopes[0].Regexp)
	assert.Check(t, is.Equal(scopes[1].Value, `^.+\.example\.org$`))
	assert.Check(t, scopes[1].Regexp)

	// Metadata does not share the IdP's slice.
	metadata.IDPSSODescriptors[0].Extensions.ShibbolethScopes[0].Value = "changed"
	assert.Check(t, is.Equal(test.IDP.MetadataScopes[0].Value, "example.com"))
}

func TestCanParseShibbolethScopes(t *testing.T) {
	// The TestShib IdP metadata publishes a literal scope.
	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal(golden.Get(t, "SP_IDPMetadata"), &ed))
	assert.Assert(t, is.Len(ed.IDPSSODescriptors, 1))
	assert.Assert(t, ed.IDPSSODescriptors[0].Extensions != nil)
	assert.Check(t, is.DeepEqual(ed.IDPSSODescriptors[0].Extensions.ShibbolethScopes, []ShibbolethScope{{
		XMLName: xml.Name{Space: ShibbolethMetadataNamespace, Local: "Scope"},
		Value:   "testshib.org",
	}}))

	// regexp is optional and defaults to false. Scopes may also appear on an
	// AttributeAuthorityDescriptor.
	input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" entityID="https://idp.example.com/metadata">
  <AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <Extensions>
      <shibmd:Scope>example.com</shibmd:Scope>
      <shibmd:Scope regexp="true">^.+\.example\.com$</shibmd:Scope>
    </Extensions>
  </AttributeAuthorityDescriptor>
</EntityDescriptor>`
	ed = EntityDescriptor{}
	assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
	assert.Assert(t, is.Len(ed.AttributeAuthorityDescriptors, 1))
	assert.Assert(t, ed.AttributeAuthorityDescriptors[0].Extensions != nil)
	scopes := ed.AttributeAuthorityDescriptors[0].Extensions.ShibbolethScopes
	assert.Assert(t, is.Len(scopes, 2))
	assert.Check(t, is.Equal(scopes[0].Value, "example.com"))
	assert.Check(t, !scopes[0].Regexp)
	assert.Check(t, is.Equal(scopes[1].Value, `^.+\.example\.com$`))
	assert.Check(t, scopes[1].Regexp)
	assert.Check(t, is.Len(ed.AttributeAuthorityDescriptors[0].Extensions.Other, 0))
}
