package samlsp

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const twoIDPAggregate = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <EntityDescriptor entityID="https://evil.example.org/idp"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>
  <EntityDescriptor entityID="https://idp.example.org/idp"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>
</EntitiesDescriptor>`

// ParseMetadata takes the IDP out of an aggregate only if there is one. With
// several, the first one is not necessarily the IDP the caller means to
// trust: anyone who can add an entity to a federation's aggregate could
// otherwise become it.
func TestParseMetadataRequiresSingleIDPInAggregate(t *testing.T) {
	md, err := ParseMetadata([]byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <EntityDescriptor entityID="https://sp.example.org/sp"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>
  <EntityDescriptor entityID="https://idp.example.org/idp"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>
</EntitiesDescriptor>`))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(md.EntityID, "https://idp.example.org/idp"))

	_, err = ParseMetadata([]byte(twoIDPAggregate))
	assert.Check(t, is.Error(err, "metadata holds 2 entities with an IDPSSODescriptor; use ParseMetadataByEntityID to choose one"))

	md, err = ParseMetadataByEntityID([]byte(twoIDPAggregate), "https://idp.example.org/idp")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(md.EntityID, "https://idp.example.org/idp"))
}
