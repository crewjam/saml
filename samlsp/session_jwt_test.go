package samlsp

import (
	"encoding/xml"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// TestJWTSessionCodecNewNameIDAttributeValue checks that an AttributeValue
// whose content is a <saml:NameID> element (e.g. eduPersonTargetedID) is
// stored in the session using the NameID's value. See issue #393.
func TestJWTSessionCodecNewNameIDAttributeValue(t *testing.T) {
	testCases := []struct {
		name string
		xml  string
	}{
		{
			name: "compact",
			xml: `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
				`<saml:AttributeStatement>` +
				`<saml:Attribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10">` +
				`<saml:AttributeValue><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">target-id-123</saml:NameID></saml:AttributeValue>` +
				`</saml:Attribute>` +
				`<saml:Attribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1">` +
				`<saml:AttributeValue>alice</saml:AttributeValue>` +
				`</saml:Attribute>` +
				`</saml:AttributeStatement>` +
				`</saml:Assertion>`,
		},
		{
			name: "pretty-printed",
			xml: `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:AttributeStatement>
    <saml:Attribute FriendlyName="eduPersonTargetedID" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10">
      <saml:AttributeValue>
        <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">target-id-123</saml:NameID>
      </saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute FriendlyName="uid" Name="urn:oid:0.9.2342.19200300.100.1.1">
      <saml:AttributeValue>alice</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var assertion saml.Assertion
			assert.NilError(t, xml.Unmarshal([]byte(tc.xml), &assertion))

			s, err := covSessionCodec(t).New(&assertion)
			assert.NilError(t, err)
			attrs := s.(JWTSessionClaims).GetAttributes()
			assert.Check(t, is.DeepEqual([]string{"target-id-123"}, attrs["eduPersonTargetedID"]))
			assert.Check(t, is.DeepEqual([]string{"alice"}, attrs["uid"]))
		})
	}
}
