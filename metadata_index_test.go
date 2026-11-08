package saml

import (
	"encoding/xml"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The index attribute of an indexed endpoint is required (saml-metadata
// §2.2.3). encoding/xml reads a missing or empty one as 0, which made the
// endpoint the one chosen for AssertionConsumerServiceIndex="0" or for an
// artifact with EndpointIndex 0. Such an endpoint, and one whose index is
// not an xs:unsignedShort, is now refused.
func TestIndexedEndpointRequiresIndex(t *testing.T) {
	const acs = `<AssertionConsumerService xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ` +
		`Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"`
	for _, tc := range []struct {
		attr, wantErr string
		want          int
	}{
		{attr: ``, wantErr: "missing required index attribute"},
		{attr: ` index=""`, wantErr: `index "" is not an unsigned short`},
		{attr: ` index="-1"`, wantErr: `index "-1" is not an unsigned short`},
		{attr: ` index="65536"`, wantErr: `index "65536" is not an unsigned short`},
		{attr: ` x:index="0" xmlns:x="urn:x"`, wantErr: "missing required index attribute"},
		{attr: ` index="0"`, want: 0},
		{attr: ` index=" 7 "`, want: 7},
		{attr: ` index="65535"`, want: 65535},
	} {
		var ep IndexedEndpoint
		err := xml.Unmarshal([]byte(acs+tc.attr+`/>`), &ep)
		if tc.wantErr != "" {
			assert.Check(t, is.ErrorContains(err, tc.wantErr), tc.attr)
			continue
		}
		assert.Check(t, err, tc.attr)
		assert.Check(t, is.Equal(ep.Index, tc.want), tc.attr)
	}

	// The whole document is refused, as for an endpoint with a bad
	// Location, rather than keeping an endpoint that no index names.
	const md = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs"/>` +
		`</SPSSODescriptor></EntityDescriptor>`
	var ed EntityDescriptor
	assert.Check(t, is.ErrorContains(xml.Unmarshal([]byte(md), &ed), "AssertionConsumerService: missing required index attribute"))
}

// AttributeConsumingService also has a required index (saml-metadata
// §2.4.4.1), matched by AttributeConsumingServiceIndex.
func TestAttributeConsumingServiceRequiresIndex(t *testing.T) {
	const open = `<AttributeConsumingService xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`
	const body = `><ServiceName xml:lang="en">s</ServiceName></AttributeConsumingService>`
	var acs AttributeConsumingService
	assert.Check(t, is.ErrorContains(xml.Unmarshal([]byte(open+body), &acs), "missing required index attribute"))
	assert.Check(t, is.ErrorContains(xml.Unmarshal([]byte(open+` index="x"`+body), &acs), "is not an unsigned short"))
	assert.Check(t, xml.Unmarshal([]byte(open+` index="3"`+body), &acs))
	assert.Check(t, is.Equal(acs.Index, 3))
	assert.Assert(t, is.Len(acs.ServiceNames, 1))
	assert.Check(t, is.Equal(acs.ServiceNames[0].Value, "s"))
}
