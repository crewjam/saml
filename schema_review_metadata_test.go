package saml

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// TestRoleDescriptorCacheDurationAndValidUntil checks that the
// cacheDuration and validUntil attributes of a generic md:RoleDescriptor
// are read and written as xsd:duration and with RelaxedTime, like those of
// the concrete descriptor types.
func TestRoleDescriptorCacheDurationAndValidUntil(t *testing.T) {
	const in = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ` +
		`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ` +
		`xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" entityID="https://idp.example.com/">` +
		`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" ` +
		`cacheDuration="PT1H" validUntil="2030-01-01T00:00:00"/>` +
		`</EntityDescriptor>`

	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(in), &ed))
	assert.Assert(t, is.Len(ed.RoleDescriptors, 1))
	rd := ed.RoleDescriptors[0]
	assert.Check(t, is.Equal(rd.CacheDuration, time.Hour))
	assert.Assert(t, rd.ValidUntil != nil)
	assert.Check(t, rd.ValidUntil.Equal(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))

	out, err := xml.Marshal(ed)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(out), `cacheDuration="PT1H"`))
	assert.Check(t, is.Contains(string(out), `validUntil="2030-01-01T00:00:00Z"`))
	assert.Check(t, !strings.Contains(string(out), `cacheDuration="3600000000000"`), string(out))
}
