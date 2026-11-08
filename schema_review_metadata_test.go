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

// TestEndpointLocationWhitespace checks that whitespace around an endpoint's
// Binding and Location, which xs:anyURI's whiteSpace="collapse" allows, is
// removed rather than making the whole document fail to parse.
func TestEndpointLocationWhitespace(t *testing.T) {
	const in = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/">` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<SingleLogoutService Binding=" urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + "\n\t" + `https://sp.example.com/slo " ResponseLocation=" https://sp.example.com/slo/response"/>` +
		`<AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location=" https://sp.example.com/acs" index="0"/>` +
		`</SPSSODescriptor>` +
		`</EntityDescriptor>`

	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(in), &ed))
	sp := ed.SPSSODescriptors[0]
	assert.Check(t, is.Equal(sp.SingleLogoutServices[0].Binding, HTTPRedirectBinding))
	assert.Check(t, is.Equal(sp.SingleLogoutServices[0].Location, "https://sp.example.com/slo"))
	assert.Check(t, is.Equal(sp.SingleLogoutServices[0].ResponseLocation, "https://sp.example.com/slo/response"))
	assert.Check(t, is.Equal(sp.AssertionConsumerServices[0].Location, "https://sp.example.com/acs"))
}

// TestSubjectConfirmationDataNotBeforeRelaxed checks that NotBefore is read
// with RelaxedTime like NotOnOrAfter, and that unset times are left out by
// MarshalXML as they are by Element.
func TestSubjectConfirmationDataNotBeforeRelaxed(t *testing.T) {
	const in = `<SubjectConfirmationData xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ` +
		`NotBefore="2030-01-01T00:00:00.000Z" NotOnOrAfter="2030-01-01T00:05:00Z" Recipient="https://sp.example.com/acs"/>`
	var scd SubjectConfirmationData
	assert.NilError(t, xml.Unmarshal([]byte(in), &scd))
	assert.Check(t, scd.NotBefore.Equal(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)))
	assert.Check(t, scd.NotOnOrAfter.Equal(time.Date(2030, 1, 1, 0, 5, 0, 0, time.UTC)))

	out, err := xml.Marshal(&SubjectConfirmationData{Recipient: "https://sp.example.com/acs"})
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(out), "NotBefore"), string(out))
	assert.Check(t, !strings.Contains(string(out), "NotOnOrAfter"), string(out))

	out, err = xml.Marshal(&Conditions{})
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(out), "NotBefore"), string(out))
	assert.Check(t, !strings.Contains(string(out), "NotOnOrAfter"), string(out))

	out, err = xml.Marshal(&Conditions{NotOnOrAfter: time.Date(2030, 1, 1, 0, 5, 0, 0, time.UTC)})
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(out), `NotOnOrAfter="2030-01-01T00:05:00Z"`))
}

// TestContactPersonsReplacedAfterParsing checks the documented way of
// replacing ContactPersons of parsed metadata: clearing the deprecated
// ContactPerson alias makes the new slice authoritative.
func TestContactPersonsReplacedAfterParsing(t *testing.T) {
	const in = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/">` +
		`<ContactPerson contactType="technical"><EmailAddress>mailto:old@example.com</EmailAddress></ContactPerson>` +
		`</EntityDescriptor>`
	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(in), &ed))

	ed.ContactPersons = []ContactPerson{{ContactType: "support", EmailAddresses: []string{"mailto:new@example.com"}}}
	ed.ContactPerson = nil
	out, err := xml.Marshal(ed)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(out), "mailto:new@example.com"))
	assert.Check(t, !strings.Contains(string(out), "mailto:old@example.com"), string(out))
}
