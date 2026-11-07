package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

func TestCanParseMetadata(t *testing.T) {
	buf := golden.Get(t, "TestCanParseMetadata_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	assert.Check(t, err)

	var False = false
	var True = true

	expected := EntityDescriptor{
		EntityID:      "https://dev.aa.kndr.org/users/auth/saml/metadata",
		ID:            "_af805d1c-c2e3-444e-9cf5-efc664eeace6",
		ValidUntil:    time.Date(2001, time.February, 3, 4, 5, 6, 789000000, time.UTC),
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			{
				XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "SPSSODescriptor"},
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					},
				},
				AuthnRequestsSigned:  &False,
				WantAssertionsSigned: &False,
				AssertionConsumerServices: []IndexedEndpoint{
					{
						Binding:   "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
						Location:  "https://dev.aa.kndr.org/users/auth/saml/callback",
						Index:     0,
						IsDefault: &True,
					},
				},
				AttributeConsumingServices: []AttributeConsumingService{
					{
						Index:        1,
						IsDefault:    &True,
						ServiceNames: []LocalizedName{{Lang: "en", Value: "Required attributes"}},
						RequestedAttributes: []RequestedAttribute{
							{
								Attribute: Attribute{
									FriendlyName: "Email address",
									Name:         "email",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Full name",
									Name:         "name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Given name",
									Name:         "first_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
							{
								Attribute: Attribute{
									FriendlyName: "Family name",
									Name:         "last_name",
									NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
								},
							},
						},
					},
				},
			},
		},
	}
	assert.Check(t, is.DeepEqual(expected, metadata))

}

func TestCanProduceSPMetadata(t *testing.T) {
	validUntil, _ := time.Parse("2006-01-02T15:04:05.000000", "2013-03-10T00:32:19.104000")
	AuthnRequestsSigned := true
	WantAssertionsSigned := true
	metadata := EntityDescriptor{
		EntityID:      "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/metadata/",
		ValidUntil:    validUntil,
		CacheDuration: time.Hour,
		SPSSODescriptors: []SPSSODescriptor{
			{
				AuthnRequestsSigned:  &AuthnRequestsSigned,
				WantAssertionsSigned: &WantAssertionsSigned,
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{
												Data: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
											},
										},
									},
								},
							},
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{
												Data: `MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoX
DTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28x
EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308
kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTv
SPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gf
nqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90Dv
TLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+
cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==`,
											},
										},
									},
								},
							},
						},
					},

					SingleLogoutServices: []Endpoint{{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					}},
				},

				AssertionConsumerServices: []IndexedEndpoint{{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: "http://localhost:5000/e087a985171710fb9fb30f30f41384f9/saml2/ls/",
					Index:    1,
				}},
			},
		},
	}

	buf, err := xml.MarshalIndent(metadata, "", "  ")
	assert.Check(t, err)
	golden.Assert(t, string(buf), "TestCanProduceSPMetadata_expected")
}

func TestMetadataValidatesUrlSchemeForProtocolBinding(t *testing.T) {
	buf := golden.Get(t, "TestMetadataValidatesUrlSchemeForProtocolBinding_metadata.xml")

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(buf, &metadata)
	assert.Error(t, err, "invalid url scheme \"javascript\" for binding \"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
}

func TestEntityDescriptorOmitsUnsetValidUntil(t *testing.T) {
	// validUntil is optional; an unset value must not be rendered as the zero
	// time (which consumers would treat as already-expired metadata).
	buf, err := xml.Marshal(EntityDescriptor{EntityID: "https://sp.example.com/saml2/metadata"})
	assert.Check(t, err)
	assert.Check(t, is.Equal(string(buf),
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/saml2/metadata"></EntityDescriptor>`))

	// Round-tripping metadata without validUntil must not introduce one.
	var ed EntityDescriptor
	assert.Check(t, xml.Unmarshal(buf, &ed))
	assert.Check(t, ed.ValidUntil.IsZero())
	buf2, err := xml.Marshal(ed)
	assert.Check(t, err)
	assert.Check(t, is.Equal(string(buf), string(buf2)))

	// A set validUntil is still emitted.
	ed.ValidUntil = time.Date(2015, 12, 3, 1, 57, 9, 0, time.UTC)
	buf, err = xml.Marshal(ed)
	assert.Check(t, err)
	assert.Check(t, is.Contains(string(buf), `validUntil="2015-12-03T01:57:09Z"`))
}

func TestRoleDescriptorDurationsRoundTrip(t *testing.T) {
	// cacheDuration on a role descriptor is an xsd:duration and validUntil an
	// xsd:dateTime, exactly as on EntityDescriptor (saml-metadata-2.0-os §2.4.1).
	validUntil := time.Date(2030, time.January, 2, 3, 4, 5, 678000000, time.UTC)
	roleDescriptor := func() RoleDescriptor {
		vu := validUntil
		return RoleDescriptor{
			ValidUntil:                 &vu,
			CacheDuration:              time.Hour,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
		}
	}

	testCases := []struct {
		element string
		get     func(EntityDescriptor) []RoleDescriptor
		set     func(*EntityDescriptor)
	}{
		{
			element: "IDPSSODescriptor",
			get: func(ed EntityDescriptor) (rv []RoleDescriptor) {
				for _, d := range ed.IDPSSODescriptors {
					rv = append(rv, d.RoleDescriptor)
				}
				return rv
			},
			set: func(ed *EntityDescriptor) {
				ed.IDPSSODescriptors = []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: roleDescriptor()}}}
			},
		},
		{
			element: "SPSSODescriptor",
			get: func(ed EntityDescriptor) (rv []RoleDescriptor) {
				for _, d := range ed.SPSSODescriptors {
					rv = append(rv, d.RoleDescriptor)
				}
				return rv
			},
			set: func(ed *EntityDescriptor) {
				ed.SPSSODescriptors = []SPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: roleDescriptor()}}}
			},
		},
		{
			element: "AuthnAuthorityDescriptor",
			get: func(ed EntityDescriptor) (rv []RoleDescriptor) {
				for _, d := range ed.AuthnAuthorityDescriptors {
					rv = append(rv, d.RoleDescriptor)
				}
				return rv
			},
			set: func(ed *EntityDescriptor) {
				ed.AuthnAuthorityDescriptors = []AuthnAuthorityDescriptor{{RoleDescriptor: roleDescriptor()}}
			},
		},
		{
			element: "PDPDescriptor",
			get: func(ed EntityDescriptor) (rv []RoleDescriptor) {
				for _, d := range ed.PDPDescriptors {
					rv = append(rv, d.RoleDescriptor)
				}
				return rv
			},
			set: func(ed *EntityDescriptor) {
				ed.PDPDescriptors = []PDPDescriptor{{RoleDescriptor: roleDescriptor()}}
			},
		},
		{
			element: "AttributeAuthorityDescriptor",
			get: func(ed EntityDescriptor) (rv []RoleDescriptor) {
				for _, d := range ed.AttributeAuthorityDescriptors {
					rv = append(rv, d.RoleDescriptor)
				}
				return rv
			},
			set: func(ed *EntityDescriptor) {
				ed.AttributeAuthorityDescriptors = []AttributeAuthorityDescriptor{{RoleDescriptor: roleDescriptor()}}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.element, func(t *testing.T) {
			// Unmarshal
			input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/metadata">` +
				`<` + tc.element + ` protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" cacheDuration="PT1H" validUntil="2030-01-02T03:04:05.678Z"></` + tc.element + `>` +
				`</EntityDescriptor>`
			var ed EntityDescriptor
			assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
			got := tc.get(ed)
			assert.Assert(t, is.Len(got, 1))
			assert.Check(t, is.Equal(got[0].CacheDuration, time.Hour))
			assert.Assert(t, got[0].ValidUntil != nil)
			assert.Check(t, got[0].ValidUntil.Equal(validUntil))

			// Marshal
			ed = EntityDescriptor{EntityID: "https://example.com/metadata"}
			tc.set(&ed)
			buf, err := xml.Marshal(ed)
			assert.NilError(t, err)
			assert.Check(t, is.Contains(string(buf), `<`+tc.element+` `))
			assert.Check(t, is.Contains(string(buf), ` cacheDuration="PT1H"`))
			assert.Check(t, is.Contains(string(buf), ` validUntil="2030-01-02T03:04:05.678Z"`))

			// Round trip
			var ed2 EntityDescriptor
			assert.NilError(t, xml.Unmarshal(buf, &ed2))
			assert.Check(t, is.DeepEqual(tc.get(ed2), tc.get(ed)))
		})
	}
}

func TestRoleDescriptorOmitsUnsetDurations(t *testing.T) {
	ed := EntityDescriptor{
		EntityID: "https://example.com/metadata",
		IDPSSODescriptors: []IDPSSODescriptor{{SSODescriptor: SSODescriptor{RoleDescriptor: RoleDescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
		}}}},
		PDPDescriptors: []PDPDescriptor{{RoleDescriptor: RoleDescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
		}}},
	}
	buf, err := xml.Marshal(ed)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(buf),
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/metadata">`+
			`<IDPSSODescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></IDPSSODescriptor>`+
			`<PDPDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></PDPDescriptor>`+
			`</EntityDescriptor>`))

	var ed2 EntityDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &ed2))
	assert.Check(t, ed2.IDPSSODescriptors[0].ValidUntil == nil)
	assert.Check(t, is.Equal(ed2.IDPSSODescriptors[0].CacheDuration, time.Duration(0)))
}

func TestCanParseIDPMetadataWithRoleDescriptorCacheDuration(t *testing.T) {
	// IdP metadata in the wild sets cacheDuration (and sometimes validUntil,
	// without a time zone) on the IDPSSODescriptor rather than on the
	// EntityDescriptor.
	input := `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.example.com/saml2/idp">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="false" cacheDuration="PT604800S" validUntil="2030-01-02T03:04:05.678">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>MIIB</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml2/idp/sso"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml2/idp/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`

	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(input), &ed))
	assert.Assert(t, is.Len(ed.IDPSSODescriptors, 1))
	idp := ed.IDPSSODescriptors[0]
	assert.Check(t, is.Equal(idp.XMLName, xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "IDPSSODescriptor"}))
	assert.Check(t, is.Equal(idp.CacheDuration, 7*24*time.Hour))
	assert.Assert(t, idp.ValidUntil != nil)
	assert.Check(t, idp.ValidUntil.Equal(time.Date(2030, time.January, 2, 3, 4, 5, 678000000, time.UTC)))
	assert.Check(t, is.Len(idp.KeyDescriptors, 1))
	assert.Check(t, is.Len(idp.SingleSignOnServices, 2))
}
