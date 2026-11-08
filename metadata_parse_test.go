package saml

import (
	"strings"
	"testing"
)

func TestParseServiceProviderMetadata(t *testing.T) {
	const (
		ns  = `xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`
		sp  = `<EntityDescriptor entityID="https://sp.example.com/metadata"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="1"/></SPSSODescriptor></EntityDescriptor>`
		sp2 = `<EntityDescriptor entityID="https://sp2.example.com/metadata"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`
		idp = `<EntityDescriptor entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`
	)
	withNS := func(s string) string { return strings.Replace(s, "<EntityDescriptor ", "<EntityDescriptor "+ns+" ", 1) }

	for _, tc := range []struct {
		name, data, entityID, err string
	}{
		{"an SP", withNS(sp), "https://sp.example.com/metadata", ""},
		{"an aggregate with one SP", `<EntitiesDescriptor ` + ns + `>` + idp + sp + `</EntitiesDescriptor>`, "https://sp.example.com/metadata", ""},
		{"a nested aggregate with one SP", `<EntitiesDescriptor ` + ns + `>` + idp + `<EntitiesDescriptor>` + sp + `</EntitiesDescriptor></EntitiesDescriptor>`, "https://sp.example.com/metadata", ""},
		{"an IdP", withNS(idp), "", "has no SPSSODescriptor"},
		{"an aggregate without an SP", `<EntitiesDescriptor ` + ns + `>` + idp + `</EntitiesDescriptor>`, "", "describes no service provider"},
		{"an aggregate with two SPs", `<EntitiesDescriptor ` + ns + `>` + sp + sp2 + `</EntitiesDescriptor>`, "", "describes 2 service providers"},
		{"another element", `<Foo ` + ns + `/>`, "", "Foo is not an EntityDescriptor or EntitiesDescriptor"},
		{"another namespace", `<EntityDescriptor xmlns="urn:example"/>`, "", "is not SAML metadata"},
		{"not XML", `not XML`, "", "cannot read the metadata"},
		// A document that does not survive a round trip through
		// encoding/xml is refused before it is parsed.
		{"not round-trip safe", `<EntityDescriptor ` + ns + ` ::attr="x"></EntityDescriptor>`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			md, err := ParseServiceProviderMetadata([]byte(tc.data))
			if tc.entityID != "" {
				if err != nil {
					t.Fatal(err)
				}
				if md.EntityID != tc.entityID {
					t.Errorf("EntityID = %q, want %q", md.EntityID, tc.entityID)
				}
				return
			}
			if err == nil {
				t.Fatalf("no error; got %q", md.EntityID)
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Errorf("err = %v, want one containing %q", err, tc.err)
			}
		})
	}
}
