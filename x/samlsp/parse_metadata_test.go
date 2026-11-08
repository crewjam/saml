package samlsp_test

import (
	"errors"
	"fmt"
	"log"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func TestParseMetadata(t *testing.T) {
	ti := newTestIDP(t)
	signed := signedIDPMetadata(t, ti)
	_, otherCert := newKeyPair(t, "other")
	fedKey, fedCert := newKeyPair(t, "federation")
	idp2 := *ti.idp.Metadata()
	idp2.EntityID = "https://idp2.example.com/metadata"
	agg := signedAggregate(t, fedKey, fedCert, ti.idp.Metadata(), &idp2)

	for _, tt := range []struct {
		name   string
		data   []byte
		opts   []samlsp.MetadataOption
		entity string // "" for an error
	}{
		{"IdP", signed, nil, ti.idp.Metadata().EntityID},
		{"signed by a trusted certificate", signed, []samlsp.MetadataOption{samlsp.WithMetadataSigners(ti.cert)}, ti.idp.Metadata().EntityID},
		{"not signed by a trusted certificate", signed, []samlsp.MetadataOption{samlsp.WithMetadataSigners(otherCert)}, ""},
		{"aggregate, chosen", agg, []samlsp.MetadataOption{samlsp.WithIdentityProviderEntityID(idp2.EntityID)}, idp2.EntityID},
		{"aggregate, not chosen", agg, nil, ""},
		{"SP metadata", []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/saml/metadata"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`), nil, ""},
		{"not XML", []byte("not metadata"), nil, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			md, err := samlsp.ParseMetadata(tt.data, tt.opts...)
			if tt.entity == "" {
				if err == nil {
					t.Fatalf("no error; got %q", md.EntityID)
				}
				// StaticMetadataBytes fails the same way.
				if _, err2 := samlsp.StaticMetadataBytes(tt.data, tt.opts...)(t.Context()); err2 == nil || err2.Error() != err.Error() {
					t.Errorf("StaticMetadataBytes: %v, ParseMetadata: %v", err2, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if md.EntityID != tt.entity {
				t.Errorf("EntityID = %q, want %q", md.EntityID, tt.entity)
			}
		})
	}
}

// TestParseMetadataExpired checks that metadata is refused once a
// validUntil of the IdP's entity, of its roles, or of an aggregate around
// it has passed by the clock of WithClock.
func TestParseMetadataExpired(t *testing.T) {
	const (
		ns      = `xmlns="urn:oasis:names:tc:SAML:2.0:metadata"`
		sso     = `<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>`
		in2000  = `2000-06-01T00:00:00Z`
		entity  = `<EntityDescriptor ` + ns + ` entityID="https://idp.example.com/metadata" validUntil="` + in2000 + `"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sso + `</IDPSSODescriptor></EntityDescriptor>`
		idpRole = `<EntityDescriptor ` + ns + ` entityID="https://idp.example.com/metadata"><IDPSSODescriptor validUntil="` + in2000 + `" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sso + `</IDPSSODescriptor></EntityDescriptor>`
		aaRole  = `<EntityDescriptor ` + ns + ` entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sso + `</IDPSSODescriptor><AttributeAuthorityDescriptor validUntil="` + in2000 + `" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><AttributeService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://idp.example.com/aa"/></AttributeAuthorityDescriptor></EntityDescriptor>`
		agg     = `<EntitiesDescriptor ` + ns + ` validUntil="` + in2000 + `"><EntityDescriptor entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sso + `</IDPSSODescriptor></EntityDescriptor></EntitiesDescriptor>`
	)
	before := samlsp.WithClock(dsig.NewFakeClockAt(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)))
	for name, data := range map[string]string{"entity": entity, "IDPSSODescriptor": idpRole, "AttributeAuthorityDescriptor": aaRole, "aggregate": agg} {
		t.Run(name, func(t *testing.T) {
			if _, err := samlsp.ParseMetadata([]byte(data)); !errors.Is(err, saml.ErrExpired) {
				t.Errorf("err = %v, want saml.ErrExpired", err)
			}
			if _, err := samlsp.StaticMetadataBytes([]byte(data))(t.Context()); !errors.Is(err, saml.ErrExpired) {
				t.Errorf("StaticMetadataBytes: %v, want saml.ErrExpired", err)
			}
			if _, err := samlsp.ParseMetadata([]byte(data), before); err != nil {
				t.Errorf("before validUntil: %v", err)
			}
		})
	}
}

// Check an IdP's metadata when an administrator uploads it, and keep the
// parsed result to name the IdP per call with WithIdentityProvider.
func ExampleParseMetadata() {
	uploaded := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`)

	md, err := samlsp.ParseMetadata(uploaded)
	if err != nil {
		log.Fatal(err) // tell the administrator
	}
	fmt.Println(md.EntityID)

	_, err = samlsp.ParseMetadata([]byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/saml/metadata"/>`))
	fmt.Println(err)
	// Output:
	// https://idp.example.com/metadata
	// samlsp: invalid identity provider metadata: samlsp: metadata for "https://sp.example.com/saml/metadata" has no IDPSSODescriptor
}
