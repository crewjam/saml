package samlsp_test

import (
	"fmt"
	"log"
	"testing"

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
