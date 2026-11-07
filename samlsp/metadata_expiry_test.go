package samlsp

import (
	"crypto/x509"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// testValidityAggregate nests an IDP in two EntitiesDescriptors that set
// validUntil and cacheDuration. The inner aggregate's validUntil is the
// earliest, and the entity's own cacheDuration the shortest.
const testValidityAggregate = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="id-aggregate" validUntil="2030-01-01T00:00:00Z" cacheDuration="PT24H">
  <EntitiesDescriptor validUntil="2001-01-01T00:00:00Z">
    <EntityDescriptor entityID="https://sp.example.org/shibboleth">
      <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="0"/>
      </SPSSODescriptor>
    </EntityDescriptor>
  </EntitiesDescriptor>
  <EntitiesDescriptor validUntil="2028-01-01T00:00:00Z" cacheDuration="PT6H">
    <EntityDescriptor entityID="https://idp.example.org/idp" validUntil="2029-01-01T00:00:00Z" cacheDuration="PT1H">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>
      </IDPSSODescriptor>
    </EntityDescriptor>
  </EntitiesDescriptor>
</EntitiesDescriptor>`

// testValidityOuterOnly has an IDP whose own policy is stricter than its
// parent's, after a closed aggregate whose stricter policy must not apply.
const testValidityOuterOnly = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2030-01-01T00:00:00Z" cacheDuration="PT24H">
  <EntitiesDescriptor validUntil="2001-01-01T00:00:00Z" cacheDuration="PT1M">
    <EntityDescriptor entityID="https://sp.example.org/shibboleth">
      <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="0"/>
      </SPSSODescriptor>
    </EntityDescriptor>
  </EntitiesDescriptor>
  <EntityDescriptor entityID="https://idp.example.org/idp" validUntil="2027-01-01T00:00:00Z">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`

const testValidityNone = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <EntitiesDescriptor>
    <EntityDescriptor entityID="https://idp.example.org/idp">
      <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>
      </IDPSSODescriptor>
    </EntityDescriptor>
  </EntitiesDescriptor>
</EntitiesDescriptor>`

// saml-metadata-2.0-os §4.3.1: "If metadata elements have parent elements
// which contain caching policies, the parent element takes precedence." The
// entity picked out of an EntitiesDescriptor carries the earliest validUntil
// and the shortest cacheDuration of itself and its enclosing aggregates.
func TestParseMetadataPropagatesParentValidity(t *testing.T) {
	signer := testMetadataSigner(t)
	certs := []*x509.Certificate{signer.cert}
	const entityID = "https://idp.example.org/idp"

	parsers := map[string]func(t *testing.T, doc string) (validUntil time.Time, cacheDuration time.Duration){
		"ParseMetadata": func(t *testing.T, doc string) (time.Time, time.Duration) {
			md, err := ParseMetadata([]byte(doc))
			assert.NilError(t, err)
			return md.ValidUntil, md.CacheDuration
		},
		"ParseMetadataByEntityID": func(t *testing.T, doc string) (time.Time, time.Duration) {
			md, err := ParseMetadataByEntityID([]byte(doc), entityID)
			assert.NilError(t, err)
			return md.ValidUntil, md.CacheDuration
		},
		"ParseSignedMetadata": func(t *testing.T, doc string) (time.Time, time.Duration) {
			md, err := ParseSignedMetadata(signer.sign(t, doc, nil), certs)
			assert.NilError(t, err)
			return md.ValidUntil, md.CacheDuration
		},
		"ParseSignedMetadataByEntityID": func(t *testing.T, doc string) (time.Time, time.Duration) {
			md, err := ParseSignedMetadataByEntityID(signer.sign(t, doc, nil), entityID, certs)
			assert.NilError(t, err)
			return md.ValidUntil, md.CacheDuration
		},
	}

	for name, parse := range parsers {
		t.Run(name, func(t *testing.T) {
			t.Run("parent policy is stricter", func(t *testing.T) {
				validUntil, cacheDuration := parse(t, testValidityAggregate)
				assert.Check(t, is.Equal(time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC), validUntil.UTC()))
				assert.Check(t, is.Equal(time.Hour, cacheDuration))
			})

			t.Run("own policy is stricter; closed aggregate ignored", func(t *testing.T) {
				validUntil, cacheDuration := parse(t, testValidityOuterOnly)
				assert.Check(t, is.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), validUntil.UTC()))
				assert.Check(t, is.Equal(24*time.Hour, cacheDuration))
			})

			t.Run("no policy set", func(t *testing.T) {
				validUntil, cacheDuration := parse(t, testValidityNone)
				assert.Check(t, validUntil.IsZero())
				assert.Check(t, is.Equal(time.Duration(0), cacheDuration))
			})
		})
	}
}

// Options.RejectExpiredIDPMetadata turns on the ServiceProvider's check of
// the IDP metadata's validUntil; it is off by default.
func TestOptionsRejectExpiredIDPMetadata(t *testing.T) {
	opts := Options{URL: mustParseURL("https://sp.example.com/")}
	assert.Check(t, !DefaultServiceProvider(opts).RejectExpiredIDPMetadata)
	opts.RejectExpiredIDPMetadata = true
	assert.Check(t, DefaultServiceProvider(opts).RejectExpiredIDPMetadata)
}
