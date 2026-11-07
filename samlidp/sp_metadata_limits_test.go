package samlidp

import (
	"io"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

type endlessReader struct{ read *int64 }

func (r endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	*r.read += int64(len(p))
	return len(p), nil
}

// The service endpoints read the request body as metadata; they must stop
// at MaxServiceMetadataSize rather than hold whatever the client sends.
func TestGetSPMetadataStopsReadingAtMaxServiceMetadataSize(t *testing.T) {
	defer func(old int64) { MaxServiceMetadataSize = old }(MaxServiceMetadataSize)
	MaxServiceMetadataSize = 1024

	var read int64
	_, err := getSPMetadata(io.LimitReader(endlessReader{read: &read}, 4<<20))
	assert.Check(t, is.Error(err, "metadata is larger than 1024 bytes (MaxServiceMetadataSize)"))
	assert.Check(t, read <= 1024+512, "read %d bytes", read)
}

// With several service providers in an aggregate, the first one is not
// necessarily the one meant, so none is registered.
func TestGetSPMetadataRequiresSingleSPInAggregate(t *testing.T) {
	sp := func(id string) string {
		return `<EntityDescriptor entityID="` + id + `"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></SPSSODescriptor></EntityDescriptor>`
	}
	_, err := getSPMetadata(strings.NewReader(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		sp("https://evil.example.com/") + `<EntitiesDescriptor>` + sp("https://sp.example.com/") + `</EntitiesDescriptor></EntitiesDescriptor>`))
	assert.Check(t, is.Error(err, "metadata holds 2 entities with an SPSSODescriptor; register them one at a time"))

	md, err := getSPMetadata(strings.NewReader(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><EntitiesDescriptor>` +
		sp("https://sp.example.com/") + `</EntitiesDescriptor></EntitiesDescriptor>`))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(md.EntityID, "https://sp.example.com/"))
}
