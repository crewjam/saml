package saml

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestMetadataCovEntitiesDescriptorRoundTrip(t *testing.T) {
	validUntil := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	cacheDuration := 36 * time.Hour
	name := "federation"
	in := EntitiesDescriptor{
		Name:          &name,
		ValidUntil:    &validUntil,
		CacheDuration: &cacheDuration,
		EntityDescriptors: []EntityDescriptor{
			{EntityID: "https://sp.example.com/metadata"},
		},
	}

	buf, err := xml.Marshal(in)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(buf), `validUntil="2030-01-02T03:04:05Z"`))
	assert.Check(t, is.Contains(string(buf), `cacheDuration="PT36H"`))

	var out EntitiesDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &out))
	assert.Check(t, is.Equal(validUntil, *out.ValidUntil))
	assert.Check(t, is.Equal(cacheDuration, *out.CacheDuration))
	assert.Check(t, is.Equal(name, *out.Name))
	assert.Check(t, is.Len(out.EntityDescriptors, 1))
	assert.Check(t, is.Equal("https://sp.example.com/metadata", out.EntityDescriptors[0].EntityID))
}

func TestMetadataCovEntitiesDescriptorWithoutOptionalAttrs(t *testing.T) {
	buf, err := xml.Marshal(EntitiesDescriptor{})
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(buf), "validUntil"))
	assert.Check(t, !strings.Contains(string(buf), "cacheDuration"))

	var out EntitiesDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &out))
	assert.Check(t, out.ValidUntil == nil)
	assert.Check(t, out.CacheDuration == nil)
}

func TestMetadataCovEntitiesDescriptorUnmarshalError(t *testing.T) {
	var out EntitiesDescriptor
	err := xml.Unmarshal([]byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" cacheDuration="bogus"/>`), &out)
	assert.Check(t, is.ErrorContains(err, "invalid duration"))
}

func TestMetadataCovCheckEndpointLocationBadURL(t *testing.T) {
	_, err := checkEndpointLocation(HTTPPostBinding, "://no-scheme")
	assert.Check(t, is.ErrorContains(err, "invalid url"))
}

func TestMetadataCovEndpointUnmarshal(t *testing.T) {
	testCases := []struct {
		name    string
		xml     string
		want    Endpoint
		wantErr string
	}{
		{
			name: "valid response location",
			xml:  `<Endpoint Binding="` + HTTPPostBinding + `" Location="https://a/" ResponseLocation="https://b/"/>`,
			want: Endpoint{Binding: HTTPPostBinding, Location: "https://a/", ResponseLocation: "https://b/"},
		},
		{
			name:    "bad location",
			xml:     `<Endpoint Binding="` + HTTPPostBinding + `" Location="ftp://a/"/>`,
			wantErr: `invalid url scheme "ftp"`,
		},
		{
			name:    "bad response location",
			xml:     `<Endpoint Binding="` + HTTPPostBinding + `" Location="https://a/" ResponseLocation="ftp://b/"/>`,
			wantErr: `invalid url scheme "ftp"`,
		},
		{
			name:    "truncated element",
			xml:     `<Endpoint Binding="` + HTTPPostBinding + `" Location="https://a/">`,
			wantErr: "EOF",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var got Endpoint
			err := xml.Unmarshal([]byte(tc.xml), &got)
			if tc.wantErr != "" {
				assert.Check(t, is.ErrorContains(err, tc.wantErr))
				return
			}
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(tc.want, got))
		})
	}
}

func TestMetadataCovIndexedEndpointUnmarshal(t *testing.T) {
	strPtr := func(s string) *string { return &s }
	testCases := []struct {
		name    string
		xml     string
		want    IndexedEndpoint
		wantErr string
	}{
		{
			name: "valid response location",
			xml:  `<E Binding="` + HTTPPostBinding + `" Location="https://a/" ResponseLocation="https://b/" index="1"/>`,
			want: IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://a/", ResponseLocation: strPtr("https://b/"), Index: 1},
		},
		{
			name: "unknown binding drops response location",
			xml:  `<E Binding="urn:idpcov:unknown" Location="whatever" ResponseLocation="whatever" index="2"/>`,
			want: IndexedEndpoint{Binding: "urn:idpcov:unknown", Index: 2},
		},
		{
			name:    "bad response location",
			xml:     `<E Binding="` + HTTPPostBinding + `" Location="https://a/" ResponseLocation="ftp://b/" index="1"/>`,
			wantErr: `invalid url scheme "ftp"`,
		},
		{
			name:    "bad index",
			xml:     `<E Binding="` + HTTPPostBinding + `" Location="https://a/" index="one"/>`,
			wantErr: "invalid syntax",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var got IndexedEndpoint
			err := xml.Unmarshal([]byte(tc.xml), &got)
			if tc.wantErr != "" {
				assert.Check(t, is.ErrorContains(err, tc.wantErr))
				return
			}
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(tc.want, got))
		})
	}
}
