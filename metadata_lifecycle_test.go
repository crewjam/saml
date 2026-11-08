package saml

import (
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	"gotest.tools/v3/assert/cmp"
)

func TestMetadataCacheDurationRoundTrip(t *testing.T) {
	testCases := []struct {
		name      string
		attribute string
		wantValue time.Duration
		wantSet   bool
	}{
		{name: "omitted"},
		{name: "zero", attribute: ` cacheDuration="PT0S"`, wantSet: true},
		{name: "nonzero", attribute: ` cacheDuration="PT1H"`, wantValue: time.Hour, wantSet: true},
	}

	for _, testCase := range testCases {
		t.Run("entity/"+testCase.name, func(t *testing.T) {
			input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.test/idp"` + testCase.attribute + `/>`
			var entity EntityDescriptor
			assert.NilError(t, xml.Unmarshal([]byte(input), &entity))
			assert.Equal(t, entity.CacheDuration, testCase.wantValue)
			assert.Equal(t, entity.metadataCacheDurationSet, testCase.wantSet && testCase.wantValue == 0)
			assertCacheDurationRoundTrips(t, entity, testCase.attribute)
		})

		t.Run("role/"+testCase.name, func(t *testing.T) {
			input := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.test/idp"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"` + testCase.attribute + `/></EntityDescriptor>`
			var entity EntityDescriptor
			assert.NilError(t, xml.Unmarshal([]byte(input), &entity))
			assert.Assert(t, cmp.Len(entity.IDPSSODescriptors, 1))
			role := entity.IDPSSODescriptors[0].RoleDescriptor
			assert.Equal(t, role.CacheDuration, testCase.wantValue)
			assert.Equal(t, role.metadataCacheDurationSet, testCase.wantSet && testCase.wantValue == 0)
			assertCacheDurationRoundTrips(t, entity, testCase.attribute)
		})

		t.Run("aggregate/"+testCase.name, func(t *testing.T) {
			input := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"` + testCase.attribute + `><EntityDescriptor entityID="https://example.test/idp"/></EntitiesDescriptor>`
			var aggregate EntitiesDescriptor
			assert.NilError(t, xml.Unmarshal([]byte(input), &aggregate))
			if testCase.wantSet {
				assert.Assert(t, aggregate.CacheDuration != nil)
				assert.Equal(t, *aggregate.CacheDuration, testCase.wantValue)
			} else {
				assert.Assert(t, aggregate.CacheDuration == nil)
			}
			encoded, err := xml.Marshal(&aggregate)
			assert.NilError(t, err)
			assertCacheDurationAttribute(t, string(encoded), testCase.attribute)
		})
	}
}

func assertCacheDurationRoundTrips(t *testing.T, entity EntityDescriptor, expectedAttribute string) {
	t.Helper()
	encoded, err := xml.Marshal(&entity)
	assert.NilError(t, err)
	assertCacheDurationAttribute(t, string(encoded), expectedAttribute)
}

func assertCacheDurationAttribute(t *testing.T, encoded, expectedAttribute string) {
	t.Helper()
	switch expectedAttribute {
	case "":
		assert.Assert(t, !containsCacheDuration(encoded), "unexpected cacheDuration in %s", encoded)
	case ` cacheDuration="PT0S"`, ` cacheDuration="PT1H"`:
		assert.Assert(t, containsCacheDuration(encoded), "missing cacheDuration in %s", encoded)
		assert.Assert(t, strings.Contains(encoded, expectedAttribute), "missing %s in %s", expectedAttribute, encoded)
	default:
		t.Fatalf("unexpected test attribute %q", expectedAttribute)
	}
}

func containsCacheDuration(encoded string) bool {
	return strings.Contains(encoded, `cacheDuration=`)
}

func TestFindEntityDescriptorAppliesEveryAggregatePolicy(t *testing.T) {
	now := time.Now().UTC()
	entityID := "https://example.test/idp"
	for _, level := range []string{"root", "middle", "inner"} {
		for _, policy := range []string{"validUntil", "cacheDuration"} {
			t.Run(level+"/"+policy, func(t *testing.T) {
				policyTime := now.Add(time.Hour)
				policyCache := time.Hour
				root, middle, inner := EntitiesDescriptor{}, EntitiesDescriptor{}, EntitiesDescriptor{}
				selected := map[string]*EntitiesDescriptor{"root": &root, "middle": &middle, "inner": &inner}[level]
				switch policy {
				case "validUntil":
					selected.ValidUntil = &policyTime
				case "cacheDuration":
					selected.CacheDuration = &policyCache
				}
				inner.EntityDescriptors = []EntityDescriptor{{
					EntityID:      entityID,
					ValidUntil:    now.Add(10 * time.Hour),
					CacheDuration: 10 * time.Hour,
				}}
				middle.EntitiesDescriptors = []EntitiesDescriptor{inner}
				root.EntitiesDescriptors = []EntitiesDescriptor{middle}

				entity := root.FindEntityDescriptor(entityID)
				assert.Assert(t, entity != nil)
				if policy == "validUntil" {
					assert.Assert(t, entity.ValidUntil.Equal(policyTime), "level %s policy was not applied", level)
				} else {
					assert.Equal(t, entity.CacheDuration, policyCache, "level %s policy was not applied", level)
				}
			})
		}
	}
}

func TestValidateMetadataAtChecksOnlyEntityValidity(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	entity := &EntityDescriptor{
		EntityID: "https://example.test/idp",
		PDPDescriptors: []PDPDescriptor{{
			RoleDescriptor: RoleDescriptor{ValidUntil: &past},
		}},
	}
	assert.NilError(t, entity.ValidateMetadataAt(now))
	assert.Assert(t, errors.Is(entity.PDPDescriptors[0].ValidateMetadataAt(now), ErrMetadataExpired))
}
