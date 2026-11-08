package samlmd

import (
	"encoding/xml"
	"errors"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestEntities(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	outer, inner := now.Add(2*time.Hour), now.Add(time.Hour)
	outerCache, innerCache := 30*time.Minute, time.Hour
	agg := saml.EntitiesDescriptor{
		ValidUntil:    &outer,
		CacheDuration: &outerCache,
		EntityDescriptors: []saml.EntityDescriptor{
			{EntityID: "a", ValidUntil: now.Add(3 * time.Hour)},
		},
		EntitiesDescriptors: []saml.EntitiesDescriptor{{
			ValidUntil:        &inner,
			CacheDuration:     &innerCache,
			EntityDescriptors: []saml.EntityDescriptor{{EntityID: "b", CacheDuration: 10 * time.Minute}},
		}},
	}
	data, err := xml.Marshal(agg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Entities(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].EntityID != "a" || got[1].EntityID != "b" {
		t.Fatalf("got %d entities", len(got))
	}
	if !got[0].ValidUntil.Equal(outer) || got[0].CacheDuration != outerCache {
		t.Errorf("a: %v %v", got[0].ValidUntil, got[0].CacheDuration)
	}
	if !got[1].ValidUntil.Equal(inner) || got[1].CacheDuration != 10*time.Minute {
		t.Errorf("b: %v %v", got[1].ValidUntil, got[1].CacheDuration)
	}

	one, err := xml.Marshal(saml.EntityDescriptor{EntityID: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Entities(one); err != nil || len(got) != 1 || got[0].EntityID != "c" {
		t.Errorf("EntityDescriptor: %v, %v", got, err)
	}
	for _, bad := range []string{"", "<x/>", "<EntitiesDescriptor xmlns='urn:x'/>"} {
		if _, err := Entities([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestValidityRoles(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	soon := now.Add(time.Minute)
	role := saml.RoleDescriptor{ValidUntil: &soon, CacheDuration: time.Second}
	md := &saml.EntityDescriptor{
		EntityID:                      "e",
		ValidUntil:                    now.Add(time.Hour),
		IDPSSODescriptors:             []saml.IDPSSODescriptor{{}},
		AttributeAuthorityDescriptors: []saml.AttributeAuthorityDescriptor{{RoleDescriptor: role}},
		SPSSODescriptors:              []saml.SPSSODescriptor{{}},
	}
	if v, c := Validity(md, IDPRoles); !v.Equal(soon) || c != time.Second {
		t.Errorf("IDPRoles: %v %v", v, c)
	}
	if v, c := Validity(md, SPRoles); !v.Equal(now.Add(time.Hour)) || c != 0 {
		t.Errorf("SPRoles: %v %v", v, c)
	}
	if err := Expired(md, IDPRoles, soon); !errors.Is(err, saml.ErrExpired) {
		t.Errorf("Expired: %v", err)
	}
	if err := Expired(md, SPRoles, soon); err != nil {
		t.Errorf("Expired by SP roles: %v", err)
	}
}
