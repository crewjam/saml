package samlsp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/x/samlsp"
)

// A field that holds one value is not filled from an attribute with
// several: which comes first is up to the IdP, and a decision made on it
// could change with the order. The tag option first takes the first, as
// before.
func TestDecodeAttributesMultipleValuesIntoScalar(t *testing.T) {
	a := &samlsp.Assertion{Attributes: samlsp.Attributes{
		{Name: "role", Values: []string{"user", "admin"}},
		{Name: "level", Values: []string{"1", "2"}},
		{Name: "when", Values: []string{"2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"}},
		{Name: "levels", Values: []string{"low", "high"}},
	}}
	for _, tt := range []struct {
		name string
		v    any
	}{
		{"string", new(struct {
			X string `saml:"role"`
		})},
		{"*string", new(struct {
			X *string `saml:"role"`
		})},
		{"int", new(struct {
			X int `saml:"level"`
		})},
		{"time", new(struct {
			X time.Time `saml:"when"`
		})},
		{"[]byte", new(struct {
			X []byte `saml:"role"`
		})},
		{"TextUnmarshaler", new(struct {
			X level `saml:"levels"`
		})},
		{"with a format", new(struct {
			X string `saml:"role,format=unspecified"`
		})},
	} {
		err := a.DecodeAttributes(tt.v)
		if err == nil || !strings.Contains(err.Error(), "2 values") || !strings.Contains(err.Error(), "first") {
			t.Errorf("%s: err = %v, want an error about 2 values", tt.name, err)
		}
	}

	var first struct {
		Role    string    `saml:"role,first"`
		PRole   *string   `saml:"role,first"`
		Level   int       `saml:"level,first"`
		When    time.Time `saml:"when,first"`
		Lvl     level     `saml:"levels,first"`
		Formats string    `saml:"role,format=unspecified,first"`
		All     []string  `saml:"role"`
		OneOf   []string  `saml:"role,first"`
	}
	if err := a.DecodeAttributes(&first); err != nil {
		t.Fatal(err)
	}
	if first.Role != "user" || first.PRole == nil || *first.PRole != "user" || first.Level != 1 ||
		first.When.Year() != 2026 || first.Lvl != 1 || first.Formats != "user" {
		t.Errorf("with first: %+v", first)
	}
	if len(first.All) != 2 || len(first.OneOf) != 1 || first.OneOf[0] != "user" {
		t.Errorf("slices: %q, %q", first.All, first.OneOf)
	}

	// One value fills a scalar field without the option.
	one := &samlsp.Assertion{Attributes: samlsp.Attributes{{Name: "role", Values: []string{"admin"}}}}
	var single struct {
		Role string `saml:"role"`
	}
	if err := one.DecodeAttributes(&single); err != nil || single.Role != "admin" {
		t.Errorf("one value: %q, %v", single.Role, err)
	}
}
