package samlsp_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/crewjam/saml/attrname"
	"github.com/crewjam/saml/x/samlsp"
)

func TestAttributesLegacyMap(t *testing.T) {
	attrs := samlsp.Attributes{
		{Name: attrname.Mail, FriendlyName: "mail", Values: []string{"alice@example.com"}},
		{Name: "memberOf", Values: []string{"admins", "users"}},
		// Another attribute with the same FriendlyName: merged, in order.
		{Name: "urn:example:mail", FriendlyName: "mail", Values: []string{"a@example.org"}},
		{Name: "empty"},
	}
	want := map[string][]string{
		"mail":     {"alice@example.com", "a@example.org"},
		"memberOf": {"admins", "users"},
		"empty":    nil,
	}
	if got := attrs.LegacyMap(); !reflect.DeepEqual(got, want) {
		t.Errorf("LegacyMap() = %v, want %v", got, want)
	}
	if got := attrs.Get("mail"); got != "" {
		t.Errorf(`Get("mail") = %q; Get must not match FriendlyName`, got)
	}
}

// A setting that named an attribute by its FriendlyName under samlsp keeps
// working through LegacyMap.
func ExampleAttributes_LegacyMap() {
	attrs := samlsp.Attributes{
		{Name: attrname.Mail, FriendlyName: "mail", Values: []string{"alice@example.com"}},
	}
	userAttribute := "mail" // from configuration written for samlsp
	if v := attrs.LegacyMap()[userAttribute]; len(v) > 0 {
		fmt.Println(v[0])
	}
	// Output:
	// alice@example.com
}
