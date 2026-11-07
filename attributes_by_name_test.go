package saml

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// saml-core §2.7.3.1: FriendlyName "MUST NOT be used as a basis for formally
// identifying SAML attributes". AssertionAttributes.GetByName matches the
// Name only, so an attribute whose FriendlyName equals another's Name is
// not returned in its place.
func TestSpecCore_2_7_3_1_GetByNameIgnoresFriendlyName(t *testing.T) {
	aa := AssertionAttributes{
		{FriendlyName: "urn:oid:2.5.4.3", Name: "urn:example:nickname", Value: "spoofed"},
		{FriendlyName: "cn", Name: "urn:oid:2.5.4.3", Value: "Alice"},
	}
	got := aa.GetByName("urn:oid:2.5.4.3")
	assert.Assert(t, got != nil)
	assert.Check(t, is.Equal("Alice", got.Value))
	assert.Check(t, aa.GetByName("cn") == nil)
	assert.Check(t, is.Equal("spoofed", aa.Get("urn:oid:2.5.4.3").Value), "Get still matches FriendlyName first")
}
