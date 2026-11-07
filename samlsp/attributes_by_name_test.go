package samlsp

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// saml-core §2.7.3.1 (line 1204): FriendlyName's "value MUST NOT be used as
// a basis for formally identifying SAML attributes" (errata E49: they are
// identified by NameFormat and Name). With KeyAttributesByName, attributes
// that share a FriendlyName keep separate claims under their Names, and a
// FriendlyName cannot take another attribute's place. By default the claims
// are keyed by FriendlyName, as before.
func TestSpecCore_2_7_3_1_KeyAttributesByName(t *testing.T) {
	test := specMiddlewareTest(t)
	assertion := &saml.Assertion{AttributeStatements: []saml.AttributeStatement{{Attributes: []saml.Attribute{
		{FriendlyName: "role", Name: "urn:example:idp-asserted-role", Values: []saml.AttributeValue{{Value: "user"}}},
		{FriendlyName: "role", Name: "urn:example:self-asserted-role", Values: []saml.AttributeValue{{Value: "admin"}}},
		{FriendlyName: "urn:oid:2.5.4.3", Name: "urn:example:nickname", Values: []saml.AttributeValue{{Value: "spoofed"}}},
		{Name: "urn:oid:2.5.4.3", Values: []saml.AttributeValue{{Value: "Alice"}}},
	}}}}
	codec := DefaultSessionCodec(Options{URL: mustParseURL("https://sp.example.com/"), Key: test.Key})
	attributes := func(t *testing.T) Attributes {
		t.Helper()
		s, err := codec.New(assertion)
		assert.NilError(t, err)
		return s.(JWTSessionClaims).Attributes
	}

	t.Run("default keys by FriendlyName", func(t *testing.T) {
		got := attributes(t)
		assert.Check(t, is.DeepEqual([]string{"user", "admin"}, got["role"]))
		assert.Check(t, is.DeepEqual([]string{"spoofed", "Alice"}, got["urn:oid:2.5.4.3"]))
	})

	t.Run("KeyAttributesByName", func(t *testing.T) {
		codec = DefaultSessionCodec(Options{URL: mustParseURL("https://sp.example.com/"), Key: test.Key, KeyAttributesByName: true})
		got := attributes(t)
		assert.Check(t, is.DeepEqual([]string{"user"}, got["urn:example:idp-asserted-role"]))
		assert.Check(t, is.DeepEqual([]string{"admin"}, got["urn:example:self-asserted-role"]))
		assert.Check(t, is.DeepEqual([]string{"Alice"}, got["urn:oid:2.5.4.3"]))
		assert.Check(t, is.DeepEqual([]string{"spoofed"}, got["urn:example:nickname"]))
		_, ok := got["role"]
		assert.Check(t, !ok)
	})
}
