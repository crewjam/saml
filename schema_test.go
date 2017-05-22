package saml

import (
	"encoding/xml"
	"testing"
)

func TestAttributeXMLRoundTrip(t *testing.T) {
	expected := Attribute{
		FriendlyName: "TestFriendlyName",
		Name:         "TestName",
		NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		Values: []AttributeValue{AttributeValue{
			Type:  "xs:string",
			Value: "test",
		}},
	}

	x, err := xml.Marshal(expected)
	if err != nil {
		t.Fatalf("failed to marhsal AttributeValue to XML: %v", err)
	}

	var actual Attribute
	err = xml.Unmarshal(x, &actual)
	if err != nil {
		t.Fatalf("Failed to unrmarshall XML '%v': %v", string(x), err)
	}

	if actual.FriendlyName != expected.FriendlyName {
		t.Errorf("expected FriendlyName of '%v', got: %v", expected.FriendlyName, actual.FriendlyName)
	}

	if actual.Name != expected.Name {
		t.Errorf("expected Name of '%v', got: %v", expected.Name, actual.Name)
	}

	if actual.NameFormat != expected.NameFormat {
		t.Errorf("expected NameFormat of '%v', got: %v", expected.NameFormat, actual.NameFormat)
	}

	if len(actual.Values) != len(expected.Values) {
		t.Fatalf("expected %d values, got: %d", len(expected.Values), len(actual.Values))
	}

	for i, expectedValue := range expected.Values {
		actualValue := actual.Values[i]

		if expectedValue.Type != actualValue.Type {
			t.Fatalf("expected value %d to have Type of %s, but got %s", i, expectedValue.Type, actualValue.Type)
		}

		if expectedValue.Value != actualValue.Value {
			t.Fatalf("expected value %d to have Value of %s, but got %s", i, expectedValue.Value, actualValue.Value)
		}
	}
}
