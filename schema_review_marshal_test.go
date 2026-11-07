package saml

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// TestMarshalXMLOnValues checks that the custom MarshalXML methods of the
// protocol types are used when a value, not a pointer, is marshalled: the
// signature is written as XML and IssueInstant as a SAML time.
func TestMarshalXMLOnValues(t *testing.T) {
	zone := time.FixedZone("UTC+1", 3600)
	issueInstant := time.Date(2030, 1, 1, 1, 0, 0, 123456789, zone)
	signature := etree.NewElement("ds:Signature")
	signature.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")

	for name, v := range map[string]any{
		"AuthnRequest":     AuthnRequest{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
		"LogoutRequest":    LogoutRequest{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
		"LogoutResponse":   LogoutResponse{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
		"Response":         Response{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
		"ArtifactResolve":  ArtifactResolve{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
		"ArtifactResponse": ArtifactResponse{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
		"AttributeQuery":   AttributeQuery{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
		"Assertion":        Assertion{ID: "id", Version: "2.0", IssueInstant: issueInstant, Signature: signature},
	} {
		t.Run(name, func(t *testing.T) {
			for _, x := range []any{v, &v} {
				out, err := xml.Marshal(x)
				assert.NilError(t, err)
				assert.Check(t, is.Contains(string(out), `IssueInstant="2030-01-01T00:00:00.123Z"`))
				assert.Check(t, !strings.Contains(string(out), "<Space>"), string(out))
				assert.Check(t, !strings.Contains(string(out), "<Tag>"), string(out))
			}
		})
	}
}

// TestMarshalXMLOmitsEmptyOptionalAttributes checks that optional
// attributes that are unset are left out, rather than written as empty
// strings (AssertionConsumerServiceIndex="" is not a valid unsignedShort).
func TestMarshalXMLOmitsEmptyOptionalAttributes(t *testing.T) {
	req := AuthnRequest{
		ID:           "id",
		Version:      "2.0",
		IssueInstant: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		Issuer:       &Issuer{Value: "https://sp.example.com/"},
	}
	out, err := xml.Marshal(req)
	assert.NilError(t, err)
	for _, attr := range []string{
		"Destination", "Consent", "AssertionConsumerServiceIndex", "AssertionConsumerServiceURL",
		"ProtocolBinding", "AttributeConsumingServiceIndex", "ProviderName",
		"NameQualifier", "SPNameQualifier", "Format", "SPProvidedID",
	} {
		assert.Check(t, !strings.Contains(string(out), attr+`=`), "%s in %s", attr, out)
	}

	req.AssertionConsumerServiceURL = "https://sp.example.com/acs"
	out, err = xml.Marshal(req)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(out), `AssertionConsumerServiceURL="https://sp.example.com/acs"`))
}
