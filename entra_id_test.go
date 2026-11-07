package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// TestSPCanHandleEntraIDResponse covers responses shaped the way Microsoft
// Entra ID (Azure AD) sends them, for each of its "Signing Option" settings,
// with token encryption on, and IdP-initiated (issue #609).
//
// The fixtures are synthetic: they were generated and signed with a test key,
// not captured from a tenant, but they follow Entra's wire format, which is
// what broke in #605. The Response uses the samlp: prefix while the Issuer,
// Assertion and Signature are unprefixed and each declares its own default
// namespace. Signatures sit right after Issuer and use exclusive c14n with
// RSA-SHA256. The EncryptedAssertion uses WIF-style markup: an "e:" prefix on
// EncryptedKey and an unprefixed KeyInfo that references the SP certificate
// by issuer and serial number. The IdP metadata uses a default namespace, is
// signed, and carries a WS-Federation RoleDescriptor before the
// IDPSSODescriptor.
func TestSPCanHandleEntraIDResponse(t *testing.T) {
	const requestID = "id-4f6e2c9d8a7b1e3f5d0c2b4a6e8f1d3c5b7a9e0f"

	testCases := []struct {
		name         string
		idpInitiated bool
	}{
		{name: "assertion_signed"},
		{name: "response_signed"},
		{name: "response_and_assertion_signed"},
		{name: "encrypted_assertion_signed"},
		{name: "idp_initiated", idpInitiated: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			TimeNow = func() time.Time {
				return time.Date(2025, 6, 2, 15, 4, 6, 0, time.UTC)
			}
			Clock = dsig.NewFakeClockAt(TimeNow())
			t.Cleanup(func() {
				TimeNow = func() time.Time { return time.Now().UTC() }
				Clock = nil
			})

			s := ServiceProvider{
				Key:               mustParsePrivateKey(golden.Get(t, "sp_key.pem")),
				Certificate:       mustParseCertificate(golden.Get(t, "sp_cert.pem")),
				MetadataURL:       mustParseURL("https://sp.example.com/saml/metadata"),
				AcsURL:            mustParseURL("https://sp.example.com/saml/acs"),
				IDPMetadata:       &EntityDescriptor{},
				AllowIDPInitiated: tc.idpInitiated,
			}
			assert.NilError(t, xml.Unmarshal(golden.Get(t, "TestSPCanHandleEntraIDResponse_IDPMetadata"), s.IDPMetadata))
			assert.Check(t, s.IDPMetadata.Signature != nil)
			assert.Check(t, is.Equal(entraIDIssuer, s.IDPMetadata.EntityID))
			assert.Check(t, is.Equal("https://login.microsoftonline.com/8c3a9b2e-4f1d-4e6a-9b7c-2d5e8f1a3c4b/saml2",
				s.GetSSOBindingLocation(HTTPPostBinding)))

			respXML := golden.Get(t, "TestSPCanHandleEntraIDResponse_"+tc.name)

			// ParseXMLResponse is the call that failed in #605.
			possibleRequestIDs := []string{requestID}
			if tc.idpInitiated {
				possibleRequestIDs = nil
			}
			assertion, err := s.ParseXMLResponse(respXML, possibleRequestIDs, s.AcsURL)
			if err != nil {
				t.Fatalf("ParseXMLResponse: %v", err.(*InvalidResponseError).PrivateErr)
			}
			checkEntraIDAssertion(t, assertion)

			// And through the HTTP-POST binding.
			req := http.Request{PostForm: url.Values{}, URL: &s.AcsURL}
			req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(respXML))
			assertion, err = s.ParseResponse(&req, possibleRequestIDs)
			if err != nil {
				t.Fatalf("ParseResponse: %v", err.(*InvalidResponseError).PrivateErr)
			}
			checkEntraIDAssertion(t, assertion)
		})
	}
}

const entraIDIssuer = "https://sts.windows.net/8c3a9b2e-4f1d-4e6a-9b7c-2d5e8f1a3c4b/"

func checkEntraIDAssertion(t *testing.T, assertion *Assertion) {
	t.Helper()
	assert.Check(t, is.Equal("_d4e7f2a9-3b1c-4e6d-8f0a-5c2b9e7d1a38", assertion.ID))
	assert.Check(t, is.Equal(entraIDIssuer, assertion.Issuer.Value))
	assert.Assert(t, assertion.Subject != nil && assertion.Subject.NameID != nil)
	assert.Check(t, is.Equal("alice@contoso.example", assertion.Subject.NameID.Value))
	assert.Check(t, is.Equal(string(EmailAddressNameIDFormat), assertion.Subject.NameID.Format))
	assert.Assert(t, is.Len(assertion.AuthnStatements, 1))
	assert.Check(t, is.Equal("_d4e7f2a9-3b1c-4e6d-8f0a-5c2b9e7d1a38", assertion.AuthnStatements[0].SessionIndex))

	assert.Assert(t, is.Len(assertion.AttributeStatements, 1))
	got := map[string][]string{}
	for _, attr := range assertion.AttributeStatements[0].Attributes {
		for _, v := range attr.Values {
			got[attr.Name] = append(got[attr.Name], v.Value)
		}
	}
	assert.Check(t, is.DeepEqual(map[string][]string{
		"http://schemas.microsoft.com/identity/claims/tenantid":         {"8c3a9b2e-4f1d-4e6a-9b7c-2d5e8f1a3c4b"},
		"http://schemas.microsoft.com/identity/claims/objectidentifier": {"5e1c9a7f-2b4d-4a8e-9c3f-7d1b6e2a4c90"},
		"http://schemas.microsoft.com/identity/claims/displayname":      {"Alice Example"},
		"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": {
			"0f3b5d7e-1a2c-4e6f-8b9d-3c5e7f9a1b2d",
			"a7c9e1f3-5b7d-4f2a-8c4e-6d8f0a2c4e6b",
		},
		"http://schemas.microsoft.com/identity/claims/identityprovider": {entraIDIssuer},
		"http://schemas.microsoft.com/claims/authnmethodsreferences": {
			"http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password",
			"http://schemas.microsoft.com/claims/multipleauthn",
		},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":    {"Alice"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":      {"Example"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"alice@contoso.example"},
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         {"alice@contoso.example"},
	}, got))
}
