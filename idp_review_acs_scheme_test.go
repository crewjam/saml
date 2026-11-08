package saml

import (
	"errors"
	"net/http"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// An assertion consumer service whose Location is not an http or https URL,
// in metadata built in Go rather than parsed, is never used.
func TestIDPIgnoresNonHTTPACSLocations(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	const evil = "javascript:alert(1)"
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
			md := test.SP.Metadata()
			isDefault := true
			md.SPSSODescriptors[0].AssertionConsumerServices = append([]IndexedEndpoint{
				{Binding: HTTPPostBinding, Location: evil, Index: 9, IsDefault: &isDefault},
			}, md.SPSSODescriptors[0].AssertionConsumerServices...)
			return md, nil
		},
	}

	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	authReq.AssertionConsumerServiceURL = evil
	req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, authReq.Post("")))
	assert.NilError(t, err)
	err = req.Validate()
	assert.Check(t, errors.Is(err, ErrUnknownAssertionConsumerService), "%v", err)

	// Without a URL, the default is chosen among the usable endpoints.
	idpInitiated, err := test.IDP.NewIdpInitiatedRequest(nil, test.SP.MetadataURL.String(), "")
	assert.NilError(t, err)
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), idpInitiated.ACSEndpoint.Location))
}
