package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// PostBinding and MakeResponse return an error, rather than panic, for a
// request that was not validated, and PostBinding does not sign a response
// it cannot send.
func TestIDPPostBindingChecksEndpointFirst(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := &IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow()}

	_, err := req.PostBinding()
	assert.Check(t, is.ErrorContains(err, "no assertion consumer service endpoint"))
	assert.Check(t, is.ErrorContains(req.MakeResponse(), "no assertion consumer service endpoint"))

	req.ACSEndpoint = &IndexedEndpoint{Binding: HTTPArtifactBinding, Location: "https://sp.example.com/acs"}
	_, err = req.PostBinding()
	assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
	assert.Check(t, is.Nil(req.ResponseEl), "nothing is signed for a binding that cannot be used")

	req.ACSEndpoint.Binding = HTTPPostBinding
	_, err = req.PostBinding()
	assert.Check(t, is.ErrorContains(err, "no assertion"))
}
