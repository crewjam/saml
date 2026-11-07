package saml

import (
	"testing"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func spSigningKeyDescriptors(sp *ServiceProvider) int {
	n := 0
	for _, kd := range sp.Metadata().SPSSODescriptors[0].KeyDescriptors {
		if kd.Use == "signing" {
			n++
		}
	}
	return n
}

// The SP metadata publishes the signing certificate whenever the SP signs
// messages the IdP has to verify with it, not only when AuthnRequests are
// signed.
func TestSPMetadataPublishesSigningKeyWhenSigning(t *testing.T) {
	testCases := []struct {
		name  string
		setup func(sp *ServiceProvider)
		want  int
	}{
		{"nothing signed", func(*ServiceProvider) {}, 0},
		{"AuthnRequests signed", func(sp *ServiceProvider) { sp.SignatureMethod = dsig.RSASHA256SignatureMethod }, 1},
		{"only logout messages signed", func(sp *ServiceProvider) { sp.LogoutSignatureMethod = dsig.RSASHA256SignatureMethod }, 1},
		{"SOAP single logout", func(sp *ServiceProvider) { sp.LogoutBindings = []string{SOAPBinding} }, 1},
		{"SOAP single logout without Key", func(sp *ServiceProvider) {
			sp.LogoutBindings = []string{SOAPBinding}
			sp.Key = nil
		}, 0},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			tc.setup(e.sp)
			assert.Check(t, is.Equal(tc.want, spSigningKeyDescriptors(e.sp)))
		})
	}
}
