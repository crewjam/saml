package saml

import (
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// The SP's metadata lists the content encryption algorithms it accepts in
// order of preference. IdPs that honour the list should pick AES-GCM, which
// is authenticated, over CBC, which is not.
func TestSPMetadataPrefersAESGCM(t *testing.T) {
	sp := ServiceProvider{
		Key:         mustParsePrivateKey(golden.Get(t, "sp_key.pem")),
		Certificate: mustParseCertificate(golden.Get(t, "sp_cert.pem")),
		MetadataURL: mustParseURL("https://sp.example.com/saml/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml/acs"),
	}
	var methods []string
	for _, kd := range sp.Metadata().SPSSODescriptors[0].KeyDescriptors {
		if kd.Use != "encryption" {
			continue
		}
		for _, m := range kd.EncryptionMethods {
			methods = append(methods, m.Algorithm)
		}
	}
	assert.Assert(t, len(methods) > 0)
	firstCBC, lastGCM := -1, -1
	for i, m := range methods {
		if strings.HasSuffix(m, "-cbc") && firstCBC < 0 {
			firstCBC = i
		}
		if strings.HasSuffix(m, "-gcm") {
			lastGCM = i
		}
	}
	assert.Check(t, is.Equal(methods[0], "http://www.w3.org/2009/xmlenc11#aes256-gcm"))
	assert.Check(t, lastGCM >= 0 && lastGCM < firstCBC, "%v", methods)
}
