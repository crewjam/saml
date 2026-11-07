package saml

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

func TestAssertionEncrypterBlockCipher(t *testing.T) {
	methods := func(algorithms ...string) []EncryptionMethod {
		rv := make([]EncryptionMethod, 0, len(algorithms))
		for _, a := range algorithms {
			rv = append(rv, EncryptionMethod{Algorithm: a})
		}
		return rv
	}
	for _, tc := range []struct {
		name    string
		methods []EncryptionMethod
		want    string
	}{
		{"none listed keeps AES-128-CBC", nil, xmlenc.AES128CBC.Algorithm()},
		{"only key transport listed", methods("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"), xmlenc.AES128CBC.Algorithm()},
		{"CBC listed", methods(xmlenc.AES256CBC.Algorithm(), xmlenc.AES128CBC.Algorithm()), xmlenc.AES256CBC.Algorithm()},
		{"GCM preferred", methods(xmlenc.AES128CBC.Algorithm(), xmlenc.AES128GCM.Algorithm()), xmlenc.AES128GCM.Algorithm()},
		{"this package's SP", spEncryptionMethods(t), xmlenc.AES256GCM.Algorithm()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enc, ok := assertionEncrypter(nil, tc.methods).(xmlenc.RSA)
			assert.Assert(t, ok)
			assert.Check(t, is.Equal(tc.want, enc.BlockCipher.Algorithm()))
		})
	}

	configured := xmlenc.OAEP()
	configured.BlockCipher = xmlenc.AES192CBC
	enc, ok := assertionEncrypter(configured, methods(xmlenc.AES128GCM.Algorithm())).(xmlenc.RSA)
	assert.Assert(t, ok)
	assert.Check(t, is.Equal(xmlenc.AES192CBC.Algorithm(), enc.BlockCipher.Algorithm()), "a configured encrypter is used as is")
}

// spEncryptionMethods returns the EncryptionMethods the test SP lists for
// its encryption key.
func spEncryptionMethods(t *testing.T) []EncryptionMethod {
	t.Helper()
	_, methods, err := encryptionKey(NewIdentityProviderTest(t, applyKey).SP.Metadata().SPSSODescriptors[0].KeyDescriptors)
	assert.NilError(t, err)
	return methods
}
