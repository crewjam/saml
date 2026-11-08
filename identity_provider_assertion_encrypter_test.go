package saml

import (
	"errors"
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

// cbcAssertionEncrypter is the encrypter the IdP used by default before it
// chose the block cipher from the SP's metadata: RSA-OAEP-MGF1P with a SHA-1
// digest and AES-128-CBC. Tests whose golden files hold an encrypted
// assertion set it, so that those files do not depend on the default.
func cbcAssertionEncrypter() xmlenc.Encrypter {
	encrypter := xmlenc.OAEP()
	encrypter.BlockCipher = xmlenc.AES128CBC
	encrypter.DigestMethod = &xmlenc.SHA1
	return encrypter
}

// encryptedAssertionAlgorithm makes and encrypts an assertion for a
// validated request from the test SP, after edit has adjusted the request,
// and returns the block cipher the EncryptedData names. It also checks
// that the SP's key decrypts it.
func encryptedAssertionAlgorithm(t *testing.T, edit func(*IdentityProviderTest, *IdpAuthnRequest)) string {
	t.Helper()
	test := NewIdentityProviderTest(t, applyKey)
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, authReq.Post("")))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	if edit != nil {
		edit(test, req)
	}
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", UserName: "alice"}))
	assert.NilError(t, req.MakeAssertionEl())

	encryptedData := req.AssertionEl.FindElement("./EncryptedData")
	assert.Assert(t, encryptedData != nil, "the assertion is encrypted")
	method := encryptedData.FindElement("./EncryptionMethod")
	assert.Assert(t, method != nil)
	_, err = xmlenc.Decrypt(test.SPKey, encryptedData)
	assert.NilError(t, err, "the SP's key decrypts the assertion")
	return method.SelectAttrValue("Algorithm", "")
}

// By default the assertion is encrypted with the strongest block cipher the
// SP's metadata lists: this package's SP lists AES-256-GCM.
func TestMakeAssertionElDefaultUsesGCMWhenListed(t *testing.T) {
	assert.Check(t, is.Equal(xmlenc.AES256GCM.Algorithm(), encryptedAssertionAlgorithm(t, nil)))
}

// An SP whose metadata lists no block cipher still gets AES-128-CBC, which
// every implementation can decrypt.
func TestMakeAssertionElDefaultFallsBackToCBC(t *testing.T) {
	alg := encryptedAssertionAlgorithm(t, func(_ *IdentityProviderTest, req *IdpAuthnRequest) {
		for i := range req.SPSSODescriptor.KeyDescriptors {
			req.SPSSODescriptor.KeyDescriptors[i].EncryptionMethods = nil
		}
	})
	assert.Check(t, is.Equal(xmlenc.AES128CBC.Algorithm(), alg))
}

// A configured AssertionEncrypter is used as is, whatever the SP lists.
func TestMakeAssertionElUsesConfiguredEncrypter(t *testing.T) {
	alg := encryptedAssertionAlgorithm(t, func(test *IdentityProviderTest, _ *IdpAuthnRequest) {
		test.IDP.AssertionEncrypter = cbcAssertionEncrypter()
	})
	assert.Check(t, is.Equal(xmlenc.AES128CBC.Algorithm(), alg))
}

// AssertionEncrypterFunc chooses the encrypter from what the SP lists, and
// its error refuses the assertion.
func TestMakeAssertionElAssertionEncrypterFunc(t *testing.T) {
	var got []string
	alg := encryptedAssertionAlgorithm(t, func(test *IdentityProviderTest, _ *IdpAuthnRequest) {
		test.IDP.AssertionEncrypterFunc = func(methods []EncryptionMethod) (xmlenc.Encrypter, error) {
			for _, m := range methods {
				got = append(got, m.Algorithm)
			}
			enc := xmlenc.OAEP_SHA256()
			enc.BlockCipher = xmlenc.AES128GCM
			return enc, nil
		}
	})
	assert.Check(t, is.Equal(xmlenc.AES128GCM.Algorithm(), alg))
	assert.Check(t, len(got) > 0, "the SP's EncryptionMethods are passed")

	test := NewIdentityProviderTest(t, applyKey)
	refused := errors.New("refused")
	test.IDP.AssertionEncrypterFunc = func([]EncryptionMethod) (xmlenc.Encrypter, error) { return nil, refused }
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, authReq.Post("")))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", UserName: "alice"}))
	assert.Check(t, is.ErrorIs(req.MakeAssertionEl(), refused))
}
