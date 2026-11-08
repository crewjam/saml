package saml

import (
	"crypto/rsa"
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

// decryptionKeysFixture is a captured response whose assertion is encrypted
// to sp_key.pem.
type decryptionKeysFixture struct {
	name        string
	now         string
	idpMetadata string
	spURL       string
	response    func(t *testing.T) string
	requestID   string
	nameID      string
}

var decryptionKeysFixtures = []decryptionKeysFixture{
	{
		// The EncryptedKey is inside the EncryptedData's KeyInfo.
		name:        "nested EncryptedKey",
		now:         "Mon Dec 1 01:57:09 UTC 2015",
		idpMetadata: "SP_IDPMetadata",
		spURL:       "https://15661444.ngrok.io/saml2/",
		response: func(t *testing.T) string {
			return base64.StdEncoding.EncodeToString(golden.Get(t, "SP_SamlResponse"))
		},
		requestID: "id-9e61753d64e928af5a7a341a97f420c9",
		nameID:    "_41bd295976dadd70e1480f318e772841",
	},
	{
		// The EncryptedKey is beside the EncryptedData.
		name:        "sibling EncryptedKey",
		now:         "Tue Mar 3 19:24:28 UTC 2020",
		idpMetadata: "TestSPCanHandleOktaSignedResponseEncryptedAssertion_IDPMetadata",
		spURL:       "http://localhost:8000/saml/",
		response: func(t *testing.T) string {
			return string(golden.Get(t, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_response"))
		},
		requestID: "id-a7364d1e4432aa9085a7a8bd824ea2fa8fa8f684",
		nameID:    "testuser@testrsc.com",
	},
}

// parse parses the fixture's response at an SP whose Key, EncryptionKey and
// DecryptionKeys are set by configure.
func (f decryptionKeysFixture) parse(t *testing.T, configure func(sp *ServiceProvider)) (*Assertion, error) {
	t.Helper()
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", f.now)
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	sp := &ServiceProvider{
		Certificate: test.Certificate,
		MetadataURL: mustParseURL(f.spURL + "metadata"),
		AcsURL:      mustParseURL(f.spURL + "acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	assert.NilError(t, xml.Unmarshal(golden.Get(t, f.idpMetadata), sp.IDPMetadata))
	configure(sp)

	req := http.Request{PostForm: url.Values{}, URL: &sp.AcsURL}
	req.PostForm.Set("SAMLResponse", f.response(t))
	return sp.ParseResponse(&req, []string{f.requestID})
}

func decryptionKeysPrivateErr(t *testing.T, err error) string {
	t.Helper()
	ire, ok := err.(*InvalidResponseError)
	assert.Assert(t, ok, "got %v", err)
	return ire.PrivateErr.Error()
}

func testRSAKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	return mustParsePrivateKey(golden.Get(t, name)).(*rsa.PrivateKey)
}

// An assertion encrypted to one of DecryptionKeys decrypts, whatever key
// comes first and wherever the EncryptedKey is.
func TestSPDecryptsWithDecryptionKeys(t *testing.T) {
	ecKey, _ := newTestECDSAKeyAndCert(t)
	cases := []struct {
		name      string
		configure func(sp *ServiceProvider, right, wrong *rsa.PrivateKey)
	}{
		{"after Key", func(sp *ServiceProvider, right, wrong *rsa.PrivateKey) {
			sp.Key = wrong
			sp.DecryptionKeys = []*rsa.PrivateKey{right}
		}},
		{"after EncryptionKey", func(sp *ServiceProvider, right, wrong *rsa.PrivateKey) {
			sp.Key = right // not used for decryption, since EncryptionKey is set
			sp.EncryptionKey = wrong
			sp.DecryptionKeys = []*rsa.PrivateKey{wrong, right}
		}},
		{"after an ECDSA Key", func(sp *ServiceProvider, right, _ *rsa.PrivateKey) {
			sp.Key = ecKey
			sp.DecryptionKeys = []*rsa.PrivateKey{right}
		}},
		{"primary key still first", func(sp *ServiceProvider, right, wrong *rsa.PrivateKey) {
			sp.Key = right
			sp.DecryptionKeys = []*rsa.PrivateKey{wrong}
		}},
	}
	for _, f := range decryptionKeysFixtures {
		for _, c := range cases {
			t.Run(f.name+"/"+c.name, func(t *testing.T) {
				right := testRSAKey(t, "sp_key.pem")
				wrong := testRSAKey(t, "key_2017.pem")
				assertion, err := f.parse(t, func(sp *ServiceProvider) { c.configure(sp, right, wrong) })
				assert.NilError(t, err)
				assert.Check(t, is.Equal(f.nameID, assertion.Subject.NameID.Value))
			})
		}
	}
}

// When no key decrypts the assertion, the error names each key tried.
func TestSPDecryptionKeysNoneFits(t *testing.T) {
	for _, f := range decryptionKeysFixtures {
		t.Run(f.name, func(t *testing.T) {
			wrong := testRSAKey(t, "key_2017.pem")
			ecKey, _ := newTestECDSAKeyAndCert(t)

			_, err := f.parse(t, func(sp *ServiceProvider) {
				sp.Key = ecKey
				sp.DecryptionKeys = []*rsa.PrivateKey{wrong}
			})
			msg := decryptionKeysPrivateErr(t, err)
			assert.Check(t, is.Contains(msg, "failed to decrypt EncryptedAssertion: no decryption key could decrypt it: "))
			assert.Check(t, is.Contains(msg, "Key: "))
			assert.Check(t, is.Contains(msg, "expected key to be a *rsa.PrivateKey"))
			assert.Check(t, is.Contains(msg, "DecryptionKeys[0]: "))
			assert.Check(t, is.Contains(msg, "certificate does not match provided key"))
		})
	}
}

// Without DecryptionKeys the error is what it always was.
func TestSPWithoutDecryptionKeysErrorUnchanged(t *testing.T) {
	expected := map[string]string{
		"nested EncryptedKey":  "failed to decrypt EncryptedAssertion: certificate does not match provided key",
		"sibling EncryptedKey": "failed to decrypt EncryptedAssertion: failed to decrypt key from response: certificate does not match provided key",
	}
	for _, f := range decryptionKeysFixtures {
		t.Run(f.name, func(t *testing.T) {
			wrong := testRSAKey(t, "key_2017.pem")
			for _, keys := range [][]*rsa.PrivateKey{nil, {}} {
				_, err := f.parse(t, func(sp *ServiceProvider) {
					sp.Key = wrong
					sp.DecryptionKeys = keys
				})
				assert.Check(t, is.Equal(expected[f.name], decryptionKeysPrivateErr(t, err)))
			}
		})
	}
}

// With KeyOnlySigns, Key neither decrypts assertions nor is advertised for
// encryption; EncryptionKey and DecryptionKeys still decrypt.
func TestSPKeyOnlySigns(t *testing.T) {
	for _, f := range decryptionKeysFixtures {
		t.Run(f.name, func(t *testing.T) {
			right := testRSAKey(t, "sp_key.pem")
			_, err := f.parse(t, func(sp *ServiceProvider) {
				sp.Key = right
				sp.KeyOnlySigns = true
			})
			assert.Check(t, is.Contains(decryptionKeysPrivateErr(t, err), "no decryption key"))

			for name, configure := range map[string]func(sp *ServiceProvider){
				"EncryptionKey":  func(sp *ServiceProvider) { sp.EncryptionKey = right },
				"DecryptionKeys": func(sp *ServiceProvider) { sp.DecryptionKeys = []*rsa.PrivateKey{right} },
			} {
				assertion, err := f.parse(t, func(sp *ServiceProvider) {
					sp.Key = right
					sp.KeyOnlySigns = true
					configure(sp)
				})
				assert.NilError(t, err, name)
				assert.Check(t, is.Equal(f.nameID, assertion.Subject.NameID.Value), name)
			}
		})
	}

	test := NewServiceProviderTest(t)
	sp := &ServiceProvider{Key: test.Key, Certificate: test.Certificate, KeyOnlySigns: true,
		MetadataURL: mustParseURL("https://sp.example.com/metadata"), AcsURL: mustParseURL("https://sp.example.com/acs")}
	for _, kd := range sp.Metadata().SPSSODescriptors[0].KeyDescriptors {
		assert.Check(t, kd.Use != "encryption", "the signing certificate is advertised for encryption")
	}
}
