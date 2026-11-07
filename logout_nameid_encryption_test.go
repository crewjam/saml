package saml

import (
	"net/http"
	"os"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// blockCipherOf returns the algorithm of the EncryptedData in encryptedID.
func blockCipherOf(t *testing.T, encryptedID *etree.Element) string {
	t.Helper()
	assert.Assert(t, encryptedID != nil)
	method := encryptedID.FindElement("./EncryptedData/EncryptionMethod")
	assert.Assert(t, method != nil)
	return method.SelectAttrValue("Algorithm", "")
}

func TestIdentifierEncrypter(t *testing.T) {
	configured := &stubEncrypter{}
	assert.Check(t, identifierEncrypter(configured, nil) == xmlenc.Encrypter(configured))

	methods := func(algorithms ...string) []EncryptionMethod {
		rv := make([]EncryptionMethod, 0, len(algorithms))
		for _, algorithm := range algorithms {
			rv = append(rv, EncryptionMethod{Algorithm: algorithm})
		}
		return rv
	}
	for _, tc := range []struct {
		name    string
		methods []EncryptionMethod
		want    xmlenc.BlockCipher
	}{
		{"none listed", nil, xmlenc.AES256GCM},
		{"only key transport listed", methods("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"), xmlenc.AES256GCM},
		{"only CBC listed", methods(
			"http://www.w3.org/2001/04/xmlenc#aes128-cbc",
			"http://www.w3.org/2001/04/xmlenc#aes256-cbc",
			"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
		), xmlenc.AES256CBC},
		{"GCM preferred over CBC", methods(
			"http://www.w3.org/2001/04/xmlenc#aes128-cbc",
			xmlenc.AES128GCM.Algorithm(),
		), xmlenc.AES128GCM},
		{"AES-256-GCM first", methods(xmlenc.AES128GCM.Algorithm(), xmlenc.AES256GCM.Algorithm()), xmlenc.AES256GCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypter, ok := identifierEncrypter(nil, tc.methods).(xmlenc.RSA)
			assert.Assert(t, ok)
			assert.Check(t, is.Equal(tc.want.Algorithm(), encrypter.BlockCipher.Algorithm()))
			assert.Check(t, is.Equal(xmlenc.SHA1.Algorithm(), encrypter.DigestMethod.Algorithm()))
			assert.Check(t, is.Equal("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", encrypter.Algorithm()))
		})
	}
}

// stubEncrypter is an xmlenc.Encrypter that is never called.
type stubEncrypter struct{ xmlenc.Encrypter }

// The SP encrypts the NameID of its LogoutRequests with the strongest block
// cipher the IdP metadata lists, which for this package's IdP is
// AES-256-GCM, and the IdP decrypts it.
func TestSPEncryptLogoutNameIDDefaultCipher(t *testing.T) {
	test := newSLOTest(t)
	test.SP.EncryptLogoutNameID = true

	req, err := test.SP.MakeLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID, WithSessionIndex(sloTestSessionIndex))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(xmlenc.AES256GCM.Algorithm(), blockCipherOf(t, req.EncryptedID)))
	w := test.serve(test.postRequest(t, req))
	resp, err := test.SP.ParseLogoutResponse(spRequestForResponse(t, w), []string{req.ID})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
	assert.Assert(t, is.Len(test.sessions.invalidated, 1))

	// An IdP whose metadata lists only AES-CBC is sent AES-CBC.
	for i := range test.SP.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors {
		kd := &test.SP.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[i]
		if kd.Use == "encryption" {
			kd.EncryptionMethods = []EncryptionMethod{{Algorithm: xmlenc.AES128CBC.Algorithm()}}
		}
	}
	req, err = test.SP.MakeLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(xmlenc.AES128CBC.Algorithm(), blockCipherOf(t, req.EncryptedID)))
}

// The IdP encrypts the NameID of the LogoutRequests it sends to service
// providers that publish an encryption certificate, and sends it in the
// clear to the others.
func TestIDPInitiatedLogoutEncryptedNameID(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.EncryptLogoutNameID = true
	inClear := pt.sps[1].MetadataURL.String()
	pt.idp.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, id string) (*EntityDescriptor, error) {
			sp := pt.sp(id)
			if sp == nil {
				return nil, os.ErrNotExist
			}
			md := sp.Metadata()
			if id == inClear {
				// This SP publishes no encryption certificate.
				for i := range md.SPSSODescriptors {
					var keyDescriptors []KeyDescriptor
					for _, kd := range md.SPSSODescriptors[i].KeyDescriptors {
						if kd.Use != "encryption" {
							keyDescriptors = append(keyDescriptors, kd)
						}
					}
					md.SPSSODescriptors[i].KeyDescriptors = keyDescriptors
				}
			}
			return md, nil
		},
	}
	pt.login(t, pt.sps...)

	w := pt.run(t, pt.startLogout(propagationReturnURL))
	assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
	for _, sp := range pt.sps {
		id := sp.MetadataURL.String()
		reqs := pt.received[id]
		assert.Assert(t, is.Len(reqs, 1), id)
		assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value), id)
		assert.Check(t, is.Equal("idp-session-index", reqs[0].SessionIndex.Value), id)
		if id == inClear {
			assert.Check(t, reqs[0].EncryptedID == nil, id)
			continue
		}
		// The SP metadata lists AES-256-GCM first.
		assert.Check(t, is.Equal(xmlenc.AES256GCM.Algorithm(), blockCipherOf(t, reqs[0].EncryptedID)), id)
	}
}

// LogoutNameIDEncrypter, when set, is used whatever the metadata lists.
func TestIDPLogoutNameIDEncrypter(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.EncryptLogoutNameID = true
	encrypter := xmlenc.OAEP()
	encrypter.BlockCipher = xmlenc.AES128CBC
	pt.idp.LogoutNameIDEncrypter = encrypter
	pt.login(t, pt.sps[0])

	pt.run(t, pt.startLogout(propagationReturnURL))
	reqs := pt.received[pt.sps[0].MetadataURL.String()]
	assert.Assert(t, is.Len(reqs, 1))
	assert.Check(t, is.Equal(xmlenc.AES128CBC.Algorithm(), blockCipherOf(t, reqs[0].EncryptedID)))
	assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value))
}

// The NameID of a LogoutRequest sent over SOAP is encrypted too.
func TestIDPInitiatedLogoutOverSOAPEncryptedNameID(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.EncryptLogoutNameID = true
	soapSP := pt.addSOAPParticipant(t)
	pt.login(t, soapSP.sp)

	w := pt.startLogout("")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	reqs := soapSP.requests()
	assert.Assert(t, is.Len(reqs, 1))
	assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value))
	assert.Check(t, is.Equal(xmlenc.AES256GCM.Algorithm(), blockCipherOf(t, reqs[0].EncryptedID)))
	soapSP.checkNoErrors(t)
}
