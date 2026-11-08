package saml

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

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

// The logout state cookie is signed, not encrypted, so with
// EncryptLogoutNameID it holds the EncryptedIDs of the pending participants,
// not their NameIDs, and the LogoutRequests carry those EncryptedIDs.
func TestIDPLogoutStateCookieHoldsNoClearNameID(t *testing.T) {
	pt := newPropagationTest(t)
	pt.idp.EncryptLogoutNameID = true
	pt.login(t, pt.sps...)

	w := pt.startLogout(propagationReturnURL)
	state, err := pt.idp.decodeLogoutState(pt.cookieFrom(t, w).Value)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(state.Pending, len(pt.sps)-1))
	spCert := base64.StdEncoding.EncodeToString(pt.sps[0].Certificate.Raw)
	sealed := map[string]string{}
	for _, p := range state.Pending {
		assert.Check(t, p.NameID == nil, p.ServiceProviderID)
		assert.Check(t, p.EncryptedID != "", p.ServiceProviderID)
		// The certificate it is encrypted to is left out, to save room.
		assert.Check(t, !strings.Contains(p.EncryptedID, spCert), p.ServiceProviderID)
		sealed[p.ServiceProviderID] = p.EncryptedID
	}
	assert.Assert(t, state.Current != nil)
	assert.Check(t, is.DeepEqual(SessionParticipant{ServiceProviderID: state.Current.ServiceProviderID}, *state.Current))
	payload, err := json.Marshal(state)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(payload), "alice@example.com"), "%s", payload)

	w = pt.run(t, w)
	assert.Check(t, is.Equal(propagationReturnURL, w.Header().Get("Location")))
	for _, sp := range pt.sps {
		id := sp.MetadataURL.String()
		reqs := pt.received[id]
		assert.Assert(t, is.Len(reqs, 1), id)
		assert.Check(t, is.Equal("alice@example.com", reqs[0].NameID.Value), id)
		assert.Check(t, is.Equal("idp-session-index", reqs[0].SessionIndex.Value), id)
		assert.Assert(t, reqs[0].EncryptedID != nil, id)
		if want, ok := sealed[id]; ok {
			// The EncryptedID in the cookie is the one sent.
			doc := etree.NewDocument()
			doc.SetRoot(reqs[0].EncryptedID.Copy())
			got, err := doc.WriteToString()
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(cipherValues(t, want), cipherValues(t, got)), id)
			// The certificate is back in the request.
			assert.Check(t, strings.Contains(got, spCert), id)
		}
	}

	// Without EncryptLogoutNameID the cookie holds the NameIDs, as the
	// LogoutRequests do.
	pt = newPropagationTest(t)
	pt.login(t, pt.sps...)
	state, err = pt.idp.decodeLogoutState(pt.cookieFrom(t, pt.startLogout(propagationReturnURL)).Value)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(state.Pending, len(pt.sps)-1))
	for _, p := range state.Pending {
		assert.Check(t, p.NameID != nil && p.NameID.Value == "alice@example.com", p.ServiceProviderID)
		assert.Check(t, is.Equal("", p.EncryptedID))
	}
}

// cipherValues returns the text of the CipherValue elements in the
// serialized element s.
func cipherValues(t *testing.T, s string) []string {
	t.Helper()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(s))
	els := doc.FindElements("//CipherValue")
	values := make([]string, 0, len(els))
	for _, el := range els {
		values = append(values, el.Text())
	}
	assert.Check(t, len(values) > 0)
	return values
}

// A logout state written before NameIDs were sealed, with the participants
// in the shape of SessionParticipant, is still read.
func TestLogoutStateOldParticipantShapeIsRead(t *testing.T) {
	old := struct {
		Expires time.Time            `json:"exp"`
		Pending []SessionParticipant `json:"pending"`
	}{
		Expires: TimeNow().Add(time.Minute),
		Pending: []SessionParticipant{{
			ServiceProviderID: "https://sp.example.com/metadata",
			NameID:            NameID{Format: string(TransientNameIDFormat), Value: "alice"},
			SessionIndex:      "index",
		}},
	}
	payload, err := json.Marshal(old)
	assert.NilError(t, err)
	var state logoutState
	assert.NilError(t, json.Unmarshal(payload, &state))
	assert.Assert(t, is.Len(state.Pending, 1))
	participant, encryptedID, err := state.Pending[0].participant()
	assert.NilError(t, err)
	assert.Check(t, encryptedID == nil)
	assert.Check(t, is.DeepEqual(old.Pending[0], participant))
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
