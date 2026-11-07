package saml

import (
	"crypto/rsa"
	"encoding/xml"
	"errors"
	"net/http"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

const logoutRequestWithSessionIndexes = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1" Version="2.0" IssueInstant="2014-01-01T00:00:00Z">` +
	`<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>` +
	`<saml:NameID>alice@example.com</saml:NameID>` +
	`<samlp:SessionIndex>one</samlp:SessionIndex>` +
	`<samlp:SessionIndex>two</samlp:SessionIndex>` +
	`<samlp:SessionIndex>three</samlp:SessionIndex>` +
	`</samlp:LogoutRequest>`

func TestLogoutRequestSessionIndexesXML(t *testing.T) {
	var req LogoutRequest
	assert.NilError(t, xml.Unmarshal([]byte(logoutRequestWithSessionIndexes), &req))
	assert.Check(t, is.DeepEqual(&SessionIndex{Value: "one"}, req.SessionIndex))
	assert.Check(t, is.DeepEqual([]SessionIndex{{Value: "two"}, {Value: "three"}}, req.AdditionalSessionIndexes))
	assert.Check(t, is.DeepEqual([]SessionIndex{{Value: "one"}, {Value: "two"}, {Value: "three"}}, req.AllSessionIndexes()))
	assert.Check(t, is.Equal("alice@example.com", req.NameID.Value))

	// encoding/xml writes every SessionIndex, after the NameID.
	buf, err := xml.Marshal(&req)
	assert.NilError(t, err)
	var roundTrip LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &roundTrip))
	assert.Check(t, is.DeepEqual(req.AllSessionIndexes(), roundTrip.AllSessionIndexes()))
	assertChildOrder(t, buf, "Issuer", "NameID", "SessionIndex", "SessionIndex", "SessionIndex")

	// So does Element.
	buf, err = req.Bytes()
	assert.NilError(t, err)
	roundTrip = LogoutRequest{}
	assert.NilError(t, xml.Unmarshal(buf, &roundTrip))
	assert.Check(t, is.DeepEqual(req.AllSessionIndexes(), roundTrip.AllSessionIndexes()))
	assertChildOrder(t, buf, "Issuer", "NameID", "SessionIndex", "SessionIndex", "SessionIndex")
}

func TestLogoutRequestSingleSessionIndexUnchanged(t *testing.T) {
	var req LogoutRequest
	assert.NilError(t, xml.Unmarshal([]byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><samlp:SessionIndex>one</samlp:SessionIndex></samlp:LogoutRequest>`), &req))
	assert.Check(t, is.DeepEqual(&SessionIndex{Value: "one"}, req.SessionIndex))
	assert.Check(t, is.Nil(req.AdditionalSessionIndexes))

	req = LogoutRequest{}
	assert.NilError(t, xml.Unmarshal([]byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:LogoutRequest>`), &req))
	assert.Check(t, is.Nil(req.SessionIndex))
	assert.Check(t, is.Len(req.AllSessionIndexes(), 0))
}

// assertChildOrder checks the local names of the child elements of the root
// of buf.
func assertChildOrder(t *testing.T, buf []byte, tags ...string) {
	t.Helper()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	var got []string
	for _, el := range doc.Root().ChildElements() {
		got = append(got, el.Tag)
	}
	assert.Check(t, is.DeepEqual(tags, got))
}

func TestWithSessionIndexes(t *testing.T) {
	test := newSLOTest(t)
	req := test.SP.makeUnsignedLogoutRequest("https://idp.example.com/slo", "alice", WithSessionIndexes("a", "", "b"))
	assert.Check(t, is.DeepEqual([]SessionIndex{{Value: "a"}, {Value: "b"}}, req.AllSessionIndexes()))

	req = test.SP.makeUnsignedLogoutRequest("https://idp.example.com/slo", "alice", WithSessionIndexes("a", "b"), WithSessionIndex("c"))
	assert.Check(t, is.DeepEqual([]SessionIndex{{Value: "c"}}, req.AllSessionIndexes()))

	req = test.SP.makeUnsignedLogoutRequest("https://idp.example.com/slo", "alice", WithSessionIndexes())
	assert.Check(t, is.Nil(req.SessionIndex))
	assert.Check(t, is.Nil(req.AdditionalSessionIndexes))
}

func TestIdpLogoutRequestMatchesAnySessionIndex(t *testing.T) {
	req := &IdpLogoutRequest{Request: LogoutRequest{NameID: &NameID{Value: "alice"}}}
	req.Request.setSessionIndexes([]SessionIndex{{Value: "a"}, {Value: "b"}})
	assert.Check(t, req.MatchesSession(&Session{NameID: "alice", Index: "a"}))
	assert.Check(t, req.MatchesSession(&Session{NameID: "alice", Index: "b"}))
	assert.Check(t, !req.MatchesSession(&Session{NameID: "alice", Index: "c"}))
	assert.Check(t, !req.MatchesSession(&Session{NameID: "bob", Index: "b"}))
}

// A signed LogoutRequest with several SessionIndexes ends every session of
// the NameID with one of them.
func TestIDPServeSLOSeveralSessionIndexes(t *testing.T) {
	test := newSLOTest(t)
	req := test.SP.makeUnsignedLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID,
		WithSessionIndexes("other-index", sloTestSessionIndex))

	for name, r := range map[string]*http.Request{
		"redirect": test.redirectRequest(t, req),
		"post":     test.signedPostRequest(t, req),
	} {
		t.Run(name, func(t *testing.T) {
			test.sessions.invalidated = nil
			w := test.serve(r)
			assert.Check(t, w.Code == http.StatusFound || w.Code == http.StatusOK, w.Body.String())
			ids := []string{}
			for _, s := range test.sessions.invalidated {
				ids = append(ids, s.ID)
			}
			assert.Check(t, is.DeepEqual([]string{"s1", "s2"}, ids))
		})
	}
}

// encryptedNameID returns a saml:EncryptedID holding nameID, encrypted to
// the RSA key of cert.
func encryptedNameID(t *testing.T, nameID *etree.Element, cert interface{}) *etree.Element {
	t.Helper()
	nameID.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	doc := etree.NewDocument()
	doc.SetRoot(nameID)
	plaintext, err := doc.WriteToBytes()
	assert.NilError(t, err)

	encrypter := xmlenc.OAEP()
	encrypter.BlockCipher = xmlenc.AES128CBC
	encryptedData, err := encrypter.Encrypt(cert, plaintext, nil)
	assert.NilError(t, err)
	encryptedData.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	el := etree.NewElement("saml:EncryptedID")
	el.AddChild(encryptedData)
	return el
}

func (test *sloTest) encryptedIDLogoutRequest(t *testing.T) *LogoutRequest {
	req := test.logoutRequest()
	req.EncryptedID = encryptedNameID(t, req.NameID.Element(), test.IDP.Certificate)
	req.NameID = nil
	return req
}

func TestIDPServeSLOEncryptedID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request
	}{
		{"redirect", func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
			return test.redirectRequest(t, req)
		}},
		{"post", func(t *testing.T, test *sloTest, req *LogoutRequest) *http.Request {
			return test.signedPostRequest(t, req)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			logoutRequest := test.encryptedIDLogoutRequest(t)

			req, err := NewIdpLogoutRequest(&test.IDP, tc.request(t, test, logoutRequest))
			assert.NilError(t, err)
			assert.NilError(t, req.Validate())
			assert.Check(t, is.Equal(sloTestNameID, req.Request.NameID.Value))
			assert.Check(t, req.Request.EncryptedID != nil)

			logoutRequest.Signature = nil
			w := test.serve(tc.request(t, test, logoutRequest))
			resp, err := test.SP.ParseLogoutResponse(spRequestForResponse(t, w), []string{logoutRequest.ID})
			assert.NilError(t, err)
			assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
			assert.Assert(t, is.Len(test.sessions.invalidated, 1))
			assert.Check(t, is.Equal("s1", test.sessions.invalidated[0].ID))
		})
	}
}

func TestIDPServeSLOEncryptedIDRejected(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, test *sloTest, req *LogoutRequest)
		wantErr string
	}{
		{"both NameID and EncryptedID", func(_ *testing.T, test *sloTest, req *LogoutRequest) {
			req.NameID = test.logoutRequest().NameID
		}, "both a NameID and an EncryptedID"},
		{"encrypted to another key", func(t *testing.T, test *sloTest, req *LogoutRequest) {
			req.EncryptedID = encryptedNameID(t, test.logoutRequest().NameID.Element(), test.SP.Certificate)
		}, "cannot decrypt EncryptedID"},
		{"IdP key is not RSA", func(_ *testing.T, test *sloTest, _ *LogoutRequest) {
			test.IDP.Signer = test.IDP.Key.(*rsa.PrivateKey)
			test.IDP.Key = nil
		}, "IdentityProvider.Key is not an RSA private key"},
		{"EncryptedID without EncryptedData", func(_ *testing.T, _ *sloTest, req *LogoutRequest) {
			req.EncryptedID = etree.NewElement("saml:EncryptedID")
		}, "cannot decrypt EncryptedID"},
		{"EncryptedID holding something else", func(t *testing.T, test *sloTest, req *LogoutRequest) {
			issuer := etree.NewElement("saml:Issuer")
			issuer.SetText("x")
			req.EncryptedID = encryptedNameID(t, issuer, test.IDP.Certificate)
		}, "only saml:NameID is supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			logoutRequest := test.encryptedIDLogoutRequest(t)
			tc.setup(t, test, logoutRequest)

			req, err := NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
			assert.NilError(t, err)
			assert.Check(t, is.ErrorContains(req.Validate(), tc.wantErr))
			assert.Check(t, is.Equal(http.StatusBadRequest, test.serve(test.redirectRequest(t, logoutRequest)).Code))
			assert.Check(t, is.Equal(0, test.sessions.calls))
		})
	}
}

// The service provider decrypts an EncryptedID in an IdP-initiated
// LogoutRequest with its own key.
func TestValidateLogoutRequestEncryptedID(t *testing.T) {
	e := spcovSetup(t)
	req := e.logoutRequest()
	req.EncryptedID = encryptedNameID(t, req.NameID.Element(), e.sp.Certificate)
	req.NameID = nil
	req.setSessionIndexes([]SessionIndex{{Value: "a"}, {Value: "b"}})
	signed := spcovSerialize(t, e.idpSign(t, req.Element()))

	got, err := e.sp.ValidateLogoutRequest(postRequestBytes(e.sp.SloURL.String(), signed))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", got.NameID.Value))
	assert.Check(t, is.DeepEqual([]SessionIndex{{Value: "a"}, {Value: "b"}}, got.AllSessionIndexes()))

	// Encrypted to a key the SP does not hold.
	other := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
	req.EncryptedID = encryptedNameID(t, e.logoutRequest().NameID.Element(), other)
	signed = spcovSerialize(t, e.idpSign(t, req.Element()))
	_, err = e.sp.ValidateLogoutRequest(postRequestBytes(e.sp.SloURL.String(), signed))
	assert.Check(t, errors.Is(err, ErrDecryptionFailed), "%v", err)
}
