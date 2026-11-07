package saml

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// The SP encrypts the NameID of the LogoutRequests it makes to the IdP's
// encryption certificate, and the IdP decrypts it and ends the session.
func TestSPEncryptLogoutNameID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(t *testing.T, test *sloTest) (*http.Request, string)
	}{
		{"redirect", func(t *testing.T, test *sloTest) (*http.Request, string) {
			u, err := test.SP.MakeRedirectLogoutRequest(sloTestNameID, sloTestRelayState, WithSessionIndex(sloTestSessionIndex))
			assert.NilError(t, err)
			return httptest.NewRequest(http.MethodGet, u.String(), nil), redirectRequestID(t, u)
		}},
		{"post", func(t *testing.T, test *sloTest) (*http.Request, string) {
			req, err := test.SP.MakeLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID, WithSessionIndex(sloTestSessionIndex))
			assert.NilError(t, err)
			assert.Check(t, req.NameID == nil)
			assert.Check(t, req.EncryptedID != nil)
			assert.Check(t, req.Signature != nil)
			return test.postRequest(t, req), req.ID
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			test.SP.EncryptLogoutNameID = true
			enc := xmlenc.OAEP()
			enc.BlockCipher = xmlenc.AES256GCM
			test.SP.LogoutNameIDEncrypter = enc

			r, requestID := tc.request(t, test)
			w := test.serve(r)
			resp, err := test.SP.ParseLogoutResponse(spRequestForResponse(t, w), []string{requestID})
			assert.NilError(t, err)
			assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
			assert.Assert(t, is.Len(test.sessions.invalidated, 1))
			assert.Check(t, is.Equal("s1", test.sessions.invalidated[0].ID))
		})
	}
}

// redirectRequestID returns the ID of the LogoutRequest sent by u with the
// HTTP-Redirect binding, and checks that it carries an EncryptedID and no
// NameID.
func redirectRequestID(t *testing.T, u *url.URL) string {
	t.Helper()
	compressed, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	assert.NilError(t, err)
	var req LogoutRequest
	assert.NilError(t, xml.NewDecoder(newSaferFlateReader(bytes.NewReader(compressed))).Decode(&req))
	assert.Check(t, req.NameID == nil)
	assert.Check(t, req.EncryptedID != nil)
	return req.ID
}

func TestEncryptLogoutRequestNameIDErrors(t *testing.T) {
	test := newSLOTest(t)
	req := test.logoutRequest()
	req.NameID = nil
	assert.Check(t, errors.Is(test.SP.EncryptLogoutRequestNameID(req), ErrMissingElement))

	// The IdP metadata publishes only a signing certificate.
	for i := range test.SP.IDPMetadata.IDPSSODescriptors {
		descriptor := &test.SP.IDPMetadata.IDPSSODescriptors[i]
		var keyDescriptors []KeyDescriptor
		for _, kd := range descriptor.KeyDescriptors {
			if kd.Use == "signing" {
				keyDescriptors = append(keyDescriptors, kd)
			}
		}
		descriptor.KeyDescriptors = keyDescriptors
	}
	test.SP.EncryptLogoutNameID = true
	_, err := test.SP.MakeLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID)
	assert.Check(t, errors.Is(err, ErrMissingElement), "%v", err)
	assert.Check(t, is.ErrorContains(err, "cannot find an encryption certificate"))
	_, err = test.SP.MakeRedirectLogoutRequest(sloTestNameID, "")
	assert.Check(t, errors.Is(err, ErrMissingElement), "%v", err)
	_, err = test.SP.MakeSimpleSignLogoutRequest(sloTestNameID, "")
	assert.Check(t, errors.Is(err, ErrMissingElement), "%v", err)
}

// A certificate published with no use is used for encryption when there is
// none with use="encryption".
func TestGetIDPEncryptionCertUnspecifiedUse(t *testing.T) {
	test := newSLOTest(t)
	_, cert := aqKeyPair(t)
	test.SP.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors = []KeyDescriptor{
		{Use: "signing", KeyInfo: keyInfo(test.IDP.Certificate.Raw)},
		{KeyInfo: keyInfo(cert.Raw)},
	}
	got, err := test.SP.getIDPEncryptionCert()
	assert.NilError(t, err)
	assert.Check(t, got.Equal(cert))

	test.SP.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors = append(
		test.SP.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors,
		KeyDescriptor{Use: "encryption", KeyInfo: keyInfo(test.IDP.Certificate.Raw)})
	got, err = test.SP.getIDPEncryptionCert()
	assert.NilError(t, err)
	assert.Check(t, got.Equal(test.IDP.Certificate))

	test.SP.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors = []KeyDescriptor{
		{Use: "encryption", KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: "not base64!"}}}}},
	}
	_, err = test.SP.getIDPEncryptionCert()
	assert.Check(t, errors.Is(err, ErrInvalidCertificate), "%v", err)
}

func keyInfo(der []byte) KeyInfo {
	return KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{{Data: base64.StdEncoding.EncodeToString(der)}}}}
}

// An IdP that signs with a Signer alone publishes EncryptionCertificate and
// decrypts with DecryptionKeys.
func TestIDPDecryptionKeysWithSignerOnly(t *testing.T) {
	test := newSLOTest(t)
	test.IDP.Signer = test.IDP.Key.(*rsa.PrivateKey)
	test.IDP.Key = nil
	decryptionKey, encryptionCert := aqKeyPair(t)
	test.IDP.EncryptionCertificate = encryptionCert
	test.IDP.DecryptionKeys = []*rsa.PrivateKey{decryptionKey}

	// The metadata publishes EncryptionCertificate for encryption, and
	// Certificate for signing.
	test.SP.IDPMetadata = test.IDP.Metadata()
	for _, kd := range test.SP.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors {
		want := test.IDP.Certificate.Raw
		if kd.Use == "encryption" {
			want = encryptionCert.Raw
		}
		assert.Check(t, is.Equal(base64.StdEncoding.EncodeToString(want), kd.KeyInfo.X509Data.X509Certificates[0].Data), kd.Use)
	}

	test.SP.EncryptLogoutNameID = true
	req, err := test.SP.MakeLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID, WithSessionIndex(sloTestSessionIndex))
	assert.NilError(t, err)
	w := test.serve(test.postRequest(t, req))
	resp, err := test.SP.ParseLogoutResponse(spRequestForResponse(t, w), []string{req.ID})
	assert.NilError(t, err)
	assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
	assert.Assert(t, is.Len(test.sessions.invalidated, 1))
	assert.Check(t, is.Equal("s1", test.sessions.invalidated[0].ID))
}

// While the IdP encryption key is rotated, an EncryptedID encrypted to the
// previous certificate is decrypted with DecryptionKeys.
func TestIDPDecryptionKeysRollover(t *testing.T) {
	test := newSLOTest(t)
	oldKey, oldCert := aqKeyPair(t)
	logoutRequest := test.logoutRequest()
	logoutRequest.EncryptedID = encryptedNameID(t, logoutRequest.NameID.Element(), oldCert)
	logoutRequest.NameID = nil

	req, err := NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
	assert.NilError(t, err)
	err = req.Validate()
	assert.Check(t, errors.Is(err, ErrDecryptionFailed), "%v", err)

	otherKey, _ := aqKeyPair(t)
	test.IDP.DecryptionKeys = []*rsa.PrivateKey{nil, otherKey, oldKey}
	req, err = NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	assert.Check(t, is.Equal(sloTestNameID, req.Request.NameID.Value))

	// No key can decrypt it: each one tried is named in the error.
	test.IDP.DecryptionKeys = []*rsa.PrivateKey{otherKey}
	req, err = NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
	assert.NilError(t, err)
	err = req.Validate()
	assert.Check(t, errors.Is(err, ErrDecryptionFailed), "%v", err)
	assert.Check(t, is.ErrorContains(err, "Key: "))
	assert.Check(t, is.ErrorContains(err, "DecryptionKeys[0]: "))
}

const logoutRequestWithBaseID = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1" Version="2.0" IssueInstant="2014-01-01T00:00:00Z">` +
	`<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>` +
	`<saml:BaseID xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ex="urn:example" xsi:type="ex:Employee" NameQualifier="https://idp.example.com"><ex:Number>42</ex:Number></saml:BaseID>` +
	`<samlp:SessionIndex>one</samlp:SessionIndex>` +
	`</samlp:LogoutRequest>`

func TestLogoutRequestBaseIDXML(t *testing.T) {
	var req LogoutRequest
	assert.NilError(t, xml.Unmarshal([]byte(logoutRequestWithBaseID), &req))
	assert.Assert(t, req.BaseID != nil)
	assert.Check(t, is.Equal("BaseID", req.BaseID.Tag))
	assert.Check(t, is.Equal("ex:Employee", req.BaseID.SelectAttrValue("xsi:type", "")))
	assert.Check(t, is.Equal("42", req.BaseID.FindElement("./Number").Text()))
	assert.Check(t, req.NameID == nil)

	buf, err := xml.Marshal(&req)
	assert.NilError(t, err)
	assertChildOrder(t, buf, "Issuer", "BaseID", "SessionIndex")
	var roundTrip LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &roundTrip))
	assert.Assert(t, roundTrip.BaseID != nil)
	assert.Check(t, is.Equal("42", roundTrip.BaseID.FindElement("./Number").Text()))
	assert.Check(t, is.Equal("ex:Employee", roundTrip.BaseID.SelectAttrValue("xsi:type", "")))

	buf, err = req.Bytes()
	assert.NilError(t, err)
	assertChildOrder(t, buf, "Issuer", "BaseID", "SessionIndex")
}

// baseIDElement returns a saml:BaseID element for alice.
func baseIDElement() *etree.Element {
	el := etree.NewElement("saml:BaseID")
	el.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	el.CreateAttr("xmlns:ex", "urn:example")
	el.CreateAttr("xsi:type", "ex:Employee")
	el.CreateElement("ex:Number").SetText("42")
	return el
}

func TestIDPLogoutRequestBaseID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, test *sloTest, req *LogoutRequest)
	}{
		{"BaseID", func(_ *testing.T, _ *sloTest, req *LogoutRequest) {
			req.BaseID = baseIDElement()
		}},
		{"EncryptedID holding a BaseID", func(t *testing.T, test *sloTest, req *LogoutRequest) {
			req.EncryptedID = encryptedNameID(t, baseIDElement(), test.IDP.Certificate)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			test := newSLOTest(t)
			logoutRequest := test.logoutRequest()
			logoutRequest.NameID = nil
			tc.setup(t, test, logoutRequest)

			// Refused unless AcceptLogoutRequestBaseID is set.
			req, err := NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
			assert.NilError(t, err)
			err = req.Validate()
			assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
			assert.Check(t, is.Equal(http.StatusBadRequest, test.serve(test.redirectRequest(t, logoutRequest)).Code))
			assert.Check(t, is.Equal(0, test.sessions.calls))

			test.IDP.AcceptLogoutRequestBaseID = true
			req, err = NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
			assert.NilError(t, err)
			assert.NilError(t, req.Validate())
			assert.Check(t, req.Request.NameID == nil)
			assert.Assert(t, req.Request.BaseID != nil)
			assert.Check(t, is.Equal("42", req.Request.BaseID.FindElement("./Number").Text()))
			assert.Check(t, !req.MatchesSession(&Session{NameID: sloTestNameID, Index: sloTestSessionIndex}))

			// The SessionInvalidator is called, and matches no session.
			w := test.serve(test.redirectRequest(t, logoutRequest))
			resp, err := test.SP.ParseLogoutResponse(spRequestForResponse(t, w), []string{logoutRequest.ID})
			assert.NilError(t, err)
			assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
			assert.Check(t, is.Equal(1, test.sessions.calls))
			assert.Check(t, is.Len(test.sessions.invalidated, 0))
		})
	}
}

func TestIDPLogoutRequestSeveralIdentifiers(t *testing.T) {
	test := newSLOTest(t)
	test.IDP.AcceptLogoutRequestBaseID = true
	logoutRequest := test.logoutRequest()
	logoutRequest.BaseID = baseIDElement()

	req, err := NewIdpLogoutRequest(&test.IDP, test.redirectRequest(t, logoutRequest))
	assert.NilError(t, err)
	err = req.Validate()
	assert.Check(t, errors.Is(err, ErrMalformedMessage), "%v", err)
	assert.Check(t, is.ErrorContains(err, "more than one of BaseID, NameID and EncryptedID"))
}

// The SP accepts a BaseID in an IdP-initiated LogoutRequest only if
// AcceptLogoutRequestBaseID is set.
func TestValidateLogoutRequestBaseID(t *testing.T) {
	e := spcovSetup(t)
	req := e.logoutRequest()
	req.NameID = nil
	req.EncryptedID = encryptedNameID(t, baseIDElement(), e.sp.Certificate)
	signed := spcovSerialize(t, e.idpSign(t, req.Element()))

	_, err := e.sp.ValidateLogoutRequest(postRequestBytes(e.sp.SloURL.String(), signed))
	assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)

	e.sp.AcceptLogoutRequestBaseID = true
	got, err := e.sp.ValidateLogoutRequest(postRequestBytes(e.sp.SloURL.String(), signed))
	assert.NilError(t, err)
	assert.Check(t, got.NameID == nil)
	assert.Assert(t, got.BaseID != nil)
	assert.Check(t, is.Equal("ex:Employee", got.BaseID.SelectAttrValue("xsi:type", "")))
}
