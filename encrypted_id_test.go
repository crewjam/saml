package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

var eidNameID = NameID{
	Format:          string(PersistentNameIDFormat),
	SPNameQualifier: "https://sp.example.com/saml/metadata",
	Value:           "alice-persistent-id",
}

// eidEncrypt encrypts el, serialized on its own, to cert and wraps it in a
// saml:EncryptedID, as an IdP does (saml-core §2.2.4).
func eidEncrypt(t *testing.T, cert *x509.Certificate, el *etree.Element) *etree.Element {
	t.Helper()
	encryptor := xmlenc.OAEP()
	encryptor.BlockCipher = xmlenc.AES128CBC
	encryptor.DigestMethod = &xmlenc.SHA1
	encryptedDataEl, err := encryptor.Encrypt(cert, spcovSerialize(t, el), nil)
	assert.NilError(t, err)
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	encryptedIDEl := etree.NewElement("saml:EncryptedID")
	encryptedIDEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	encryptedIDEl.AddChild(encryptedDataEl)
	return encryptedIDEl
}

// eidNameIDEl returns nameID as a standalone saml:NameID element.
func eidNameIDEl(nameID NameID) *etree.Element {
	el := nameID.Element()
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	return el
}

// encryptedID returns nameID encrypted to the SP.
func (e *spcovEnv) encryptedID(t *testing.T, nameID NameID) *etree.Element {
	t.Helper()
	return eidEncrypt(t, e.sp.Certificate, eidNameIDEl(nameID))
}

func TestSubjectEncryptedIDRoundTrip(t *testing.T) {
	e := spcovSetup(t)
	encryptedID := e.encryptedID(t, eidNameID)
	subject := Subject{
		EncryptedID: encryptedID,
		SubjectConfirmations: []SubjectConfirmation{{
			Method:      bearerSubjectConfirmationMethod,
			EncryptedID: encryptedID,
		}},
	}
	want := string(spcovSerialize(t, encryptedID.Copy()))

	// Element writes the EncryptedID, and can be called again.
	for i := 0; i < 2; i++ {
		el := subject.Element()
		got := el.FindElement("./EncryptedID")
		assert.Assert(t, got != nil)
		assert.Check(t, is.Equal(string(spcovSerialize(t, got.Copy())), want))
		assert.Assert(t, el.FindElement("./SubjectConfirmation/EncryptedID") != nil)
	}

	// encoding/xml round trips it.
	buf, err := xml.Marshal(&subject)
	assert.NilError(t, err)
	var decoded Subject
	assert.NilError(t, xml.Unmarshal(buf, &decoded))
	assert.Check(t, is.Equal(decoded.XMLName.Local, "Subject"))
	assert.Check(t, decoded.NameID == nil)
	assert.Assert(t, decoded.EncryptedID != nil)
	assert.Check(t, is.Equal(string(spcovSerialize(t, decoded.EncryptedID.Copy())), want))
	assert.Assert(t, is.Len(decoded.SubjectConfirmations, 1))
	assert.Assert(t, decoded.SubjectConfirmations[0].EncryptedID != nil)
	assert.Check(t, is.Equal(decoded.SubjectConfirmations[0].Method, bearerSubjectConfirmationMethod))

	// and inside an Assertion.
	buf, err = xml.Marshal(&Assertion{ID: "id-assertion", Subject: &subject})
	assert.NilError(t, err)
	var decodedAssertion Assertion
	assert.NilError(t, xml.Unmarshal(buf, &decodedAssertion))
	assert.Assert(t, decodedAssertion.Subject != nil && decodedAssertion.Subject.EncryptedID != nil)
	assert.Check(t, is.Equal(string(spcovSerialize(t, decodedAssertion.Subject.EncryptedID.Copy())), want))

	// So does Element followed by unmarshalElement. (Element leaves the saml
	// prefix to be declared by the enclosing Assertion.)
	subjectEl := subject.Element()
	subjectEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	var fromElement Subject
	assert.NilError(t, unmarshalElement(subjectEl, &fromElement))
	assert.Assert(t, fromElement.EncryptedID != nil)
	assert.Check(t, is.Equal(string(spcovSerialize(t, fromElement.EncryptedID.Copy())), want))
}

// eidAssertion is e.assertion() with its Subject NameID encrypted.
func (e *spcovEnv) eidAssertion(t *testing.T, nameID NameID) *Assertion {
	t.Helper()
	assertion := e.assertion()
	assertion.Subject.NameID = nil
	assertion.Subject.EncryptedID = e.encryptedID(t, nameID)
	return assertion
}

func TestSPDecryptsSubjectEncryptedID(t *testing.T) {
	testCases := []struct {
		name     string
		response func(t *testing.T, e *spcovEnv, assertion *Assertion) []byte
	}{
		{"signed response", func(t *testing.T, e *spcovEnv, assertion *Assertion) []byte {
			r := e.response()
			r.Assertion = assertion
			return spcovSerialize(t, e.idpSign(t, r.Element()))
		}},
		{"signed assertion", func(t *testing.T, e *spcovEnv, assertion *Assertion) []byte {
			el := e.response().Element()
			el.AddChild(e.idpSign(t, assertion.Element()))
			return spcovSerialize(t, el)
		}},
		{"encrypted signed assertion", func(t *testing.T, e *spcovEnv, assertion *Assertion) []byte {
			el := e.response().Element()
			el.AddChild(e.encryptedAssertion(t, spcovSerialize(t, e.idpSign(t, assertion.Element()))))
			return spcovSerialize(t, el)
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			assertion := e.eidAssertion(t, eidNameID)
			got, err := e.sp.ParseXMLResponse(tc.response(t, e, assertion), []string{spcovRequestID}, e.sp.AcsURL)
			assert.NilError(t, err)
			assert.Assert(t, got.Subject.NameID != nil)
			assert.Check(t, is.DeepEqual(*got.Subject.NameID, eidNameID))
			assert.Check(t, is.Nil(got.Subject.EncryptedID))

			// Marshalled again, the Subject holds only the NameID.
			subjectEl := got.Subject.Element()
			assert.Check(t, subjectEl.FindElement("./NameID") != nil)
			assert.Check(t, is.Nil(subjectEl.FindElement("./EncryptedID")))
		})
	}
}

func TestSPDecryptsSubjectEncryptedIDWithDecryptionKeys(t *testing.T) {
	e := spcovSetup(t)
	e.sp.Key = testRSAKey(t, "key_2017.pem")
	e.sp.DecryptionKeys = []*rsa.PrivateKey{testRSAKey(t, "sp_key.pem")}

	r := e.response()
	r.Assertion = e.eidAssertion(t, eidNameID)
	got, err := e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Assert(t, got.Subject.NameID != nil)
	assert.Check(t, is.Equal(got.Subject.NameID.Value, eidNameID.Value))
}

func TestSPDecryptsSubjectConfirmationEncryptedID(t *testing.T) {
	e := spcovSetup(t)
	assertion := e.assertion()
	assertion.Subject.SubjectConfirmations[0].EncryptedID = e.encryptedID(t, NameID{Value: "presenter"})
	r := e.response()
	r.Assertion = assertion
	got, err := e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(got.Subject.NameID.Value, "alice@example.com"))
	assert.Assert(t, got.Subject.SubjectConfirmations[0].NameID != nil)
	assert.Check(t, is.Equal(got.Subject.SubjectConfirmations[0].NameID.Value, "presenter"))
	assert.Check(t, is.Nil(got.Subject.SubjectConfirmations[0].EncryptedID))
}

func TestSPRejectsBadSubjectEncryptedID(t *testing.T) {
	testCases := []struct {
		name        string
		encryptedID func(t *testing.T, e *spcovEnv) *etree.Element
		keepNameID  bool
		kind        error
		wantErr     string
	}{
		{
			name: "encrypted to another key",
			encryptedID: func(t *testing.T, _ *spcovEnv) *etree.Element {
				return eidEncrypt(t, mustParseCertificate(golden.Get(t, "cert_2017.pem")), eidNameIDEl(eidNameID))
			},
			kind:    ErrDecryptionFailed,
			wantErr: "assertion Subject: cannot decrypt EncryptedID",
		},
		{
			name: "holds an Issuer",
			encryptedID: func(t *testing.T, e *spcovEnv) *etree.Element {
				el := (&Issuer{Value: "alice"}).Element()
				el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
				return eidEncrypt(t, e.sp.Certificate, el)
			},
			kind:    ErrUnsupported,
			wantErr: "assertion Subject: EncryptedID holds a saml:Issuer element, only saml:NameID is supported",
		},
		{
			name: "holds a NameID in another namespace",
			encryptedID: func(t *testing.T, e *spcovEnv) *etree.Element {
				el := etree.NewElement("NameID")
				el.CreateAttr("xmlns", "urn:example:not-saml")
				el.SetText("alice-persistent-id")
				return eidEncrypt(t, e.sp.Certificate, el)
			},
			kind:    ErrUnsupported,
			wantErr: "assertion Subject: EncryptedID holds a NameID element, only saml:NameID is supported",
		},
		{
			name: "beside a NameID",
			encryptedID: func(t *testing.T, e *spcovEnv) *etree.Element {
				return e.encryptedID(t, eidNameID)
			},
			keepNameID: true,
			kind:       ErrMalformedMessage,
			wantErr:    "assertion Subject: has both a NameID and an EncryptedID",
		},
		{
			name: "no EncryptedData",
			encryptedID: func(_ *testing.T, _ *spcovEnv) *etree.Element {
				el := etree.NewElement("saml:EncryptedID")
				el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
				return el
			},
			kind:    ErrDecryptionFailed,
			wantErr: "assertion Subject: cannot decrypt EncryptedID",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			assertion := e.assertion()
			if !tc.keepNameID {
				assertion.Subject.NameID = nil
			}
			assertion.Subject.EncryptedID = tc.encryptedID(t, e)
			r := e.response()
			r.Assertion = assertion
			_, err := e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
			privateErr := spcovPrivateErr(t, err)
			assert.Check(t, is.ErrorContains(privateErr, tc.wantErr))
			assert.Check(t, errors.Is(err, tc.kind), "got %v", privateErr)
		})
	}
}

// The signature covers the EncryptedID as sent: swapping it for another one
// breaks the signature.
func TestSPSubjectEncryptedIDIsSigned(t *testing.T) {
	e := spcovSetup(t)
	r := e.response()
	r.Assertion = e.eidAssertion(t, eidNameID)
	signed := e.idpSign(t, r.Element())

	subjectEl := signed.FindElement("./Assertion/Subject")
	assert.Assert(t, subjectEl != nil)
	oldEl := subjectEl.FindElement("./EncryptedID")
	assert.Assert(t, oldEl != nil)
	other := eidNameID
	other.Value = "mallory-persistent-id"
	subjectEl.InsertChildAt(oldEl.Index(), e.encryptedID(t, other))
	subjectEl.RemoveChild(oldEl)

	_, err := e.sp.ParseXMLResponse(spcovSerialize(t, signed), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Response"))
}

func TestParseXMLAttributeQueryResponseEncryptedID(t *testing.T) {
	encrypt := func(t *testing.T, e *spcovEnv, nameID NameID) func(*Assertion) {
		return func(a *Assertion) {
			a.Subject.NameID = nil
			a.Subject.EncryptedID = e.encryptedID(t, nameID)
		}
	}

	t.Run("matches the queried NameID", func(t *testing.T) {
		for _, o := range []aqOptions{{signResponse: true}, {signAssertion: true, encrypt: true}} {
			e := aqSetup(t)
			query := e.aqQuery(t)
			o.assertion = encrypt(t, e, aqNameID)
			result, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, o), query)
			assert.NilError(t, err)
			assert.Assert(t, is.Len(result.Assertions, 1))
			assert.Check(t, is.DeepEqual(*result.Assertions[0].Subject.NameID, aqNameID))
			assert.Assert(t, is.Len(result.Attributes, 1))
			assert.Check(t, is.Equal(result.Attributes[0].Values[0].Value, "alice@example.com"))
		}
	})

	t.Run("another NameID", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		other := aqNameID
		other.Value = "bob-persistent-id"
		_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true, assertion: encrypt(t, e, other)}), query)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), `does not match the queried NameID`))
	})

	t.Run("not decryptable", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.NameID = nil
			a.Subject.EncryptedID = eidEncrypt(t, mustParseCertificate(golden.Get(t, "cert_2017.pem")), eidNameIDEl(aqNameID))
		}}), query)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), `assertion "id-assertion": assertion Subject: cannot decrypt EncryptedID`))
	})
}
