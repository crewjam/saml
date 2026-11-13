package saml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

// sidBaseID returns a standalone saml:BaseID element. BaseID is abstract:
// its content is defined by the xsi:type extension (saml-core §2.2.3).
func sidBaseID() *etree.Element {
	el := etree.NewElement("saml:BaseID")
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)
	el.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	el.CreateAttr("xmlns:ex", "urn:example:baseid")
	el.CreateAttr("xsi:type", "ex:EmployeeID")
	el.CreateAttr("NameQualifier", spcovIDPEntityID)
	el.CreateElement("ex:Number").SetText("12345")
	return el
}

// sidEncrypt encrypts el to the certificate of e's SP (or to cert, if set)
// and wraps the xenc:EncryptedData in a new element named wrapper, such as
// saml:EncryptedAttribute.
func sidEncrypt(t *testing.T, e *spcovEnv, wrapper string, el *etree.Element) *etree.Element {
	t.Helper()
	encrypter := xmlenc.OAEP()
	encrypter.BlockCipher = xmlenc.AES256GCM
	encryptedDataEl, err := encrypter.Encrypt(e.sp.Certificate, spcovSerialize(t, el), nil)
	assert.NilError(t, err)
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	wrapperEl := etree.NewElement(wrapper)
	wrapperEl.CreateAttr("xmlns:saml", samlAssertionNamespace)
	wrapperEl.AddChild(encryptedDataEl)
	return wrapperEl
}

// sidAttribute returns a standalone saml:Attribute element named name with
// one value.
func sidAttribute(name, value string) *etree.Element {
	el := (&Attribute{Name: name, Values: []AttributeValue{{Value: value}}}).Element()
	el.CreateAttr("xmlns:saml", samlAssertionNamespace)
	return el
}

// sidParse parses a Response signed by e's IdP whose assertion is a,
// after mutate edits the Assertion element.
func sidParse(t *testing.T, e *spcovEnv, a *Assertion, mutate func(assertionEl *etree.Element)) (*Assertion, error) {
	t.Helper()
	return e.sp.ParseXMLResponse(specCoreSignedResponse(t, e, a, mutate), []string{spcovRequestID}, e.sp.AcsURL)
}

// An assertion whose Subject identifies the principal with a BaseID is
// refused unless AcceptAssertionBaseID is set: its content is defined by an
// extension this package does not interpret, and accepting it silently
// left Subject.NameID nil (issue #803).
func TestSPAssertionSubjectBaseID(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		name := "plain"
		if encrypted {
			name = "in an EncryptedID"
		}
		t.Run(name, func(t *testing.T) {
			setSubject := func(e *spcovEnv) *Assertion {
				a := e.assertion()
				a.Subject.NameID = nil
				if encrypted {
					a.Subject.EncryptedID = sidEncrypt(t, e, "saml:EncryptedID", sidBaseID())
				} else {
					a.Subject.BaseID = sidBaseID()
				}
				return a
			}

			t.Run("refused by default", func(t *testing.T) {
				e := spcovSetup(t)
				_, err := sidParse(t, e, setSubject(e), nil)
				assert.Check(t, errors.Is(err, ErrUnsupported), "got %v", spcovPrivateErr(t, err))
				assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "BaseID"))
			})

			t.Run("accepted with AcceptAssertionBaseID", func(t *testing.T) {
				e := spcovSetup(t)
				e.sp.AcceptAssertionBaseID = true
				assertion, err := sidParse(t, e, setSubject(e), nil)
				if err != nil {
					t.Fatalf("ParseXMLResponse: %v", spcovPrivateErr(t, err))
				}
				assert.Check(t, assertion.Subject.NameID == nil)
				assert.Check(t, assertion.Subject.EncryptedID == nil)
				baseID := assertion.Subject.BaseID
				assert.Assert(t, baseID != nil)
				assert.Check(t, is.Equal(samlAssertionNamespace, baseID.NamespaceURI()))
				assert.Check(t, is.Equal("BaseID", baseID.Tag))
				assert.Check(t, is.Equal(spcovIDPEntityID, baseID.SelectAttrValue("NameQualifier", "")))
				assert.Check(t, is.Equal("ex:EmployeeID", baseID.SelectAttrValue("xsi:type", "")))
				number := baseID.FindElement("./Number")
				assert.Assert(t, number != nil)
				assert.Check(t, is.Equal("12345", number.Text()))
			})
		})
	}
}

// adfsSubjectWithoutNameID is the Subject and AttributeStatement of an
// assertion from AD FS 3.0 whose relying party trust has no claim rule
// issuing a Name ID (issue #989): the Subject has only a bearer
// SubjectConfirmation, and the user is named by the emailaddress claim.
// The elements are in the default namespace, as AD FS writes them. %s are
// the InResponseTo, NotOnOrAfter and Recipient of the confirmation.
const adfsSubjectWithoutNameID = `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
      <Subject>
         <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <SubjectConfirmationData InResponseTo="%s" NotOnOrAfter="%s" Recipient="%s" />
         </SubjectConfirmation>
      </Subject>
      <AttributeStatement>
         <Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
            <AttributeValue>foo@bar.com</AttributeValue>
         </Attribute>
      </AttributeStatement>
</Assertion>`

// saml-core §2.4.1: the identifier of a Subject is optional ("<BaseID>,
// <NameID>, or <EncryptedID> [Optional]"), and the Web Browser SSO profile
// requires only a bearer SubjectConfirmation (saml-profiles §4.1.4.2). So
// an assertion whose Subject has none, as AD FS sends without a Name ID
// claim rule, is accepted with a nil NameID, and the caller names the
// principal by an attribute (issue #989).
func TestSPAssertionSubjectWithoutIdentifier(t *testing.T) {
	for _, acceptBaseID := range []bool{false, true} {
		t.Run(fmt.Sprintf("AcceptAssertionBaseID=%v", acceptBaseID), func(t *testing.T) {
			e := spcovSetup(t)
			e.sp.AcceptAssertionBaseID = acceptBaseID
			a := e.assertion()
			a.Subject = nil
			adfs := etree.NewDocument()
			assert.NilError(t, adfs.ReadFromString(fmt.Sprintf(adfsSubjectWithoutNameID,
				spcovRequestID, spcovNow.Add(5*time.Minute).Format(timeFormat), e.sp.AcsURL.String())))

			assertion, err := sidParse(t, e, a, func(assertionEl *etree.Element) {
				// Put AD FS's Subject where the schema has it, after the
				// Issuer, and its AttributeStatement after the
				// AuthnStatement, each declaring the default namespace
				// that its AD FS parent declared.
				adfsChild := func(tag string) *etree.Element {
					el := adfs.Root().SelectElement(tag)
					assert.Assert(t, el != nil, tag)
					el = el.Copy()
					el.CreateAttr("xmlns", samlAssertionNamespace)
					return el
				}
				issuer := assertionEl.FindElement("./Issuer")
				assert.Assert(t, issuer != nil)
				assertionEl.InsertChildAt(issuer.Index()+1, adfsChild("Subject"))
				assertionEl.AddChild(adfsChild("AttributeStatement"))
			})
			if err != nil {
				t.Fatalf("ParseXMLResponse: %v", spcovPrivateErr(t, err))
			}
			assert.Assert(t, assertion.Subject != nil)
			assert.Check(t, assertion.Subject.NameID == nil)
			assert.Check(t, assertion.Subject.BaseID == nil)
			assert.Check(t, assertion.Subject.EncryptedID == nil)
			assert.Check(t, is.Len(assertion.Subject.SubjectConfirmations, 1))
			assert.Assert(t, is.Len(assertion.AttributeStatements, 1))
			attrs := assertion.AttributeStatements[0].Attributes
			assert.Assert(t, is.Len(attrs, 1))
			assert.Check(t, is.Equal("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", attrs[0].Name))
			assert.Assert(t, is.Len(attrs[0].Values, 1))
			assert.Check(t, is.Equal("foo@bar.com", attrs[0].Values[0].Value))
		})
	}
}

// An assertion still needs a Subject, with a bearer SubjectConfirmation
// (saml-profiles §4.1.4.2), even though the Subject's identifier is
// optional.
func TestSPAssertionWithoutSubjectRefused(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	a.Subject = nil
	_, err := sidParse(t, e, a, nil)
	assert.Check(t, errors.Is(err, ErrMissingElement), "got %v", spcovPrivateErr(t, err))
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "assertion has no Subject"))
}

// saml-core §2.4.1: BaseID, NameID and EncryptedID are alternatives.
func TestSPAssertionSubjectBaseIDWithNameIDRefused(t *testing.T) {
	e := spcovSetup(t)
	e.sp.AcceptAssertionBaseID = true
	a := e.assertion()
	a.Subject.BaseID = sidBaseID()
	_, err := sidParse(t, e, a, nil)
	assert.Check(t, errors.Is(err, ErrMalformedMessage), "got %v", spcovPrivateErr(t, err))
}

// Subject.BaseID is read and written in the place the schema gives it,
// before SubjectConfirmation.
func TestSubjectBaseIDRoundTrip(t *testing.T) {
	subject := Subject{
		BaseID: sidBaseID(),
		SubjectConfirmations: []SubjectConfirmation{
			{Method: bearerSubjectConfirmationMethod},
		},
	}
	el := subject.Element()
	children := el.ChildElements()
	assert.Assert(t, is.Len(children, 2))
	assert.Check(t, is.Equal("BaseID", children[0].Tag))
	assert.Check(t, is.Equal("SubjectConfirmation", children[1].Tag))

	buf, err := xml.Marshal(&subject)
	assert.NilError(t, err)
	var got Subject
	assert.NilError(t, xml.Unmarshal(buf, &got))
	assert.Assert(t, got.BaseID != nil)
	assert.Check(t, is.Equal("BaseID", got.BaseID.Tag))
	assert.Check(t, is.Equal(spcovIDPEntityID, got.BaseID.SelectAttrValue("NameQualifier", "")))
	assert.Check(t, got.NameID == nil)
	assert.Check(t, is.Len(got.SubjectConfirmations, 1))
}

// saml-core §2.7.3.2: an AttributeStatement may carry EncryptedAttribute
// elements. They are decrypted with the SP's keys into Attributes, in
// document order, instead of being silently ignored (issue #803).
func TestSPDecryptsEncryptedAttributes(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	a.AttributeStatements = []AttributeStatement{{Attributes: []Attribute{
		{Name: "first", Values: []AttributeValue{{Value: "1"}}},
		{Name: "third", Values: []AttributeValue{{Value: "3"}}},
	}}}
	assertion, err := sidParse(t, e, a, func(assertionEl *etree.Element) {
		statementEl := assertionEl.FindElement("./AttributeStatement")
		assert.Assert(t, statementEl != nil)
		// first, second (encrypted), third, fourth (encrypted)
		statementEl.InsertChildAt(1, sidEncrypt(t, e, "saml:EncryptedAttribute", sidAttribute("second", "2")))
		statementEl.AddChild(sidEncrypt(t, e, "saml:EncryptedAttribute", sidAttribute("fourth", "4")))
	})
	if err != nil {
		t.Fatalf("ParseXMLResponse: %v", spcovPrivateErr(t, err))
	}
	assert.Assert(t, is.Len(assertion.AttributeStatements, 1))
	attributes := assertion.AttributeStatements[0].Attributes
	names := make([]string, 0, len(attributes))
	values := make([]string, 0, len(attributes))
	for _, attribute := range attributes {
		names = append(names, attribute.Name)
		assert.Assert(t, is.Len(attribute.Values, 1))
		values = append(values, attribute.Values[0].Value)
	}
	assert.Check(t, is.DeepEqual([]string{"first", "second", "third", "fourth"}, names))
	assert.Check(t, is.DeepEqual([]string{"1", "2", "3", "4"}, values))
}

// An EncryptedAttribute that cannot be decrypted, or that does not hold an
// Attribute, makes the assertion refused rather than dropped.
func TestSPRejectsBadEncryptedAttribute(t *testing.T) {
	testCases := []struct {
		name    string
		el      func(t *testing.T, e *spcovEnv) *etree.Element
		kind    error
		wantErr string
	}{
		{
			name: "encrypted to another key",
			el: func(t *testing.T, e *spcovEnv) *etree.Element {
				other := *e
				otherSP := *e.sp
				otherSP.Certificate = mustParseCertificate(golden.Get(t, "cert_2017.pem"))
				other.sp = &otherSP
				return sidEncrypt(t, &other, "saml:EncryptedAttribute", sidAttribute("secret", "x"))
			},
			kind:    ErrDecryptionFailed,
			wantErr: "cannot decrypt EncryptedAttribute",
		},
		{
			name: "no EncryptedData",
			el: func(_ *testing.T, _ *spcovEnv) *etree.Element {
				el := etree.NewElement("saml:EncryptedAttribute")
				el.CreateAttr("xmlns:saml", samlAssertionNamespace)
				return el
			},
			kind:    ErrDecryptionFailed,
			wantErr: "cannot decrypt EncryptedAttribute",
		},
		{
			name: "holds a NameID",
			el: func(t *testing.T, e *spcovEnv) *etree.Element {
				return sidEncrypt(t, e, "saml:EncryptedAttribute", eidNameIDEl(eidNameID))
			},
			kind:    ErrMalformedMessage,
			wantErr: "EncryptedAttribute holds a saml:NameID element, not a saml:Attribute",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			a := e.assertion()
			a.AttributeStatements = []AttributeStatement{{Attributes: []Attribute{
				{Name: "plain", Values: []AttributeValue{{Value: "p"}}},
			}}}
			_, err := sidParse(t, e, a, func(assertionEl *etree.Element) {
				statementEl := assertionEl.FindElement("./AttributeStatement")
				assert.Assert(t, statementEl != nil)
				statementEl.AddChild(tc.el(t, e))
			})
			privateErr := spcovPrivateErr(t, err)
			assert.Check(t, is.ErrorContains(privateErr, tc.wantErr))
			assert.Check(t, errors.Is(err, tc.kind), "got %v", privateErr)
		})
	}
}
