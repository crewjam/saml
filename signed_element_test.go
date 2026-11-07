package saml

import (
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// validatedElement returns what the signature covers, parsed from the bytes
// that were digested: a namespace declaration added after signing, which
// exclusive canonicalization leaves out, is not in it. The Signature is put
// back so the parsed message still has it.
func TestValidatedElementIsWhatTheSignatureCovers(t *testing.T) {
	e := spcovSetup(t)
	// Parsed from bytes, as a received message is.
	signed := spcovParse(t, string(spcovSerialize(t, e.idpSign(t, e.assertion().Element()))))
	signed.FindElement("//saml:SubjectConfirmationData").CreateAttr("xmlns:NotOnOrAfter", "2999-01-01T00:00:00Z")

	verified, err := e.sp.validatedElement(signed)
	assert.NilError(t, err)
	assert.Check(t, verified != signed)
	scd := verified.FindElement("//saml:SubjectConfirmationData")
	assert.Assert(t, scd != nil)
	assert.Check(t, is.Nil(scd.SelectAttr("xmlns:NotOnOrAfter")))
	assert.Check(t, is.Equal(verified.SelectAttrValue("ID", ""), "id-assertion"))
	sig, err := findChild(verified, "http://www.w3.org/2000/09/xmldsig#", "Signature")
	assert.NilError(t, err)
	assert.Check(t, sig != nil)

	var a Assertion
	assert.NilError(t, unmarshalElement(verified, &a))
	assert.Check(t, a.Signature != nil)
	assert.Check(t, is.Equal(a.Subject.NameID.Value, "alice@example.com"))
}

// signedElementVerifier returns, as the signed element, a copy of the
// element it is given with the NameID changed, so a test can tell which of
// the two the service provider reads.
type signedElementVerifier struct{ calls int }

func (v *signedElementVerifier) VerifySignature(*dsig.ValidationContext, *etree.Element) error {
	return nil
}

func (v *signedElementVerifier) VerifySignedElement(_ *dsig.ValidationContext, el *etree.Element) (*etree.Element, error) {
	v.calls++
	signed := el.Copy()
	for _, nameID := range signed.FindElements("//NameID") {
		nameID.SetText("signed@example.com")
	}
	for _, sig := range signed.FindElements("./Signature") {
		signed.RemoveChild(sig)
	}
	return signed, nil
}

// The service provider reads a signed Response or Assertion from the element
// the signature check returns, not from the one it received.
func TestParseXMLResponseReadsTheSignedElement(t *testing.T) {
	for _, tc := range []struct {
		name string
		sign func(e *spcovEnv) []byte
	}{
		{"signed response", func(e *spcovEnv) []byte {
			r := e.response()
			r.Assertion = e.assertion()
			return spcovSerialize(t, e.idpSign(t, r.Element()))
		}},
		{"signed assertion", func(e *spcovEnv) []byte {
			el := e.response().Element()
			el.AddChild(e.idpSign(t, e.assertion().Element()))
			return spcovSerialize(t, el)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := spcovSetup(t)
			v := &signedElementVerifier{}
			e.sp.SignatureVerifier = v
			assertion, err := e.sp.ParseXMLResponse(tc.sign(e), []string{spcovRequestID}, e.sp.AcsURL)
			assert.NilError(t, err)
			assert.Check(t, is.Equal(v.calls, 1))
			assert.Check(t, is.Equal(assertion.Subject.NameID.Value, "signed@example.com"))
		})
	}
}

// A SignatureVerifier that only reports an error leaves the message as
// received, as before.
func TestParseXMLResponseWithPlainSignatureVerifierReadsTheMessage(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureVerifier = &spcovVerifier{}
	r := e.response()
	r.Assertion = e.assertion()
	assertion, err := e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(assertion.Subject.NameID.Value, "alice@example.com"))
}
