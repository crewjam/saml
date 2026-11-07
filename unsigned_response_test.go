package saml

import (
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Each assertion of an unsigned Response had its signature checked, which
// copies the namespace context in scope: 4,000 assertions under 1,000
// declarations (300 KB) took seconds and gigabytes. An unsigned Response may
// carry one assertion only.
func TestUnsignedResponseWithManyAssertionsRejectedCheaply(t *testing.T) {
	e := spcovSetup(t)
	buf := []byte(responseOpen + namespaceDeclarations(1000) + ">" + responseStatus +
		strings.Repeat(`<saml:Assertion ID="a" Version="2.0"><ds:Signature/></saml:Assertion>`, 4000) + "</samlp:Response>")
	perByte, err := parseCost(t, e, buf)
	assert.Check(t, is.Error(err, "an unsigned Response must contain exactly one Assertion or EncryptedAssertion, not 4000"))
	assert.Check(t, perByte < maxParseBytesPerInputByte, "allocated %.0f bytes per input byte", perByte)
}

func TestUnsignedResponseMayCarryOnlyOneAssertion(t *testing.T) {
	e := spcovSetup(t)
	signedAssertion := func() *etree.Element { return e.idpSign(t, e.assertion().Element()) }

	t.Run("one signed assertion", func(t *testing.T) {
		responseEl := e.response().Element()
		responseEl.AddChild(signedAssertion())
		assertion, err := e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(assertion.Subject.NameID.Value, "alice@example.com"))
	})

	t.Run("two signed assertions", func(t *testing.T) {
		responseEl := e.response().Element()
		responseEl.AddChild(signedAssertion())
		responseEl.AddChild(signedAssertion())
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Check(t, is.Error(spcovPrivateErr(t, err), "an unsigned Response must contain exactly one Assertion or EncryptedAssertion, not 2"))
	})

	t.Run("an assertion and an encrypted assertion", func(t *testing.T) {
		responseEl := e.response().Element()
		responseEl.AddChild(signedAssertion())
		responseEl.AddChild(e.encryptedAssertion(t, spcovSerialize(t, signedAssertion())))
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Check(t, is.Error(spcovPrivateErr(t, err), "an unsigned Response must contain exactly one Assertion or EncryptedAssertion, not 2"))
	})

	t.Run("signed response with two assertions", func(t *testing.T) {
		r := e.response()
		responseEl := r.Element()
		responseEl.AddChild(e.assertion().Element())
		second := e.assertion()
		second.Subject.NameID.Value = "bob@example.com"
		responseEl.AddChild(second.Element())
		buf := spcovSerialize(t, e.idpSign(t, responseEl))
		assertion, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(assertion.Subject.NameID.Value, "alice@example.com"))
	})
}
