package saml

import (
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// adviceAssertion returns an assertion for mallory, with ID id, to be put in
// the Advice of another assertion.
func (e *spcovEnv) adviceAssertion(id string) *Assertion {
	a := e.assertion()
	a.ID = id
	a.Subject.NameID.Value = "mallory@example.com"
	return a
}

// withAdvice returns el, an assertion element, with a saml:Advice holding
// children inserted after its Conditions, as the schema orders it.
func withAdvice(t *testing.T, el *etree.Element, children ...*etree.Element) *etree.Element {
	t.Helper()
	advice := etree.NewElement("saml:Advice")
	for _, child := range children {
		advice.AddChild(child)
	}
	conditions := el.FindElement("./Conditions")
	assert.Assert(t, conditions != nil)
	el.InsertChildAt(conditions.Index()+1, advice)
	return el
}

// parseAdviceResponse parses a Response holding assertionEl (unsigned
// unless signResponse) and returns what ParseXMLResponse returns.
func (e *spcovEnv) parseAdviceResponse(t *testing.T, assertionEl *etree.Element, signResponse bool) (*Assertion, error) {
	t.Helper()
	responseEl := e.response().Element()
	responseEl.AddChild(assertionEl)
	if signResponse {
		responseEl = e.idpSign(t, responseEl)
	}
	return e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
}

// An assertion the IdP signed, holding in its Advice other assertions (one
// of them signed by the IdP too) and an EncryptedAssertion, is accepted as
// a single assertion in an unsigned Response: the assertions in Advice are
// not counted by the one-assertion rule, not decrypted, not verified, and
// never returned in place of the outer one. They are exposed in Advice.
func TestAdviceAssertionsAreNotPrimary(t *testing.T) {
	e := spcovSetup(t)
	innerSigned := e.idpSign(t, e.adviceAssertion("id-advice-signed").Element())
	innerUnsigned := e.adviceAssertion("id-advice-unsigned").Element()
	// Not decryptable: decrypting it would fail.
	garbage := etree.NewElement("saml:EncryptedAssertion")
	garbage.CreateElement("xenc:EncryptedData").CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	idRef := etree.NewElement("saml:AssertionIDRef")
	idRef.SetText("id-advice-ref")

	outer := withAdvice(t, e.assertion().Element(), idRef, innerSigned, innerUnsigned, garbage)
	signed := e.idpSign(t, outer)

	for _, signResponse := range []bool{false, true} {
		assertion, err := e.parseAdviceResponse(t, signed.Copy(), signResponse)
		assert.NilError(t, err, "signResponse=%v", signResponse)
		assert.Check(t, is.Equal(assertion.ID, "id-assertion"))
		assert.Check(t, is.Equal(assertion.Subject.NameID.Value, "alice@example.com"))
		assert.Assert(t, assertion.Advice != nil)
		assert.Check(t, is.DeepEqual(assertion.Advice.AssertionIDRefs, []string{"id-advice-ref"}))
		assert.Assert(t, is.Len(assertion.Advice.Assertions, 2))
		assert.Check(t, is.Equal(assertion.Advice.Assertions[0].ID, "id-advice-signed"))
		assert.Check(t, assertion.Advice.Assertions[0].Signature != nil)
		assert.Check(t, is.Equal(assertion.Advice.Assertions[1].Subject.NameID.Value, "mallory@example.com"))
		assert.Check(t, is.Len(assertion.Advice.EncryptedAssertions, 1))
	}
}

// An assertion in Advice is not verified: one signed by a key the SP does
// not trust does not make the outer assertion fail.
func TestAdviceAssertionSignatureNotVerified(t *testing.T) {
	e := spcovSetup(t)
	otherKey := mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
	untrusted := spcovSign(t, otherKey, e.sp.Certificate, e.adviceAssertion("id-advice").Element())
	signed := e.idpSign(t, withAdvice(t, e.assertion().Element(), untrusted))

	assertion, err := e.parseAdviceResponse(t, signed, false)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(assertion.ID, "id-assertion"))
	assert.Assert(t, assertion.Advice != nil && len(assertion.Advice.Assertions) == 1)
	assert.Check(t, is.Equal(assertion.Advice.Assertions[0].ID, "id-advice"))
}

// An attacker who adds an Advice holding a forged assertion to an assertion
// the IdP signed breaks its signature, whether the Response is signed or
// not.
func TestAdviceAddedToSignedAssertionIsRefused(t *testing.T) {
	e := spcovSetup(t)
	forged := e.adviceAssertion("id-forged").Element()

	signed := e.idpSign(t, e.assertion().Element())
	tampered := withAdvice(t, signed, forged)
	_, err := e.parseAdviceResponse(t, tampered, false)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)

	// A Response the IdP signed, whose (unsigned) assertion an attacker
	// then gives an Advice.
	responseEl := e.response().Element()
	responseEl.AddChild(e.assertion().Element())
	responseEl = e.idpSign(t, responseEl)
	withAdvice(t, responseEl.FindElement("./Assertion"), e.adviceAssertion("id-forged").Element())
	_, err = e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
}

// An attacker who puts an assertion the IdP signed in the Advice of a
// forged assertion, with or without a copy of its Signature and with the
// same ID, does not get the forged assertion accepted, nor the signed one
// returned from inside it.
func TestAdviceWrappingSignedAssertionIsRefused(t *testing.T) {
	e := spcovSetup(t)
	genuine := e.idpSign(t, e.assertion().Element())

	forgedAssertion := func() *etree.Element {
		a := e.assertion()
		a.Subject.NameID.Value = "mallory@example.com"
		return a.Element()
	}

	// No Signature on the forged assertion.
	forged := withAdvice(t, forgedAssertion(), genuine.Copy())
	_, err := e.parseAdviceResponse(t, forged, false)
	assert.Check(t, err != nil)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "signature"))

	// The genuine Signature copied onto the forged assertion.
	forged = forgedAssertion()
	sig := genuine.FindElement("./Signature").Copy()
	forged.InsertChildAt(forged.FindElement("./Issuer").Index()+1, sig)
	forged = withAdvice(t, forged, genuine.Copy())
	_, err = e.parseAdviceResponse(t, forged, false)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)

	// The forged assertion signed by a key the SP does not trust.
	otherKey := mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
	forged = spcovSign(t, otherKey, e.sp.Certificate, withAdvice(t, forgedAssertion(), genuine.Copy()))
	_, err = e.parseAdviceResponse(t, forged, false)
	assert.Check(t, err != nil)
}

// A Response that holds no assertion of its own, only one inside its
// Extensions, has no assertion.
func TestAssertionInsideResponseExtensionsIsNotFound(t *testing.T) {
	e := spcovSetup(t)
	genuine := e.idpSign(t, e.assertion().Element())
	responseEl := e.response().Element()
	ext := etree.NewElement("samlp:Extensions")
	ext.AddChild(genuine)
	responseEl.InsertChildAt(responseEl.FindElement("./Status").Index(), ext)
	_, err := e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrMissingElement), "%v", err)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "expected at least one valid Assertion"))
	assert.Check(t, !strings.Contains(err.Error(), "alice"))
}
