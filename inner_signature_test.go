package saml

import (
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// A signature that is present must be valid even when an enclosing message
// is signed (saml-core §2.3.3, saml-profiles §4.1.4.3): a signed Response
// does not excuse an assertion signature that fails, and a signed
// ArtifactResponse does not excuse a Response signature that fails.
// See issue #775.

// innerSigOtherSigner returns a function that signs with a key the IdP
// metadata does not hold.
func innerSigOtherSigner(t *testing.T) func(*etree.Element) *etree.Element {
	t.Helper()
	key := mustParsePrivateKey(golden.Get(t, "key_2017.pem")).(*rsa.PrivateKey)
	cert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
	return func(el *etree.Element) *etree.Element { return spcovSign(t, key, cert, el) }
}

// innerSigResponse returns a Response signed by the IdP whose assertion is
// prepared by signAssertion.
func (e *spcovEnv) innerSigResponse(t *testing.T, signAssertion func(*etree.Element) *etree.Element) []byte {
	t.Helper()
	el := e.response().Element()
	assertionEl := e.assertion().Element()
	if signAssertion != nil {
		assertionEl = signAssertion(assertionEl)
	}
	el.AddChild(assertionEl)
	return spcovSerialize(t, e.idpSign(t, el))
}

func TestParseXMLResponseVerifiesAssertionSignatureInSignedResponse(t *testing.T) {
	parse := func(t *testing.T, e *spcovEnv, buf []byte) (*Assertion, error) {
		t.Helper()
		return e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	}

	t.Run("assertion signed by an untrusted key", func(t *testing.T) {
		e := spcovSetup(t)
		_, err := parse(t, e, e.innerSigResponse(t, innerSigOtherSigner(t)))
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, errors.Is(privateErr, ErrInvalidSignature), "%v", privateErr)
		assert.Check(t, is.ErrorContains(privateErr, "cannot validate signature on Assertion"))
	})

	t.Run("assertion signature with a wrong digest", func(t *testing.T) {
		e := spcovSetup(t)
		badDigest := func(el *etree.Element) *etree.Element {
			return specSigSign(t, e.idpKey, e.idpCert, el, specSigOptions{
				Refs: []specSigRef{{URI: "#" + el.SelectAttrValue("ID", ""), BadDigest: true}},
			})
		}
		_, err := parse(t, e, e.innerSigResponse(t, badDigest))
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, errors.Is(privateErr, ErrInvalidSignature), "%v", privateErr)
		assert.Check(t, is.ErrorContains(privateErr, "cannot validate signature on Assertion"))
	})

	t.Run("assertion validly signed", func(t *testing.T) {
		e := spcovSetup(t)
		assertion, err := parse(t, e, e.innerSigResponse(t, func(el *etree.Element) *etree.Element { return e.idpSign(t, el) }))
		assert.NilError(t, err)
		assert.Equal(t, "alice@example.com", assertion.Subject.NameID.Value)
	})

	t.Run("unsigned assertion is still accepted", func(t *testing.T) {
		e := spcovSetup(t)
		assertion, err := parse(t, e, e.innerSigResponse(t, nil))
		assert.NilError(t, err)
		assert.Equal(t, "alice@example.com", assertion.Subject.NameID.Value)
	})
}

func TestParseXMLArtifactResponseVerifiesInnerResponseSignature(t *testing.T) {
	const artifactReqID = "id-artifact-request"
	parse := func(t *testing.T, e *spcovEnv, el *etree.Element) (*Assertion, error) {
		t.Helper()
		return e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), []string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
	}
	// withInnerResponse returns a signed ArtifactResponse whose Response is
	// prepared by sign.
	withInnerResponse := func(t *testing.T, e *spcovEnv, sign func(*etree.Element) *etree.Element) *etree.Element {
		t.Helper()
		el := e.artifactResponseEl(t, artifactReqID, false, nil)
		inner := el.FindElement("./Response")
		el.RemoveChild(inner)
		el.AddChild(sign(inner))
		return e.idpSign(t, el)
	}

	t.Run("inner response signed by an untrusted key", func(t *testing.T) {
		e := spcovSetup(t)
		_, err := parse(t, e, withInnerResponse(t, e, innerSigOtherSigner(t)))
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, errors.Is(privateErr, ErrInvalidSignature), "%v", privateErr)
		assert.Check(t, is.ErrorContains(privateErr, "cannot validate signature on Response"))
	})

	t.Run("inner response validly signed", func(t *testing.T) {
		e := spcovSetup(t)
		assertion, err := parse(t, e, withInnerResponse(t, e, func(el *etree.Element) *etree.Element { return e.idpSign(t, el) }))
		assert.NilError(t, err)
		assert.Equal(t, "alice@example.com", assertion.Subject.NameID.Value)
	})
}

func TestParseXMLAttributeQueryResponseVerifiesAssertionSignatureInSignedResponse(t *testing.T) {
	otherSign := innerSigOtherSigner(t)

	t.Run("assertion signed by an untrusted key", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		el := e.aqResponseEl(t, query, aqOptions{signAssertion: true, sign: otherSign})
		el = e.idpSign(t, el)
		_, err := e.sp.ParseXMLAttributeQueryResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), query)
		privateErr := spcovPrivateErr(t, err)
		assert.Check(t, errors.Is(privateErr, ErrInvalidSignature), "%v", privateErr)
		assert.Check(t, is.ErrorContains(privateErr, "cannot validate signature on Assertion"))
	})

	t.Run("assertion validly signed", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true, signAssertion: true}), query)
		assert.NilError(t, err)
	})

	t.Run("unsigned assertion is still accepted", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true}), query)
		assert.NilError(t, err)
	})
}
