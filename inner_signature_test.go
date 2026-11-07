package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
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

// innerSigAddSignedUsingParentXS adds el to parent, signed by the IdP with
// an exc-c14n Reference transform whose InclusiveNamespaces PrefixList is
// "xs", and declares xmlns:xs on parent only, so that el's digest covers a
// declaration only its parent makes. Exclusive canonicalization of parent
// with an empty PrefixList drops that declaration when no element or
// attribute name uses the prefix (an xsi:type value does not count).
//
// The signature is built by hand: goxmldsig canonicalizes SignedInfo with
// the PrefixList too when signing, but not when verifying.
func (e *spcovEnv) innerSigAddSignedUsingParentXS(t *testing.T, parent, el *etree.Element) {
	t.Helper()
	const xsNS = "http://www.w3.org/2001/XMLSchema"
	parent.CreateAttr("xmlns:xs", xsNS)

	// el's canonical form in parent: with the PrefixList, xmlns:xs is
	// rendered on el, as it is when el declares it itself.
	standalone := el.Copy()
	standalone.CreateAttr("xmlns:xs", xsNS)
	canonical, err := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("xs").Canonicalize(standalone)
	assert.NilError(t, err)
	digest := sha256.Sum256(canonical)

	signedInfo := etree.NewElement("ds:SignedInfo")
	signedInfo.CreateAttr("xmlns:ds", dsig.Namespace)
	signedInfo.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", specSigExcC14N)
	signedInfo.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", dsig.RSASHA256SignatureMethod)
	ref := signedInfo.CreateElement("ds:Reference")
	ref.CreateAttr("URI", "#"+el.SelectAttrValue("ID", ""))
	transforms := ref.CreateElement("ds:Transforms")
	transforms.CreateElement("ds:Transform").CreateAttr("Algorithm", specSigEnveloped)
	excC14N := transforms.CreateElement("ds:Transform")
	excC14N.CreateAttr("Algorithm", specSigExcC14N)
	inclusive := excC14N.CreateElement("ec:InclusiveNamespaces")
	inclusive.CreateAttr("xmlns:ec", specSigExcC14N)
	inclusive.CreateAttr("PrefixList", "xs")
	ref.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", specSigDigestS256)
	ref.CreateElement("ds:DigestValue").SetText(base64.StdEncoding.EncodeToString(digest[:]))

	canonicalSignedInfo, err := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(signedInfo.Copy())
	assert.NilError(t, err)
	signedInfoDigest := sha256.Sum256(canonicalSignedInfo)
	signatureValue, err := e.idpKey.Sign(rand.Reader, signedInfoDigest[:], crypto.SHA256)
	assert.NilError(t, err)

	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", dsig.Namespace)
	sig.AddChild(signedInfo)
	sig.CreateElement("ds:SignatureValue").SetText(base64.StdEncoding.EncodeToString(signatureValue))
	// The schema places ds:Signature right after Issuer, the first child.
	el.InsertChildAt(el.ChildElements()[1].Index(), sig)
	parent.AddChild(el)
}

// innerSigWithoutOwnXS removes the xmlns:xs declarations of el's
// AttributeValues, leaving their xsi:type="xs:..." to an ancestor's.
func innerSigWithoutOwnXS(el *etree.Element) *etree.Element {
	for _, value := range el.FindElements("//AttributeValue") {
		value.RemoveAttr("xmlns:xs")
	}
	return el
}

// innerSigOuterSign signs el with the IdP key and an empty PrefixList, as
// e.idpSign does, keeping el's xmlns:xs declaration. goxmldsig returns the
// signed element in canonical form, which lacks the declaration; an IdP
// sends it as it is, and putting it back does not change what the
// signature covers.
func (e *spcovEnv) innerSigOuterSign(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	xs := el.SelectAttrValue("xmlns:xs", "")
	assert.Assert(t, xs != "")
	signed := e.idpSign(t, el)
	signed.CreateAttr("xmlns:xs", xs)
	return signed
}

// innerSigNilError is assert.NilError, reporting an InvalidResponseError's
// PrivateErr.
func innerSigNilError(t *testing.T, err error) {
	t.Helper()
	var ire *InvalidResponseError
	if errors.As(err, &ire) {
		err = ire.PrivateErr
	}
	assert.NilError(t, err)
}

// An inner signature is checked against the element as received, not as
// rebuilt from what the outer signature covers, which can lack namespace
// declarations the inner signature's PrefixList relies on.
func TestInnerSignatureUsesNamespacesAsReceived(t *testing.T) {
	t.Run("signed Response, assertion signature needs xmlns:xs from the Response", func(t *testing.T) {
		e := spcovSetup(t)
		assertion := e.assertion()
		assertion.AttributeStatements = []AttributeStatement{{Attributes: []Attribute{{
			Name:   "mail",
			Values: []AttributeValue{{Type: "xs:string", Value: "alice@example.com"}},
		}}}}
		responseEl := e.response().Element()
		e.innerSigAddSignedUsingParentXS(t, responseEl, innerSigWithoutOwnXS(assertion.Element()))
		buf := spcovSerialize(t, e.innerSigOuterSign(t, responseEl))
		got, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		innerSigNilError(t, err)
		assert.Equal(t, "alice@example.com", got.Subject.NameID.Value)
		assert.Equal(t, "xs:string", got.AttributeStatements[0].Attributes[0].Values[0].Type)
	})

	t.Run("signed ArtifactResponse, inner Response signature needs xmlns:xs from the ArtifactResponse", func(t *testing.T) {
		e := spcovSetup(t)
		const artifactReqID = "id-artifact-request"
		el := e.artifactResponseEl(t, artifactReqID, false, nil)
		inner := el.FindElement("./Response")
		el.RemoveChild(inner)
		e.innerSigAddSignedUsingParentXS(t, el, inner)
		el = e.innerSigOuterSign(t, el)
		got, err := e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), []string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
		innerSigNilError(t, err)
		assert.Equal(t, "alice@example.com", got.Subject.NameID.Value)
	})

	t.Run("signed attribute query Response, assertion signature needs xmlns:xs from the Response", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		responseEl := e.aqResponseEl(t, query, aqOptions{noAssertion: true})
		e.innerSigAddSignedUsingParentXS(t, responseEl, innerSigWithoutOwnXS(e.aqAssertion(query).Element()))
		responseEl = e.innerSigOuterSign(t, responseEl)
		result, err := e.sp.ParseXMLAttributeQueryResponse(spcovSerialize(t, spcovSOAPEnvelope(responseEl)), query)
		innerSigNilError(t, err)
		assert.Equal(t, "alice@example.com", result.Attributes[0].Values[0].Value)
	})
}
