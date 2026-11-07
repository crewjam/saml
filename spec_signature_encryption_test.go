package saml

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SAML conformance requires SHA-1 support; used only to build test signatures
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

// Tests in this file pin the behaviour of the package against the XML
// Signature and XML Encryption profiles of SAML 2.0:
// saml-core-2.0-os sections 5 and 6 (as amended by the approved errata,
// sstc-saml-core-errata-2.0-wd-07) and saml-conformance-2.0-os section 4.

const (
	specSigExcC14N    = "http://www.w3.org/2001/10/xml-exc-c14n#"
	specSigEnveloped  = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	specSigXPath      = "http://www.w3.org/TR/1999/REC-xpath-19991116"
	specSigXSLT       = "http://www.w3.org/TR/1999/REC-xslt-19991116"
	specSigInclC14N   = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	specSigDigestSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
	specSigDigestS256 = "http://www.w3.org/2001/04/xmlenc#sha256"
)

// specSigRef describes one ds:Reference of a hand-built signature.
type specSigRef struct {
	URI        string
	Transforms []string // defaults to enveloped-signature + exc-c14n
	// Canonicalizer computes the digest of the signed element; defaults to
	// exclusive canonicalization without comments. The element is
	// canonicalized standalone, so an inclusive canonicalizer only gives the
	// right digest for a document's root element.
	Canonicalizer dsig.Canonicalizer
	// BadDigest, if set, puts a digest over different bytes in the Reference.
	BadDigest bool
}

// specSigOptions controls how specSigSign builds a signature.
type specSigOptions struct {
	Refs      []specSigRef
	SHA1      bool // rsa-sha1 and sha1 digests instead of rsa-sha256 and sha256
	NoKeyInfo bool
	// SignedInfoC14N is the CanonicalizationMethod of SignedInfo; defaults
	// to exclusive canonicalization. Only exc-c14n and inclusive c14n 1.0
	// (both without comments) are supported by this helper.
	SignedInfoC14N string
}

// specSigSign returns a copy of el carrying an enveloped ds:Signature built
// by hand, so that tests can produce signatures whose SignedInfo deviates
// from what goxmldsig itself would emit (other Reference URIs, several
// References, other Transforms) while still being cryptographically valid.
func specSigSign(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, el *etree.Element, opts specSigOptions) *etree.Element {
	t.Helper()
	if len(opts.Refs) == 0 {
		opts.Refs = []specSigRef{{URI: "#" + el.SelectAttrValue("ID", "")}}
	}
	digestAlg, sigAlg, hash := specSigDigestS256, dsig.RSASHA256SignatureMethod, crypto.SHA256
	if opts.SHA1 {
		digestAlg, sigAlg, hash = specSigDigestSHA1, dsig.RSASHA1SignatureMethod, crypto.SHA1
	}
	digest := func(b []byte) []byte {
		if opts.SHA1 {
			s := sha1.Sum(b) //nolint:gosec // see import
			return s[:]
		}
		s := sha256.Sum256(b)
		return s[:]
	}

	signedInfo := etree.NewElement("ds:SignedInfo")
	signedInfo.CreateAttr("xmlns:ds", dsig.Namespace)
	signedInfoC14N := dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if opts.SignedInfoC14N == "" {
		opts.SignedInfoC14N = specSigExcC14N
	}
	if opts.SignedInfoC14N == specSigInclC14N {
		signedInfoC14N = dsig.MakeC14N10RecCanonicalizer()
	}
	signedInfo.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", opts.SignedInfoC14N)
	signedInfo.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", sigAlg)
	for _, ref := range opts.Refs {
		transforms := ref.Transforms
		if transforms == nil {
			transforms = []string{specSigEnveloped, specSigExcC14N}
		}
		c14n := ref.Canonicalizer
		if c14n == nil {
			c14n = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		}
		canonical, err := c14n.Canonicalize(el.Copy())
		assert.NilError(t, err)
		if ref.BadDigest {
			canonical = append(canonical, ' ')
		}

		refEl := signedInfo.CreateElement("ds:Reference")
		refEl.CreateAttr("URI", ref.URI)
		transformsEl := refEl.CreateElement("ds:Transforms")
		for _, alg := range transforms {
			transformsEl.CreateElement("ds:Transform").CreateAttr("Algorithm", alg)
		}
		refEl.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestAlg)
		refEl.CreateElement("ds:DigestValue").SetText(base64.StdEncoding.EncodeToString(digest(canonical)))
	}

	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", dsig.Namespace)
	sig.AddChild(signedInfo)
	signatureValueEl := sig.CreateElement("ds:SignatureValue")
	if !opts.NoKeyInfo {
		sig.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
			SetText(base64.StdEncoding.EncodeToString(cert.Raw))
	}

	// The schema places ds:Signature right after Issuer, the first child.
	out := el.Copy()
	if children := out.ChildElements(); len(children) > 1 {
		out.InsertChildAt(children[1].Index(), sig)
	} else {
		out.AddChild(sig)
	}

	// SignedInfo is canonicalized in place, with the namespaces in scope
	// there (which inclusive canonicalization renders).
	nsCtx, err := etreeutils.NSBuildParentContext(signedInfo)
	assert.NilError(t, err)
	detached, err := etreeutils.NSDetatch(nsCtx, signedInfo)
	assert.NilError(t, err)
	canonicalSignedInfo, err := signedInfoC14N.Canonicalize(detached)
	assert.NilError(t, err)
	signatureValue, err := key.Sign(rand.Reader, digest(canonicalSignedInfo), hash)
	assert.NilError(t, err)
	signatureValueEl.SetText(base64.StdEncoding.EncodeToString(signatureValue))
	return out
}

// specSigResponse wraps the given assertion-level children in an unsigned
// Response built from e.response().
func (e *spcovEnv) specSigResponse(children ...*etree.Element) *etree.Element {
	r := e.response().Element()
	for _, c := range children {
		r.AddChild(c)
	}
	return r
}

func (e *spcovEnv) specSigParse(t *testing.T, responseEl *etree.Element) (*Assertion, error) {
	t.Helper()
	return e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
}

// specSigCheckProfile asserts that el carries exactly one enveloped
// ds:Signature as a direct child, laid out as saml-core-2.0-os §5.4 asks:
// a single Reference whose URI is "#"+ID (§5.4.2), exclusive
// canonicalization for SignedInfo (§5.4.3), and only the
// enveloped-signature and exc-c14n transforms (§5.4.4).
func specSigCheckProfile(t *testing.T, el *etree.Element) {
	t.Helper()
	sigs, err := findChildren(el, dsig.Namespace, "Signature")
	assert.NilError(t, err)
	assert.Assert(t, is.Len(sigs, 1), "%s: direct-child ds:Signature elements", el.Tag)
	sig := sigs[0]

	assert.Check(t, is.Equal(specSigExcC14N,
		sig.FindElement("./SignedInfo/CanonicalizationMethod").SelectAttrValue("Algorithm", "")))

	refs := sig.FindElements("./SignedInfo/Reference")
	assert.Assert(t, is.Len(refs, 1), "%s: ds:Reference elements", el.Tag)
	id := el.SelectAttrValue("ID", "")
	assert.Assert(t, id != "", "%s has no ID", el.Tag)
	assert.Check(t, is.Equal("#"+id, refs[0].SelectAttrValue("URI", "")))

	transforms := refs[0].FindElements("./Transforms/Transform")
	algs := make([]string, 0, len(transforms))
	for _, tr := range transforms {
		algs = append(algs, tr.SelectAttrValue("Algorithm", ""))
	}
	assert.Check(t, is.DeepEqual([]string{specSigEnveloped, specSigExcC14N}, algs))
}

// specSigIDPResponse has an IdentityProvider issue a Response for e's SP,
// encrypting the assertion when encrypt is set.
func (e *spcovEnv) specSigIDPResponse(t *testing.T, encrypt bool) *etree.Element {
	t.Helper()
	spsso := &SPSSODescriptor{}
	if encrypt {
		spsso.KeyDescriptors = []KeyDescriptor{{
			Use: "encryption",
			KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{
				{Data: base64.StdEncoding.EncodeToString(e.sp.Certificate.Raw)},
			}}},
		}}
	}
	req := &IdpAuthnRequest{
		IDP: &IdentityProvider{
			Key:         e.idpKey,
			Certificate: e.idpCert,
			MetadataURL: mustParseURL(spcovIDPEntityID),
			SSOURL:      mustParseURL("https://idp.example.com/sso/post"),
		},
		Now:             spcovNow,
		Request:         AuthnRequest{ID: spcovRequestID},
		ACSEndpoint:     &IndexedEndpoint{Binding: HTTPPostBinding, Location: e.sp.AcsURL.String()},
		SPSSODescriptor: spsso,
		Assertion:       e.assertion(),
	}
	assert.NilError(t, req.MakeResponse())
	// Round-trip through bytes, as the SP would receive it.
	return spcovParse(t, string(spcovSerialize(t, req.ResponseEl)))
}

// saml-core-2.0-os §5.4.1 (lines 2925-2926): "SAML assertions and protocols
// MUST use enveloped signatures"; §5.4.2 (lines 2933-2935): a single
// Reference whose URI MUST be "#"+ID; §5.4.3 / §5.4.4: exclusive
// canonicalization and only the enveloped-signature and exc-c14n transforms.
// The IdP's Response and Assertion signatures follow this profile.
func TestSpecSig_5_4_IdPSignaturesFollowProfile(t *testing.T) {
	e := spcovSetup(t)
	responseEl := e.specSigIDPResponse(t, false)
	specSigCheckProfile(t, responseEl)

	assertionEls, err := findChildren(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
	assert.NilError(t, err)
	assert.Assert(t, is.Len(assertionEls, 1))
	specSigCheckProfile(t, assertionEls[0])

	assertion, err := e.specSigParse(t, responseEl)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
}

// saml-core-2.0-os §5.4 (lines 2925-2935) and §5.2 (line 2897): requests the
// SP signs (AuthnRequest, LogoutRequest, ArtifactResolve) carry one
// enveloped signature with a single "#"+ID Reference, exclusive
// canonicalization and only the permitted transforms.
func TestSpecSig_5_4_SPRequestSignaturesFollowProfile(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod

	verify := func(t *testing.T, el *etree.Element) {
		t.Helper()
		specSigCheckProfile(t, el)
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{e.sp.Certificate},
		})
		ctx.Clock = dsig.NewFakeClockAt(spcovNow)
		_, err := ctx.Validate(el)
		assert.NilError(t, err)
	}

	t.Run("AuthnRequest", func(t *testing.T) {
		req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/post", HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		verify(t, req.Element())
	})
	t.Run("LogoutRequest", func(t *testing.T) {
		req, err := e.sp.MakeLogoutRequest("https://idp.example.com/slo/post", "alice@example.com")
		assert.NilError(t, err)
		verify(t, req.Element())
	})
	t.Run("ArtifactResolve", func(t *testing.T) {
		req, err := e.sp.MakeArtifactResolveRequest("AAQAAA==")
		assert.NilError(t, err)
		verify(t, req.Element())
	})
}

// saml-core-2.0-os §5.3 (lines 2899-2906): an assertion without its own
// ds:Signature inherits the signature of the enclosing Response when that
// signature covers the assertion and all its children. Such an assertion is
// accepted, and any change to it invalidates the Response signature.
func TestSpecSig_5_3_UnsignedAssertionInheritsResponseSignature(t *testing.T) {
	e := spcovSetup(t)
	r := e.response()
	r.Assertion = e.assertion()
	signed := e.idpSign(t, r.Element())

	assertion, err := e.specSigParse(t, signed)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))

	tampered := signed.Copy()
	tampered.FindElement("./Assertion/Subject/NameID").SetText("mallory@example.com")
	_, err = e.specSigParse(t, tampered)
	assert.Check(t, errors.Is(err, ErrInvalidSignature))
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Response"))
}

// saml-core-2.0-os §5.3 (lines 2899-2906) read with §5 (lines 2883-2884):
// inheritance needs an enclosing signature. An unsigned assertion in an
// unsigned Response has neither and is rejected.
func TestSpecSig_5_3_UnsignedAssertionWithoutEnclosingSignatureRejected(t *testing.T) {
	e := spcovSetup(t)
	_, err := e.specSigParse(t, e.specSigResponse(e.assertion().Element()))
	assert.Check(t, is.Error(spcovPrivateErr(t, err), "signature element not present"))
}

// saml-core-2.0-os §5.4.2 (lines 2933-2935): "Signatures MUST contain a single
// <ds:Reference> containing a same-document reference to the ID attribute
// value of the root element ... being signed." A cryptographically valid
// signature whose Reference names a different ID does not sign the assertion
// and is rejected.
func TestSpecSig_5_4_2_ReferenceToOtherIDRejected(t *testing.T) {
	e := spcovSetup(t)
	signed := specSigSign(t, e.idpKey, e.idpCert, e.assertion().Element(), specSigOptions{
		Refs: []specSigRef{{URI: "#some-other-id"}},
	})
	_, err := e.specSigParse(t, e.specSigResponse(signed))
	assert.Check(t, errors.Is(err, ErrInvalidSignature))
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "Missing signature referencing the top-level element"))
}

// saml-core-2.0-os §5.4.2 (lines 2929-2935): the signature is bound to the ID
// of the element it is enveloped in. Changing the ID of a signed assertion
// (for example to collide with or replace another) breaks the signature.
func TestSpecSig_5_4_2_ChangedIDBreaksSignature(t *testing.T) {
	e := spcovSetup(t)
	signed := e.idpSign(t, e.assertion().Element())
	signed.CreateAttr("ID", "id-forged") // also rewrite the Reference to match
	signed.FindElement("./Signature/SignedInfo/Reference").CreateAttr("URI", "#id-forged")
	_, err := e.specSigParse(t, e.specSigResponse(signed))
	assert.Check(t, errors.Is(err, ErrInvalidSignature))
}

// saml-core-2.0-os §5.4.4 (lines 2942-2950): verifiers "MAY reject signatures
// that contain other transform algorithms as invalid. If they do not,
// verifiers MUST ensure that no content of the SAML message is excluded from
// the signature." XPath and XSLT transforms, which can exclude content, are
// rejected.
func TestSpecSig_5_4_4_ContentExcludingTransformsRejected(t *testing.T) {
	e := spcovSetup(t)
	for _, alg := range []string{specSigXPath, specSigXSLT} {
		t.Run(alg, func(t *testing.T) {
			signed := specSigSign(t, e.idpKey, e.idpCert, e.assertion().Element(), specSigOptions{
				Refs: []specSigRef{{URI: "#id-assertion", Transforms: []string{specSigEnveloped, alg}}},
			})
			_, err := e.specSigParse(t, e.specSigResponse(signed))
			assert.Check(t, errors.Is(err, ErrInvalidSignature))
			assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "Unknown Transform Algorithm: "+alg))
		})
	}
}

// saml-core-2.0-os §5.4.3 (lines 2937-2940) allows Exclusive Canonicalization
// "with or without comments"; §5.4.4 (lines 2944-2945) lists
// xml-exc-c14n#WithComments as a permitted transform. Such a signature
// verifies, and since comments are then signed, injecting one breaks it.
func TestSpecSig_5_4_3_ExclusiveC14NWithCommentsAccepted(t *testing.T) {
	e := spcovSetup(t)
	const withComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	signed := specSigSign(t, e.idpKey, e.idpCert, e.assertion().Element(), specSigOptions{
		Refs: []specSigRef{{
			URI:           "#id-assertion",
			Transforms:    []string{specSigEnveloped, withComments},
			Canonicalizer: dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(""),
		}},
	})
	assertion, err := e.specSigParse(t, e.specSigResponse(signed))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))

	nameID := signed.FindElement("./Subject/NameID")
	nameID.AddChild(etree.NewComment("injected"))
	_, err = e.specSigParse(t, e.specSigResponse(signed))
	assert.Check(t, errors.Is(err, ErrInvalidSignature))
}

// saml-core-2.0-os §5.4.5 (lines 2951-2954): "SAML does not require the use
// of <ds:KeyInfo> ... Therefore, <ds:KeyInfo> MAY be absent." A signature
// without KeyInfo is verified against the IdP's metadata certificate.
func TestSpecSig_5_4_5_KeyInfoMayBeAbsent(t *testing.T) {
	e := spcovSetup(t)
	signed := specSigSign(t, e.idpKey, e.idpCert, e.assertion().Element(), specSigOptions{NoKeyInfo: true})
	assert.Assert(t, signed.FindElement("./Signature/KeyInfo") == nil)
	assertion, err := e.specSigParse(t, e.specSigResponse(signed))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
}

// saml-core-2.0-os §5.4.5 (lines 2951-2954) places no restriction on KeyInfo,
// so its contents are not a trust anchor: a signature that verifies under the
// certificate it embeds is rejected unless that certificate is one the IdP's
// metadata lists for signing (a KeyDescriptor with use="signing" or no use).
func TestSpecSig_5_4_5_KeyInfoCertificateMustBeTrustedForSigning(t *testing.T) {
	e := spcovSetup(t)
	otherKey := mustParsePrivateKey(golden.Get(t, "key_2017.pem")).(*rsa.PrivateKey)
	otherCert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))

	t.Run("certificate not in metadata", func(t *testing.T) {
		signed := specSigSign(t, otherKey, otherCert, e.assertion().Element(), specSigOptions{})
		_, err := e.specSigParse(t, e.specSigResponse(signed))
		assert.Check(t, errors.Is(err, ErrUntrustedCertificate))
	})

	t.Run("certificate listed only for encryption", func(t *testing.T) {
		md := spcovIDPMetadata(otherCert)
		md.IDPSSODescriptors[0].KeyDescriptors = append(md.IDPSSODescriptors[0].KeyDescriptors, KeyDescriptor{
			Use: "encryption",
			KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{
				{Data: base64.StdEncoding.EncodeToString(e.idpCert.Raw)},
			}}},
		})
		e.sp.IDPMetadata = md
		signed := e.idpSign(t, e.assertion().Element())
		_, err := e.specSigParse(t, e.specSigResponse(signed))
		assert.Check(t, errors.Is(err, ErrUntrustedCertificate))
	})
}

// saml-conformance-2.0-os §4.1 (lines 237-246): compliant implementations
// MUST implement the SHA1 digest, Canonical XML (without comments), the
// enveloped-signature transform and RSAwithSHA1. A Response signed with
// exactly those algorithms is verified.
func TestSpecSig_Conformance_4_1_MandatorySignatureAlgorithms(t *testing.T) {
	e := spcovSetup(t)
	r := e.response()
	r.Assertion = e.assertion()
	signed := specSigSign(t, e.idpKey, e.idpCert, r.Element(), specSigOptions{
		SHA1:           true,
		SignedInfoC14N: specSigInclC14N,
		Refs: []specSigRef{{
			URI:           "#id-response",
			Transforms:    []string{specSigEnveloped, specSigInclC14N},
			Canonicalizer: dsig.MakeC14N10RecCanonicalizer(),
		}},
	})
	assert.Check(t, is.Equal(dsig.RSASHA1SignatureMethod,
		signed.FindElement("./Signature/SignedInfo/SignatureMethod").SelectAttrValue("Algorithm", "")))
	assertion, err := e.specSigParse(t, signed)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))

	// The inclusive transform excludes nothing (§5.4.4 lines 2946-2947):
	// tampering is still detected.
	signed.FindElement("./Assertion/Subject/NameID").SetText("mallory@example.com")
	_, err = e.specSigParse(t, signed)
	assert.Check(t, errors.Is(err, ErrInvalidSignature))
}

// Signature wrapping, saml-core-2.0-os §5.4.2 (lines 2933-2935) and §2.3.3
// (lines 597-599: "If it is invalid, then the relying party MUST NOT rely on
// the contents of the assertion"): only an assertion whose own enveloped
// signature (or that of its enclosing Response) verifies is consumed. A
// forged assertion reusing the signed assertion's ID, or wrapping the signed
// assertion, or carrying the signed assertion's Signature, is not.
func TestSpecSig_5_4_2_SignatureWrappingRejected(t *testing.T) {
	e := spcovSetup(t)
	legit := e.idpSign(t, e.assertion().Element())
	forgedAssertion := func() *etree.Element {
		a := e.assertion()
		a.Subject.NameID.Value = "mallory@example.com"
		return a.Element()
	}

	t.Run("forged assertion with duplicate ID beside the signed one", func(t *testing.T) {
		assertion, err := e.specSigParse(t, e.specSigResponse(forgedAssertion(), legit.Copy()))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("forged assertion alone", func(t *testing.T) {
		_, err := e.specSigParse(t, e.specSigResponse(forgedAssertion()))
		assert.Check(t, is.Error(spcovPrivateErr(t, err), "signature element not present"))
	})

	t.Run("forged assertion wrapping the signed one", func(t *testing.T) {
		forged := forgedAssertion()
		forged.CreateElement("saml:Advice").AddChild(legit.Copy())
		_, err := e.specSigParse(t, e.specSigResponse(forged))
		assert.Check(t, is.Error(spcovPrivateErr(t, err), "signature element not present"))
	})

	t.Run("forged assertion carrying the signed one's Signature", func(t *testing.T) {
		forged := forgedAssertion()
		sig := legit.FindElement("./Signature").Copy()
		forged.InsertChildAt(forged.ChildElements()[1].Index(), sig)
		forged.CreateElement("saml:Advice").AddChild(legit.Copy())
		_, err := e.specSigParse(t, e.specSigResponse(forged))
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
	})

	t.Run("two Signature children", func(t *testing.T) {
		doubled := legit.Copy()
		doubled.InsertChildAt(doubled.ChildElements()[1].Index(), legit.FindElement("./Signature").Copy())
		_, err := e.specSigParse(t, e.specSigResponse(doubled))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "expected at most one"))
	})
}

// saml-core-2.0-os §6.1 (lines 3110-3113): "The <EncryptedData> element's
// Type attribute SHOULD be used and, if it is present, MUST have the value
// http://www.w3.org/2001/04/xmlenc#Element"; §6.2 (lines 3118-3121): "When a
// signed <Assertion> element is encrypted, the signature MUST first be
// calculated and placed within the <Assertion> element before the element is
// encrypted." The IdP signs the assertion, then encrypts it, then signs the
// Response over the EncryptedAssertion.
func TestSpecSig_6_2_IdPSignsAssertionBeforeEncrypting(t *testing.T) {
	e := spcovSetup(t)
	responseEl := e.specSigIDPResponse(t, true)
	specSigCheckProfile(t, responseEl)

	plain, err := findChildren(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
	assert.NilError(t, err)
	assert.Check(t, is.Len(plain, 0))
	encrypted, err := findChildren(responseEl, "urn:oasis:names:tc:SAML:2.0:assertion", "EncryptedAssertion")
	assert.NilError(t, err)
	assert.Assert(t, is.Len(encrypted, 1))

	encryptedData := encrypted[0].FindElement("./EncryptedData")
	assert.Assert(t, encryptedData != nil)
	assert.Check(t, is.Equal("http://www.w3.org/2001/04/xmlenc#Element", encryptedData.SelectAttrValue("Type", "")))

	assertionEl, err := e.sp.decryptElement(encrypted[0])
	assert.NilError(t, err)
	assert.Check(t, is.Equal("Assertion", assertionEl.Tag))
	specSigCheckProfile(t, assertionEl)
	assert.NilError(t, e.sp.validateSignature(assertionEl))

	assertion, err := e.specSigParse(t, responseEl)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))

	// The Response signature was computed over the ciphertext.
	cv := responseEl.FindElement("./EncryptedAssertion/EncryptedData/CipherData/CipherValue")
	cv.SetText(cv.Text()[4:] + cv.Text()[:4])
	_, err = e.specSigParse(t, responseEl)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Response"))
}

// saml-core-2.0-os §6.2 (lines 3117-3121): "A relying party MUST perform
// signature validation and decryption in the reverse order that signing and
// encryption were performed." A signed-then-encrypted assertion in an
// unsigned Response is decrypted and then its signature is verified; an
// encrypted assertion with no valid signature inside is rejected.
func TestSpecSig_6_2_DecryptThenVerify(t *testing.T) {
	e := spcovSetup(t)

	t.Run("signed then encrypted", func(t *testing.T) {
		plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
		assertion, err := e.specSigParse(t, e.specSigResponse(e.encryptedAssertion(t, plaintext)))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("encrypted without signature", func(t *testing.T) {
		plaintext := spcovSerialize(t, e.assertion().Element())
		_, err := e.specSigParse(t, e.specSigResponse(e.encryptedAssertion(t, plaintext)))
		assert.Check(t, is.Error(spcovPrivateErr(t, err), "signature element not present"))
	})

	t.Run("encrypted with an untrusted signature", func(t *testing.T) {
		otherKey := mustParsePrivateKey(golden.Get(t, "key_2017.pem")).(*rsa.PrivateKey)
		otherCert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
		plaintext := spcovSerialize(t, specSigSign(t, otherKey, otherCert, e.assertion().Element(), specSigOptions{}))
		_, err := e.specSigParse(t, e.specSigResponse(e.encryptedAssertion(t, plaintext)))
		assert.Check(t, errors.Is(err, ErrUntrustedCertificate))
	})

	t.Run("encrypted after signing, then tampered", func(t *testing.T) {
		plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
		plaintext = bytes.Replace(plaintext, []byte("alice@example.com"), []byte("mallory@example.com"), 1)
		_, err := e.specSigParse(t, e.specSigResponse(e.encryptedAssertion(t, plaintext)))
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
	})
}

// sstc-saml-core-errata-2.0-wd-07 §6.3 [E43] (lines 3290-3297): an
// EncryptedKey included in the instance SHOULD be referenced from the
// EncryptedData's KeyInfo with a ds:RetrievalMethod (or embedded in it). The
// errata's first example places the EncryptedKey beside the EncryptedData,
// referenced by RetrievalMethod; such an EncryptedAssertion is decrypted.
func TestSpecSig_6_3_EncryptedKeyBesideEncryptedData(t *testing.T) {
	e := spcovSetup(t)
	plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
	ea := e.encryptedAssertion(t, plaintext)
	keyInfo := ea.FindElement("./EncryptedData/KeyInfo")
	encryptedKey := keyInfo.FindElement("./EncryptedKey")
	keyInfo.RemoveChild(encryptedKey)
	rm := keyInfo.CreateElement("ds:RetrievalMethod")
	rm.CreateAttr("URI", "#"+encryptedKey.SelectAttrValue("Id", ""))
	rm.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#EncryptedKey")
	ea.AddChild(encryptedKey)

	assertion, err := e.specSigParse(t, e.specSigResponse(ea))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
}

// saml-conformance-2.0-os §4.2 (lines 250-253) lists AES-128 and AES-256 block
// encryption and RSA-OAEP key transport as mandatory. Encrypted assertions
// using each block cipher with RSA-OAEP key transport are decrypted.
func TestSpecSig_Conformance_4_2_AESWithRSAOAEP(t *testing.T) {
	e := spcovSetup(t)
	plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
	for _, bc := range []xmlenc.BlockCipher{xmlenc.AES128CBC, xmlenc.AES256CBC} {
		t.Run(bc.Algorithm(), func(t *testing.T) {
			enc := xmlenc.OAEP()
			enc.BlockCipher = bc
			enc.DigestMethod = &xmlenc.SHA1
			ed, err := enc.Encrypt(e.sp.Certificate, plaintext, nil)
			assert.NilError(t, err)
			ed.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
			ea := etree.NewElement("saml:EncryptedAssertion")
			ea.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
			ea.AddChild(ed)

			assertion, err := e.specSigParse(t, e.specSigResponse(ea))
			assert.NilError(t, err)
			assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
		})
	}
}
