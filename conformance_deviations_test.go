package saml

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// These tests pin the deliberate departures from the algorithms
// saml-conformance-2.0-os §4 and saml-bindings-2.0-os §3.4.4.1 list as
// mandatory, as documented in the README's "Conformance notes". A change to
// any of them must be a deliberate one, with the README updated to match.

// DSA-SHA1 (saml-bindings §3.4.4.1, SimpleSign §2.5) is not a supported
// SigAlg for the HTTP-Redirect or HTTP-POST-SimpleSign bindings, and
// neither is HMAC-SHA1. RSA-SHA1, which the same list requires, is.
func TestConformanceDeviation_DetachedSignatureAlgorithms(t *testing.T) {
	sig := base64.StdEncoding.EncodeToString([]byte("signature"))
	for _, sigAlg := range []string{
		"http://www.w3.org/2000/09/xmldsig#dsa-sha1",
		"http://www.w3.org/2000/09/xmldsig#hmac-sha1",
	} {
		_, _, err := decodeDetachedSignature(sigAlg, sig, base64.StdEncoding)
		assert.Check(t, is.ErrorContains(err, "unsupported signature algorithm"), sigAlg)
	}
	_, _, err := decodeDetachedSignature(dsig.RSASHA1SignatureMethod, sig, base64.StdEncoding)
	assert.Check(t, err, "RSA-SHA1 is supported")
}

// HMAC-SHA1 (saml-conformance §4.1) XML signatures are not accepted: the
// package has no shared-key configuration to verify them with.
func TestConformanceDeviation_HMACSHA1XMLSignature(t *testing.T) {
	e := spcovSetup(t)
	r := e.response()
	r.Assertion = e.assertion()
	signed := e.idpSign(t, r.Element())
	signed.FindElement("./Signature/SignedInfo/SignatureMethod").
		CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#hmac-sha1")

	_, err := e.sp.ParseXMLResponse(spcovSerialize(t, signed), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "hmac-sha1"))
}

// Triple DES block encryption and RSA-v1.5 key transport
// (saml-conformance §4.2) are not accepted by default: an
// EncryptedAssertion using either is refused unless the application
// registers the decrypter (xmlenc.RegisterDecrypter, tested in the xmlenc
// package). AES with RSA-OAEP is accepted.
func TestConformanceDeviation_EncryptedAssertionAlgorithms(t *testing.T) {
	e := spcovSetup(t)
	plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
	encrypted := func(t *testing.T, enc xmlenc.Encrypter) []byte {
		t.Helper()
		data, err := enc.Encrypt(e.sp.Certificate, plaintext, nil)
		assert.NilError(t, err)
		data.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
		ea := etree.NewElement("saml:EncryptedAssertion")
		ea.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
		ea.AddChild(data)
		r := e.response()
		el := r.Element()
		el.AddChild(ea)
		return spcovSerialize(t, e.idpSign(t, el))
	}
	parse := func(buf []byte) error {
		_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		return err
	}

	tripleDES := xmlenc.OAEP()
	tripleDES.BlockCipher = xmlenc.TripleDES
	err := parse(encrypted(t, tripleDES))
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "tripledes-cbc"), "%v", spcovPrivateErr(t, err))

	err = parse(encrypted(t, xmlenc.PKCS1v15()))
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "rsa-1_5"), "%v", spcovPrivateErr(t, err))

	aes := xmlenc.OAEP()
	aes.BlockCipher = xmlenc.AES256CBC
	assert.Check(t, parse(encrypted(t, aes)), "AES-256-CBC with RSA-OAEP is accepted")
}

// saml-core §1.3.3 requires SAML time values in UTC with the zone
// designator "Z". Protocol messages and assertions are held to it
// (TestRelaxedTimeRequiresUTC), but the validUntil of metadata is read
// leniently: a time with no zone is read as UTC, and one with an offset is
// converted to UTC. Metadata in the wild is written without a zone
// (testdata/TestCanParseMetadata_metadata.xml), and refusing it would
// make the whole document unreadable. See metadataTime.
func TestConformanceDeviation_MetadataTimeZone(t *testing.T) {
	for in, want := range map[string]time.Time{
		"2030-01-02T03:04:05.678":   time.Date(2030, 1, 2, 3, 4, 5, 678000000, time.UTC),
		"2030-01-02T05:04:05+02:00": time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	} {
		doc := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/" validUntil="` + in + `"/>`
		var ed EntityDescriptor
		assert.Check(t, xml.Unmarshal([]byte(doc), &ed), in)
		assert.Check(t, ed.ValidUntil.Equal(want), "%s: %s", in, ed.ValidUntil)

		var a Assertion
		err := xml.Unmarshal([]byte(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="`+in+`"/>`), &a)
		assert.Check(t, is.ErrorContains(err, "is not in UTC"), in)
	}
}
