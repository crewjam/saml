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
)

// Tests in this file pin saml-core-2.0-os §5.4.2 (lines 2933-2935), which
// saml-metadata-2.0-os §3.1 repeats for metadata: "Signatures MUST contain a
// single <ds:Reference> containing a same-document reference to the ID
// attribute value of the root element ... For example, if the ID attribute
// value is "foo", then the URI attribute in the <ds:Reference> element MUST
// be "#foo"." goxmldsig accepts each of the rejected variants below on its
// own (https://github.com/crewjam/saml/issues/776).

// sigRefProfileCase is one ds:Reference layout for a signed element whose ID
// is id, and whether the profile allows it.
type sigRefProfileCase struct {
	name   string
	refs   func(id string) []specSigRef
	accept bool
}

func sigRefProfileCases() []sigRefProfileCase {
	return []sigRefProfileCase{
		{"single #ID reference", func(id string) []specSigRef {
			return []specSigRef{{URI: "#" + id}}
		}, true},
		{"empty URI", func(string) []specSigRef {
			return []specSigRef{{URI: ""}}
		}, false},
		{"URI without #", func(id string) []specSigRef {
			// goxmldsig compares URI[1:] with the ID.
			return []specSigRef{{URI: "X" + id}}
		}, false},
		{"two references to the ID", func(id string) []specSigRef {
			return []specSigRef{{URI: "#" + id}, {URI: "#" + id}}
		}, false},
		{"second reference with a bad digest", func(id string) []specSigRef {
			return []specSigRef{{URI: "#" + id}, {URI: "#" + id, BadDigest: true}}
		}, false},
		{"second reference to another ID with a bad digest", func(id string) []specSigRef {
			return []specSigRef{{URI: "#" + id}, {URI: "#other", BadDigest: true}}
		}, false},
	}
}

// checkSigRefProfile asserts that err accepts or rejects c as the profile
// requires. privateErr returns the error carrying the message.
func checkSigRefProfile(t *testing.T, c sigRefProfileCase, err error, privateErr func(error) error) {
	t.Helper()
	if c.accept {
		assert.NilError(t, err)
		return
	}
	assert.Assert(t, err != nil, "a signature with %s was accepted", c.name)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
	assert.Check(t, is.ErrorContains(privateErr(err), "Reference"))
}

func TestSignatureReferenceProfile_SPAssertion(t *testing.T) {
	for _, c := range sigRefProfileCases() {
		t.Run(c.name, func(t *testing.T) {
			e := spcovSetup(t)
			signed := specSigSign(t, e.idpKey, e.idpCert, e.assertion().Element(), specSigOptions{Refs: c.refs("id-assertion")})
			_, err := e.specSigParse(t, e.specSigResponse(signed))
			checkSigRefProfile(t, c, err, func(err error) error { return spcovPrivateErr(t, err) })
		})
	}
}

func TestSignatureReferenceProfile_SPResponse(t *testing.T) {
	for _, c := range sigRefProfileCases() {
		t.Run(c.name, func(t *testing.T) {
			e := spcovSetup(t)
			response := e.specSigResponse(e.assertion().Element())
			id := response.SelectAttrValue("ID", "")
			assert.Assert(t, id != "")
			signed := specSigSign(t, e.idpKey, e.idpCert, response, specSigOptions{Refs: c.refs(id)})
			_, err := e.specSigParse(t, signed)
			checkSigRefProfile(t, c, err, func(err error) error { return spcovPrivateErr(t, err) })
		})
	}
}

// The SP's ValidateLogoutRequest, for a LogoutRequest sent by the IdP with
// the HTTP-POST binding.
func TestSignatureReferenceProfile_SPLogoutRequest(t *testing.T) {
	for _, c := range sigRefProfileCases() {
		t.Run(c.name, func(t *testing.T) {
			e := spcovSetup(t)
			req := e.logoutRequest()
			signed := specSigSign(t, e.idpKey, e.idpCert, req.Element(), specSigOptions{Refs: c.refs(req.ID)})
			_, err := e.sp.ValidateLogoutRequest(postRequestBytes(e.sp.SloURL.String(), spcovSerialize(t, signed)))
			checkSigRefProfile(t, c, err, func(err error) error { return spcovPrivateErr(t, err) })
		})
	}
}

// The IdP's IdpLogoutRequest.Validate, for a LogoutRequest sent by the SP
// with the HTTP-POST binding.
func TestSignatureReferenceProfile_IDPLogoutRequest(t *testing.T) {
	for _, c := range sigRefProfileCases() {
		t.Run(c.name, func(t *testing.T) {
			test := newSLOTest(t)
			req := test.logoutRequest()
			signed := specSigSign(t, test.SP.Key.(*rsa.PrivateKey), test.SP.Certificate, req.Element(), specSigOptions{Refs: c.refs(req.ID)})
			idpReq, err := NewIdpLogoutRequest(&test.IDP, postRequestBytes(test.IDP.LogoutURL.String(), spcovSerialize(t, signed)))
			assert.NilError(t, err)
			checkSigRefProfile(t, c, idpReq.Validate(), func(err error) error { return err })
		})
	}
}

// sigRefProfileMetadata returns IdP metadata trusting cert as an element,
// with the given ID ("" for none).
func sigRefProfileMetadata(t *testing.T, cert *x509.Certificate, id string) *etree.Element {
	t.Helper()
	md := spcovIDPMetadata(cert)
	md.ID = id
	buf, err := xml.Marshal(md)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	return doc.Root()
}

func TestSignatureReferenceProfile_VerifyMetadataSignature(t *testing.T) {
	for _, c := range sigRefProfileCases() {
		t.Run(c.name, func(t *testing.T) {
			e := spcovSetup(t)
			signed := specSigSign(t, e.idpKey, e.idpCert, sigRefProfileMetadata(t, e.idpCert, "id-metadata"),
				specSigOptions{Refs: c.refs("id-metadata")})
			_, err := VerifyMetadataSignature(spcovSerialize(t, signed), []*x509.Certificate{e.idpCert})
			checkSigRefProfile(t, c, err, func(err error) error { return err })
		})
	}

	// Metadata without an ID can only be signed with URI="", which the
	// profile does not allow.
	t.Run("no ID and empty URI", func(t *testing.T) {
		e := spcovSetup(t)
		signed := specSigSign(t, e.idpKey, e.idpCert, sigRefProfileMetadata(t, e.idpCert, ""),
			specSigOptions{Refs: []specSigRef{{URI: ""}}})
		_, err := VerifyMetadataSignature(spcovSerialize(t, signed), []*x509.Certificate{e.idpCert})
		assert.Assert(t, err != nil, "metadata signed without an ID was accepted")
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
		assert.Check(t, errors.Is(err, ErrMissingElement))
		assert.Check(t, is.ErrorContains(err, "has no ID"))
	})
}
