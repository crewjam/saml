package saml

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// cbcGCMEncryptedAssertion is spcovEnv.encryptedAssertion with AES-128-GCM
// in place of AES-128-CBC.
func (e *spcovEnv) cbcGCMEncryptedAssertion(t *testing.T, plaintext []byte) *etree.Element {
	t.Helper()
	encryptor := xmlenc.OAEP()
	encryptor.BlockCipher = xmlenc.AES128GCM
	encryptor.DigestMethod = &xmlenc.SHA1
	encryptedDataEl, err := encryptor.Encrypt(e.sp.Certificate, plaintext, nil)
	assert.NilError(t, err)
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	el := etree.NewElement("saml:EncryptedAssertion")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.AddChild(encryptedDataEl)
	return el
}

// cbcSignedEncrypted returns the IdP-signed assertion of e, encrypted with
// AES-128-CBC.
func (e *spcovEnv) cbcSignedEncrypted(t *testing.T) *etree.Element {
	t.Helper()
	return e.encryptedAssertion(t, spcovSerialize(t, e.idpSign(t, e.assertion().Element())))
}

// cbcGarbage returns a CBC EncryptedAssertion whose ciphertext and wrapped
// key are garbage, so that any attempt to decrypt it fails, and whose
// EncryptionMethod names algorithm.
func (e *spcovEnv) cbcGarbage(t *testing.T, algorithm string) *etree.Element {
	t.Helper()
	el := e.cbcSignedEncrypted(t)
	garbage := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcde"))
	for _, cv := range el.FindElements(".//CipherValue") {
		cv.SetText(garbage)
	}
	method := el.FindElement("./EncryptedData/EncryptionMethod")
	assert.Assert(t, method != nil)
	method.CreateAttr("Algorithm", algorithm)
	return el
}

func (e *spcovEnv) cbcParse(t *testing.T, sp *ServiceProvider, responseEl *etree.Element) (*Assertion, error) {
	t.Helper()
	return sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, sp.AcsURL)
}

func unsignedResponseWith(e *spcovEnv, encrypted *etree.Element) *etree.Element {
	el := e.response().Element()
	el.AddChild(encrypted)
	return el
}

func assertCBCRefused(t *testing.T, err error) {
	t.Helper()
	privateErr := spcovPrivateErr(t, err)
	assert.Check(t, errors.Is(privateErr, ErrInvalidSignature), "%v", privateErr)
	assert.Check(t, !errors.Is(privateErr, ErrDecryptionFailed), "%v", privateErr)
	assert.Check(t, is.ErrorContains(privateErr, "RequireSignedResponseForCBC"))
}

// By default, an unsigned Response carrying a CBC EncryptedAssertion whose
// assertion is signed inside the encryption is still accepted.
func TestRequireSignedResponseForCBCOffByDefault(t *testing.T) {
	e := spcovSetup(t)
	assert.Check(t, !e.sp.RequireSignedResponseForCBC)
	assertion, err := e.cbcParse(t, e.sp, unsignedResponseWith(e, e.cbcSignedEncrypted(t)))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))

	// Garbage ciphertext is decrypted, and fails as a decryption error.
	_, err = e.cbcParse(t, e.sp, unsignedResponseWith(e, e.cbcGarbage(t, xmlenc.AES128CBC.Algorithm())))
	assert.Check(t, errors.Is(spcovPrivateErr(t, err), ErrDecryptionFailed))
}

func TestRequireSignedResponseForCBC(t *testing.T) {
	e := spcovSetup(t)
	e.sp.RequireSignedResponseForCBC = true

	t.Run("unsigned Response, CBC, refused", func(t *testing.T) {
		_, err := e.cbcParse(t, e.sp, unsignedResponseWith(e, e.cbcSignedEncrypted(t)))
		assertCBCRefused(t, err)
	})

	// The refusal comes before decryption: garbage ciphertext gets the
	// integrity error, not a decryption error, for every CBC algorithm.
	for _, algorithm := range []string{
		xmlenc.AES128CBC.Algorithm(),
		xmlenc.AES192CBC.Algorithm(),
		xmlenc.AES256CBC.Algorithm(),
		xmlenc.TripleDES.Algorithm(),
	} {
		t.Run("refused before decrypting "+algorithm, func(t *testing.T) {
			_, err := e.cbcParse(t, e.sp, unsignedResponseWith(e, e.cbcGarbage(t, algorithm)))
			assertCBCRefused(t, err)
		})
	}

	t.Run("signed Response, CBC, accepted", func(t *testing.T) {
		el := e.idpSign(t, unsignedResponseWith(e, e.encryptedAssertion(t, spcovSerialize(t, e.assertion().Element()))))
		assertion, err := e.cbcParse(t, e.sp, el)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("unsigned Response, AES-GCM, accepted", func(t *testing.T) {
		encrypted := e.cbcGCMEncryptedAssertion(t, spcovSerialize(t, e.idpSign(t, e.assertion().Element())))
		assertion, err := e.cbcParse(t, e.sp, unsignedResponseWith(e, encrypted))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})
}

func TestRequireSignedResponseForCBCArtifactResponse(t *testing.T) {
	e := spcovSetup(t)
	e.sp.RequireSignedResponseForCBC = true
	const artifactReqID = "id-artifact-request"
	parse := func(t *testing.T, sign bool, encrypted *etree.Element) (*Assertion, error) {
		t.Helper()
		el := e.artifactResponseEl(t, artifactReqID, sign, func(ar *ArtifactResponse) {
			ar.Response.Assertion = nil
			ar.Response.EncryptedAssertion = encrypted
		})
		return e.sp.ParseXMLArtifactResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), []string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
	}

	t.Run("signed ArtifactResponse, CBC, accepted", func(t *testing.T) {
		assertion, err := parse(t, true, e.encryptedAssertion(t, spcovSerialize(t, e.assertion().Element())))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("unsigned ArtifactResponse, CBC, refused", func(t *testing.T) {
		_, err := parse(t, false, e.cbcGarbage(t, xmlenc.AES128CBC.Algorithm()))
		assertCBCRefused(t, err)
	})
}

func TestRequireSignedResponseForCBCAttributeQuery(t *testing.T) {
	e := aqSetup(t)
	query := e.aqQuery(t)

	t.Run("off by default", func(t *testing.T) {
		result, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signAssertion: true, encrypt: true}), query)
		assert.NilError(t, err)
		assert.Check(t, is.Len(result.Assertions, 1))
	})

	sp := *e.sp
	sp.RequireSignedResponseForCBC = true

	t.Run("unsigned Response, CBC, refused", func(t *testing.T) {
		_, err := sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signAssertion: true, encrypt: true}), query)
		var ire *InvalidResponseError
		assert.Assert(t, errors.As(err, &ire))
		assert.Check(t, errors.Is(ire.PrivateErr, ErrInvalidSignature), "%v", ire.PrivateErr)
		assert.Check(t, is.ErrorContains(ire.PrivateErr, "RequireSignedResponseForCBC"))
	})

	t.Run("signed Response, CBC, accepted", func(t *testing.T) {
		result, err := sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true, encrypt: true}), query)
		assert.NilError(t, err)
		assert.Check(t, is.Len(result.Assertions, 1))
	})
}
