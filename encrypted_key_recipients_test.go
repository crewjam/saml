package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP-MGF1P with SHA-1, as the IdPs send it
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

// Tests for issue #805: saml-core errata E43 (§6.3) lets an encrypted
// element carry one xenc:EncryptedKey per recipient, beside the
// EncryptedData, each optionally naming its Recipient; "It is RECOMMENDED
// that implementations simply use the first key they understand and ignore
// any additional keys".

// multiKeyRecipient is one xenc:EncryptedKey of a multi-recipient element:
// the content key wrapped for cert, with a Recipient attribute if recipient
// is set.
type multiKeyRecipient struct {
	cert      *x509.Certificate
	recipient string
	bogus     bool // an EncryptionMethod nobody implements
}

// multiKeyEncrypt encrypts plaintext with AES-128-CBC under a fresh content
// key, inside an element named tag, and wraps that key with RSA-OAEP-MGF1P in
// one xenc:EncryptedKey per recipient, placed beside the EncryptedData and
// referenced from its KeyInfo by RetrievalMethod.
func multiKeyEncrypt(t *testing.T, tag string, plaintext []byte, recipients ...multiKeyRecipient) *etree.Element {
	t.Helper()
	contentKey := make([]byte, xmlenc.AES128CBC.KeySize())
	_, err := rand.Read(contentKey)
	assert.NilError(t, err)

	encryptedDataEl, err := xmlenc.AES128CBC.Encrypt(contentKey, plaintext, nil)
	assert.NilError(t, err)
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	keyInfoEl := etree.NewElement("ds:KeyInfo")
	keyInfoEl.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	encryptedDataEl.InsertChildAt(encryptedDataEl.FindElement("./CipherData").Index(), keyInfoEl)

	el := etree.NewElement(tag)
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.AddChild(encryptedDataEl)

	for i, r := range recipients {
		id := fmt.Sprintf("_key%d", i)
		rm := keyInfoEl.CreateElement("ds:RetrievalMethod")
		rm.CreateAttr("URI", "#"+id)
		rm.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#EncryptedKey")

		keyEl := el.CreateElement("xenc:EncryptedKey")
		keyEl.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
		keyEl.CreateAttr("Id", id)
		if r.recipient != "" {
			keyEl.CreateAttr("Recipient", r.recipient)
		}
		algorithm := "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		if r.bogus {
			algorithm = "urn:bogus"
		}
		em := keyEl.CreateElement("xenc:EncryptionMethod")
		em.CreateAttr("Algorithm", algorithm)
		dm := em.CreateElement("ds:DigestMethod")
		dm.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
		dm.CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
		keyKeyInfo := keyEl.CreateElement("ds:KeyInfo")
		keyKeyInfo.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
		keyKeyInfo.CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
			SetText(base64.StdEncoding.EncodeToString(r.cert.Raw))
		wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, r.cert.PublicKey.(*rsa.PublicKey), contentKey, nil)
		assert.NilError(t, err)
		keyEl.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").
			SetText(base64.StdEncoding.EncodeToString(wrapped))
	}
	return el
}

func TestEncryptedKeyRecipients_SP(t *testing.T) {
	e := spcovSetup(t)
	plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
	thisSP := multiKeyRecipient{cert: e.sp.Certificate}
	// cert_2017.pem stands in for another SP's certificate. (The IdP's and
	// the SP's test certificates share one RSA key.)
	otherCert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
	otherSP := multiKeyRecipient{cert: otherCert, recipient: "https://other-sp.example.com/metadata"}

	parse := func(t *testing.T, recipients ...multiKeyRecipient) (*Assertion, error) {
		t.Helper()
		ea := multiKeyEncrypt(t, "saml:EncryptedAssertion", plaintext, recipients...)
		return e.specSigParse(t, e.specSigResponse(ea))
	}

	t.Run("other SP's key first", func(t *testing.T) {
		assertion, err := parse(t, otherSP, thisSP)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("this SP's key first", func(t *testing.T) {
		assertion, err := parse(t, thisSP, otherSP)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("this SP's key in a DecryptionKeys entry", func(t *testing.T) {
		oldKey := e.sp.Key
		t.Cleanup(func() { e.sp.Key = oldKey })
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NilError(t, err)
		e.sp.Key = otherKey
		e.sp.DecryptionKeys = []*rsa.PrivateKey{oldKey.(*rsa.PrivateKey)}
		t.Cleanup(func() { e.sp.DecryptionKeys = nil })
		assertion, err := parse(t, otherSP, thisSP)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("no key for this SP", func(t *testing.T) {
		other2 := multiKeyRecipient{cert: otherCert}
		_, err := parse(t, otherSP, other2)
		assert.Check(t, errors.Is(err, ErrDecryptionFailed), "%v", err)
		// The error is that of the first key tried, as when there was one.
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "certificate does not match provided key"))
	})

	t.Run("Recipient match preferred", func(t *testing.T) {
		// Neither key can be used; the error shows which was tried first.
		matching := multiKeyRecipient{cert: e.sp.Certificate, recipient: e.sp.entityID(), bogus: true}
		_, err := parse(t, otherSP, matching)
		assert.Check(t, errors.Is(err, ErrDecryptionFailed), "%v", err)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "algorithm is not implemented: urn:bogus"))
	})
}

func TestEncryptedKeyRecipients_CandidateOrder(t *testing.T) {
	el := spcovParse(t, `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
		`<xenc:EncryptedData><ds:KeyInfo><xenc:EncryptedKey Id="inner"/><xenc:EncryptedKey Id="inner-mine" Recipient="https://sp.example.com/saml/metadata"/></ds:KeyInfo></xenc:EncryptedData>`+
		`<xenc:EncryptedKey Id="a" Recipient="https://other.example.com/"/>`+
		`<xenc:EncryptedKey Id="b" Recipient="https://sp.example.com/saml/metadata"/>`+
		`<xenc:EncryptedKey Id="c"/>`+
		`</saml:EncryptedAssertion>`)
	ids := func(recipient string) []string {
		var got []string
		for _, k := range encryptedKeyCandidates(el, el.FindElement("./EncryptedData"), recipient) {
			got = append(got, k.SelectAttrValue("Id", ""))
		}
		return got
	}
	assert.Check(t, is.DeepEqual([]string{"b", "inner-mine", "a", "c", "inner"}, ids("https://sp.example.com/saml/metadata")))
	assert.Check(t, is.DeepEqual([]string{"a", "b", "c", "inner", "inner-mine"}, ids("")))
}

func TestEncryptedKeyRecipients_IdPEncryptedID(t *testing.T) {
	e := spcovSetup(t)
	idp := &IdentityProvider{
		Key:         e.idpKey,
		Certificate: e.idpCert,
		MetadataURL: mustParseURL(spcovIDPEntityID),
	}
	plaintext := []byte(`<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">alice@example.com</saml:NameID>`)
	// cert_2017.pem stands in for another party's certificate.
	encryptedID := multiKeyEncrypt(t, "saml:EncryptedID", plaintext,
		multiKeyRecipient{cert: mustParseCertificate(golden.Get(t, "cert_2017.pem"))},
		multiKeyRecipient{cert: e.idpCert, recipient: spcovIDPEntityID})
	nameID, err := decryptNameID(encryptedID, idp.decryptElement)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", nameID.Value))
}
