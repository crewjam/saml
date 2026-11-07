package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// newSigningSP returns a service provider that trusts a freshly generated
// IdP certificate, and a signing context holding that certificate's key.
func newSigningSP(t *testing.T) (*ServiceProvider, *dsig.SigningContext) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example.com"},
		// Other tests in this package pin the package Clock to dates in the
		// past, so the certificate covers every date they use.
		NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)

	certStr := base64.StdEncoding.EncodeToString(der)
	sp := &ServiceProvider{
		IDPMetadata:    &EntityDescriptor{EntityID: "https://idp.example.com/"},
		IDPCertificate: &certStr,
	}
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}))
	return sp, signer
}

// largeAssertion builds an assertion with more child elements than
// goxmldsig's default traversal budget of 1000, as an IdP sending a user's
// many group memberships does.
func largeAssertion() *etree.Element {
	el := etree.NewElement("saml:Assertion")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.CreateAttr("ID", "id-large")
	el.CreateElement("saml:Issuer").SetText("https://idp.example.com/")
	stmt := el.CreateElement("saml:AttributeStatement")
	attr := stmt.CreateElement("saml:Attribute")
	attr.CreateAttr("Name", "groups")
	for i := 0; i < 1500; i++ {
		attr.CreateElement("saml:AttributeValue").SetText(fmt.Sprintf("group-%d", i))
	}
	return el
}

// signLargeAssertion signs largeAssertion and moves the Signature to follow
// Issuer, where the SAML schema places it and where IdPs send it.
func signLargeAssertion(t *testing.T, signer *dsig.SigningContext) *etree.Element {
	t.Helper()
	signed, err := signer.SignEnveloped(largeAssertion())
	assert.NilError(t, err)
	// SignEnveloped appends the Signature as the last child.
	sig := signed.RemoveChildAt(len(signed.Child) - 1)
	signed.InsertChildAt(1, sig)
	return signed
}

// A correctly signed assertion larger than the traversal budget validates.
func TestValidateSignatureOnLargeAssertion(t *testing.T) {
	sp, signer := newSigningSP(t)
	signed := signLargeAssertion(t, signer)

	assert.Check(t, sp.validateSignature(signed))
}

// A tampered large assertion is refused with an error, not a panic.
func TestValidateSignatureOnTamperedLargeAssertion(t *testing.T) {
	sp, signer := newSigningSP(t)
	signed := signLargeAssertion(t, signer)
	signed.FindElement("./AttributeStatement/Attribute/AttributeValue").SetText("admins")

	assert.Check(t, is.ErrorContains(sp.validateSignature(signed), "cannot validate signature on Assertion"))
}
