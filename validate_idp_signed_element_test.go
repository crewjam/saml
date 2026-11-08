package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
)

func TestValidateIDPSignedElement(t *testing.T) {
	e := spcovSetup(t)
	el := etree.NewElement("samlp:ArtifactResolve")
	el.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	el.CreateAttr("ID", "id-resolve")
	el.CreateElement("samlp:Artifact").SetText("AAQAAA")

	// Signed by the IdP, as received: serialized and parsed again.
	signed := spcovParse(t, string(spcovSerialize(t, e.idpSign(t, el))))
	got, err := e.sp.ValidateIDPSignedElement(signed)
	assert.NilError(t, err)
	assert.Equal(t, "AAQAAA", got.FindElement("./Artifact").Text())

	// Unsigned.
	_, err = e.sp.ValidateIDPSignedElement(el)
	assert.ErrorIs(t, err, ErrInvalidSignature)

	// Signed with a key that is not the IdP's. (The SP and IdP of the
	// test data share a key, so make another.)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), NotBefore: spcovNow.Add(-time.Hour), NotAfter: spcovNow.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &otherKey.PublicKey, otherKey)
	assert.NilError(t, err)
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: otherKey, Certificate: [][]byte{der}})
	other, err := ctx.SignEnveloped(el.Copy())
	assert.NilError(t, err)
	_, err = e.sp.ValidateIDPSignedElement(spcovParse(t, string(spcovSerialize(t, other))))
	assert.ErrorIs(t, err, ErrInvalidSignature)

	// Tampered with after signing.
	tampered := signed.Copy()
	tampered.FindElement("./Artifact").SetText("BBBB")
	_, err = e.sp.ValidateIDPSignedElement(tampered)
	assert.ErrorIs(t, err, ErrInvalidSignature)
}
