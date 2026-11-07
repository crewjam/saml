package samlsp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml"
)

const signedTestAggregate = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="id-aggregate" Name="urn:example:federation">
  <EntityDescriptor entityID="https://idp1.example.org/idp">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.org/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID="https://idp2.example.org/idp">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.org/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`

const signedTestEntity = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="id-entity" entityID="https://idp.example.org/idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

type metadataSigner struct {
	key  crypto.Signer
	cert *x509.Certificate
}

func testMetadataSigner(t *testing.T) metadataSigner {
	return metadataSigner{
		key:  mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey),
		cert: mustParseCertificate(golden.Get(t, "cert.pem")),
	}
}

func otherMetadataSigner(t *testing.T) metadataSigner {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "other"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return metadataSigner{key: key, cert: cert}
}

// sign returns doc with an enveloped signature on its root element, after
// mutate (if not nil) has changed the signed element.
func (s metadataSigner) sign(t *testing.T, doc string, mutate func(*etree.Element)) []byte {
	t.Helper()
	d := etree.NewDocument()
	assert.NilError(t, d.ReadFromString(doc))
	ctx, err := dsig.NewSigningContext(s.key, [][]byte{s.cert.Raw})
	assert.NilError(t, err)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	assert.NilError(t, ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
	signed, err := ctx.SignEnveloped(d.Root())
	assert.NilError(t, err)
	if mutate != nil {
		mutate(signed)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	buf, err := out.WriteToBytes()
	assert.NilError(t, err)
	return buf
}

func TestParseSignedMetadata(t *testing.T) {
	signer := testMetadataSigner(t)
	certs := []*x509.Certificate{signer.cert}

	t.Run("signed EntityDescriptor", func(t *testing.T) {
		md, err := ParseSignedMetadata(signer.sign(t, signedTestEntity, nil), certs)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(md.EntityID, "https://idp.example.org/idp"))
		assert.Assert(t, is.Len(md.IDPSSODescriptors, 1))
	})

	t.Run("signed by the IdentityProvider", func(t *testing.T) {
		idp := saml.IdentityProvider{
			Key:         signer.key,
			Certificate: signer.cert,
			MetadataURL: mustParseURL("https://idp.example.com/metadata"),
			SSOURL:      mustParseURL("https://idp.example.com/sso"),
		}
		el, err := idp.SignedMetadata()
		assert.NilError(t, err)
		doc := etree.NewDocument()
		doc.SetRoot(el)
		buf, err := doc.WriteToBytes()
		assert.NilError(t, err)

		md, err := ParseSignedMetadata(buf, certs)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(md.EntityID, "https://idp.example.com/metadata"))
	})

	t.Run("unsigned", func(t *testing.T) {
		_, err := ParseSignedMetadata([]byte(signedTestEntity), certs)
		assert.Check(t, is.Error(err, "metadata is not signed"))
		assert.Check(t, errors.Is(err, saml.ErrInvalidSignature))
	})

	t.Run("signed by another key", func(t *testing.T) {
		_, err := ParseSignedMetadata(otherMetadataSigner(t).sign(t, signedTestEntity, nil), certs)
		assert.Check(t, is.ErrorContains(err, "cannot validate signature on EntityDescriptor"))
		assert.Check(t, errors.Is(err, saml.ErrInvalidSignature))
	})

	t.Run("changed after signing", func(t *testing.T) {
		buf := signer.sign(t, signedTestEntity, nil)
		buf = []byte(strings.Replace(string(buf), "https://idp.example.org/sso", "https://evil.example.org/sso", 1))
		_, err := ParseSignedMetadata(buf, certs)
		assert.Check(t, is.ErrorContains(err, "cannot validate signature on EntityDescriptor"))
	})

	t.Run("no certificates", func(t *testing.T) {
		_, err := ParseSignedMetadata(signer.sign(t, signedTestEntity, nil), nil)
		assert.Check(t, is.Error(err, "cannot verify metadata signature: no certificate to verify it with"))
	})

	// Exclusive canonicalization leaves out a namespace declaration that
	// nothing uses, so one added after signing leaves the signature valid.
	// encoding/xml would read xmlns:entityID as the entityID attribute; only
	// what the signature covers is parsed.
	t.Run("namespace declaration added after signing", func(t *testing.T) {
		buf := signer.sign(t, signedTestEntity, func(el *etree.Element) {
			el.CreateAttr("xmlns:entityID", "https://evil.example.org/idp")
		})
		md, err := ParseSignedMetadata(buf, certs)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(md.EntityID, "https://idp.example.org/idp"))
	})

	// A signed EntityDescriptor wrapped in an unsigned aggregate is not
	// signed metadata: only a signature on the root element counts.
	t.Run("signed entity in an unsigned aggregate", func(t *testing.T) {
		signed := signer.sign(t, signedTestEntity, nil)
		wrapped := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + string(signed) + `</EntitiesDescriptor>`
		_, err := ParseSignedMetadata([]byte(wrapped), certs)
		assert.Check(t, is.Error(err, "metadata is not signed"))
	})

	t.Run("not metadata", func(t *testing.T) {
		_, err := ParseSignedMetadata([]byte(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`), certs)
		assert.Check(t, is.ErrorContains(err, "expected an EntityDescriptor or EntitiesDescriptor"))
	})

	t.Run("signed aggregate", func(t *testing.T) {
		buf := signer.sign(t, signedTestAggregate, nil)
		_, err := ParseSignedMetadata(buf, certs)
		assert.Check(t, is.Error(err, "metadata holds 2 entities with an IDPSSODescriptor; use ParseMetadataByEntityID to choose one"))

		md, err := ParseSignedMetadataByEntityID(buf, "https://idp2.example.org/idp", certs)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(md.IDPSSODescriptors[0].SingleSignOnServices[0].Location, "https://idp2.example.org/sso"))
	})
}

func TestFetchSignedMetadata(t *testing.T) {
	signer := testMetadataSigner(t)
	certs := []*x509.Certificate{signer.cert}
	serve := func(body []byte) *http.Client {
		return &http.Client{Transport: mockTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
		})}
	}
	u := mustParseURL("https://idp.example.org/metadata")

	md, err := FetchSignedMetadata(context.Background(), serve(signer.sign(t, signedTestEntity, nil)), u, certs)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(md.EntityID, "https://idp.example.org/idp"))

	_, err = FetchSignedMetadata(context.Background(), serve([]byte(signedTestEntity)), u, certs)
	assert.Check(t, is.Error(err, "metadata is not signed"))

	md, err = FetchSignedMetadataByEntityID(context.Background(), serve(signer.sign(t, signedTestAggregate, nil)), u, "https://idp1.example.org/idp", certs)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(md.EntityID, "https://idp1.example.org/idp"))
}
