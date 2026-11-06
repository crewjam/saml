package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// opaqueSigner hides the concrete key type behind the crypto.Signer
// interface, the way a KMS or HSM client does.
type opaqueSigner struct{ signer crypto.Signer }

func (o opaqueSigner) Public() crypto.PublicKey { return o.signer.Public() }

func (o opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.signer.Sign(r, digest, opts)
}

func selfSignedCert(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return cert
}

func TestGetSigningContextWithOpaqueSigner(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)

	tests := []struct {
		name   string
		key    crypto.Signer
		method string
	}{
		{"RSA", rsaKey, dsig.RSASHA256SignatureMethod},
		{"ECDSA", ecKey, dsig.ECDSASHA256SignatureMethod},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := selfSignedCert(t, tt.key)
			sp := &ServiceProvider{
				Key:             opaqueSigner{tt.key},
				Certificate:     cert,
				SignatureMethod: tt.method,
			}

			ctx, err := GetSigningContext(sp)
			assert.NilError(t, err)

			doc := etree.NewDocument()
			el := doc.CreateElement("Foo")
			el.CreateAttr("ID", "_0123456789")
			signed, err := ctx.SignEnveloped(el)
			assert.NilError(t, err)

			vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
				Roots: []*x509.Certificate{cert},
			})
			_, err = vc.Validate(signed)
			assert.NilError(t, err)
		})
	}
}

func TestGetSigningContextRejectsBadKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	cert := selfSignedCert(t, rsaKey)

	t.Run("KeyTypeMismatch", func(t *testing.T) {
		_, err := GetSigningContext(&ServiceProvider{
			Key:             opaqueSigner{rsaKey},
			Certificate:     cert,
			SignatureMethod: dsig.ECDSASHA256SignatureMethod,
		})
		assert.Check(t, is.ErrorContains(err, "requires an ECDSA key, got *rsa.PublicKey"))
	})

	t.Run("TypedNilKey", func(t *testing.T) {
		_, err := GetSigningContext(&ServiceProvider{
			Key:             (*rsa.PrivateKey)(nil),
			Certificate:     cert,
			SignatureMethod: dsig.RSASHA256SignatureMethod,
		})
		assert.Check(t, is.ErrorContains(err, "requires a non-nil private key"))
	})

	t.Run("NilCertificate", func(t *testing.T) {
		_, err := GetSigningContext(&ServiceProvider{
			Key:             rsaKey,
			SignatureMethod: dsig.RSASHA256SignatureMethod,
		})
		assert.Check(t, is.ErrorContains(err, "requires a certificate"))
	})
}
