package xmlenc

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"gotest.tools/assert"
)

var errCovRand = errors.New("cov: rand failed")

// covFailingReader serves ok successful reads from crypto/rand, then fails.
type covFailingReader struct {
	ok int
}

func (r *covFailingReader) Read(p []byte) (int, error) {
	if r.ok <= 0 {
		return 0, errCovRand
	}
	r.ok--
	return rand.Read(p)
}

// covSetRandReader replaces RandReader for the duration of the test.
func covSetRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	orig := RandReader
	RandReader = r
	t.Cleanup(func() { RandReader = orig })
}

var errCovCipher = errors.New("cov: cipher failed")

func covFailingCipher([]byte) (cipher.Block, error) {
	return nil, errCovCipher
}

// covECDSACert returns a self-signed certificate holding an ECDSA public key.
func covECDSACert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ec.example.com"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return cert
}
