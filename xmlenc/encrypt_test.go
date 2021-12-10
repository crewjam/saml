package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	"gotest.tools/golden"
)

func TestCanEncryptOAEP(t *testing.T) {
	t.Run("CBC", func(t *testing.T) {

		RandReader = rand.New(rand.NewSource(0)) //nolint:gosec // deterministic random numbers for tests

		pemBlock, _ := pem.Decode(golden.Get(t, "cert.pem"))
		certificate, err := x509.ParseCertificate(pemBlock.Bytes)
		assert.Check(t, err)

		e := OAEP()
		e.BlockCipher = AES128CBC
		e.DigestMethod = &SHA1

		el, err := e.Encrypt(certificate, golden.Get(t, "plaintext.xml"), nil)
		assert.Check(t, err)

		doc := etree.NewDocument()
		doc.SetRoot(el)
		doc.IndentTabs()
		ciphertext, _ := doc.WriteToString()

		golden.Assert(t, ciphertext, "ciphertext.xml")
	})

	t.Run("GCM", func(t *testing.T) {
		RandReader = rand.New(rand.NewSource(0)) //nolint:gosec // deterministic random numbers for tests

		cert := golden.Get(t, "cert.cert")
		b, _ := pem.Decode(cert)
		certificate, err := x509.ParseCertificate(b.Bytes)
		assert.Check(t, err)

		e := OAEP()
		e.BlockCipher = AES128GCM
		e.DigestMethod = &SHA1

		el, err := e.Encrypt(certificate, golden.Get(t, "plaintext_gcm.xml"), []byte("1234567890AZ"))
		assert.Check(t, err)

		doc := etree.NewDocument()
		doc.SetRoot(el)
		doc.Indent(4)
		ciphertext, _ := doc.WriteToString()
		golden.Assert(t, ciphertext, "ciphertext_gcm.xml")
	})
}
