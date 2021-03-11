package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/golden"

	"github.com/beevik/etree"
)

func TestCanEncryptOAEP(t *testing.T) {
	RandReader = rand.New(rand.NewSource(0)) //nolint:gosec // deterministic random numbers for tests

	pemBlock, _ := pem.Decode(golden.Get(t, "cert.pem"))
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	assert.Check(t, err)

	e := OAEP()
	e.BlockCipher = AES128CBC
	e.DigestMethod = &SHA1

	el, err := e.Encrypt(certificate, golden.Get(t, "plaintext.xml"))
	assert.Check(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(el)
	doc.IndentTabs()
	ciphertext, _ := doc.WriteToString()

	golden.Assert(t, ciphertext, "ciphertext.xml")
}
