package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/beevik/etree"
)

func TestCanEncryptOAEP(t *testing.T) {
	RandReader = rand.New(rand.NewSource(0)) // deterministic random numbers for tests

	pemBlock, _ := pem.Decode([]byte(golden.Get(t, "cert.pem")))
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

	assert.Check(t, is.Equal(ciphertext, string(golden.Get(t, "ciphertext.xml"))))
}
