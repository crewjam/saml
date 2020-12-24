package xmlenc

import (
	"crypto/x509"
	"encoding/pem"
	"gotest.tools/golden"
	"math/rand"
	"testing"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
)

func TestCanEncryptOAEP(t *testing.T) {
	RandReader = rand.New(rand.NewSource(0)) // deterministic random numbers for tests

	pemBlock, _ := pem.Decode([]byte(golden.Get(t, "cert.pem")))
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	assert.NoError(t, err)

	e := OAEP()
	e.BlockCipher = AES128CBC
	e.DigestMethod = &SHA1

	el, err := e.Encrypt(certificate, golden.Get(t, "plaintext.xml"))
	assert.NoError(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(el)
	doc.IndentTabs()
	ciphertext, _ := doc.WriteToString()

	assert.Equal(t, ciphertext,  string(golden.Get(t, "ciphertext.xml")))
}
