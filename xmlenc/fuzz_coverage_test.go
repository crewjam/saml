package xmlenc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

// covFuzzKey is the RSA key the tests decrypt with when calling Fuzz.
var covFuzzKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// covTestKeyDocument returns an EncryptedData document encrypted to covFuzzKey,
// the key the tests pass to Fuzz.
func covTestKeyDocument(t testing.TB, e RSA) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "fuzz.example.com"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &covFuzzKey().PublicKey, covFuzzKey())
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)

	el, err := e.Encrypt(cert, []byte("<Assertion>fuzz</Assertion>"), nil)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return buf
}

func TestCovFuzz(t *testing.T) {
	assert.Check(t, is.Equal(0, Fuzz(covFuzzKey(), []byte("<unclosed"))), "not XML")
	assert.Check(t, is.Equal(0, Fuzz(covFuzzKey(), []byte(`<?xml version="1.0"?>`))), "no root element")
	assert.Check(t, is.Equal(0, Fuzz(covFuzzKey(), []byte("<EncryptedData/>"))), "does not decrypt")

	e := OAEP()
	e.BlockCipher = AES128CBC
	assert.Check(t, is.Equal(1, Fuzz(covFuzzKey(), covTestKeyDocument(t, e))), "decrypts")
	e.BlockCipher = AES256GCM
	assert.Check(t, is.Equal(1, Fuzz(covFuzzKey(), covTestKeyDocument(t, e))), "decrypts")
}

// covSeeds returns the fuzzing corpus, past crashers and a set of malformed
// documents that reach each decrypter with hostile input.
func covSeeds(t testing.TB) [][]byte {
	t.Helper()
	seeds := make([][]byte, 0, 256)
	for _, dir := range []string{"corpus", "crashers"} {
		entries, err := os.ReadDir(dir)
		assert.NilError(t, err)
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".output") || strings.HasSuffix(entry.Name(), ".quoted") {
				continue
			}
			buf, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // test fixtures
			assert.NilError(t, err)
			seeds = append(seeds, buf)
		}
	}

	wrap := func(alg, inner, cipherValue string) []byte {
		return []byte(`<EncryptedData><EncryptionMethod Algorithm="` + alg + `"/>` + inner +
			`<CipherData><CipherValue>` + cipherValue + `</CipherValue></CipherData></EncryptedData>`)
	}
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	oaep := "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	for _, alg := range []string{
		AES128CBC.Algorithm(), AES192CBC.Algorithm(), AES256CBC.Algorithm(),
		AES128GCM.Algorithm(), AES192GCM.Algorithm(), AES256GCM.Algorithm(),
		oaep, TripleDES.Algorithm(), PKCS1v15().Algorithm(), "",
	} {
		for _, n := range []int{0, 1, 8, 15, 16, 17, 27, 28, 32, 128, 129, 256} {
			seeds = append(seeds, wrap(alg, "", b64(n)))
		}
		seeds = append(seeds,
			wrap(alg, "", "not base64"),
			[]byte(`<EncryptedData><EncryptionMethod Algorithm="`+alg+`"/></EncryptedData>`),
			// A nested EncryptedKey whose own key is nested again.
			wrap(alg, `<KeyInfo><EncryptedKey><EncryptionMethod Algorithm="`+oaep+`"/>`+
				`<KeyInfo><X509Data><X509Certificate>AAAA</X509Certificate></X509Data></KeyInfo>`+
				`<CipherData><CipherValue>`+b64(128)+`</CipherValue></CipherData></EncryptedKey></KeyInfo>`, b64(32)),
			wrap(alg, `<KeyInfo><EncryptedKey><EncryptionMethod Algorithm="`+oaep+`">`+
				`<DigestMethod Algorithm="cov:digest"/></EncryptionMethod>`+
				`<CipherData><CipherValue>`+b64(128)+`</CipherValue></CipherData></EncryptedKey></KeyInfo>`, b64(32)),
		)
	}
	return seeds
}

// Malformed input must be refused with an error, never a panic.
func TestCovFuzzSeedsDoNotPanic(t *testing.T) {
	for _, seed := range covSeeds(t) {
		assert.Check(t, is.Equal(0, Fuzz(covFuzzKey(), seed)), "%q", seed)
	}
}

func FuzzCovDecrypt(f *testing.F) {
	for _, seed := range covSeeds(f) {
		f.Add(seed)
	}
	e := OAEP()
	e.BlockCipher = AES128CBC
	f.Add(covTestKeyDocument(f, e))
	f.Fuzz(func(_ *testing.T, data []byte) {
		Fuzz(covFuzzKey(), data)
	})
}
