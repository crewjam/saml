package saml

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// withPaddingCount sets the padding count, the last byte of the plaintext of
// the CBC encrypted assertion el, to 0 (which is never valid). from is the
// count the encryptor wrote. Changing a byte of the last ciphertext block but
// one changes the same byte of the last plaintext block.
func withPaddingCount(t *testing.T, el *etree.Element, from byte) {
	t.Helper()
	cipherValue := el.FindElement("./EncryptedData/CipherData/CipherValue")
	assert.Assert(t, cipherValue != nil)
	buf, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cipherValue.Text()))
	assert.NilError(t, err)
	buf[len(buf)-16-1] ^= from
	cipherValue.SetText(base64.StdEncoding.EncodeToString(buf))
}

// A sender of modified CBC ciphertexts must not learn from the error whether
// one failed on its padding or on the XML it decrypted to.
func TestDecryptionErrorsIndistinguishable(t *testing.T) {
	e := spcovSetup(t)
	parse := func(encrypted *etree.Element) error {
		el := e.response().Element()
		el.AddChild(encrypted)
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, el), []string{spcovRequestID}, e.sp.AcsURL)
		return spcovPrivateErr(t, err)
	}

	plaintext := []byte("<!-- nothing -->") // 16 bytes, so 16 bytes of padding
	badPadding := e.encryptedAssertion(t, plaintext)
	withPaddingCount(t, badPadding, 16)
	noRoot := e.encryptedAssertion(t, plaintext)
	notXML := e.encryptedAssertion(t, []byte("<a>\x01</a>"))
	unbalanced := e.encryptedAssertion(t, []byte("<a>"))

	const want = "failed to decrypt EncryptedAssertion: xmlenc: decryption failed"
	for name, el := range map[string]*etree.Element{
		"bad padding": badPadding,
		"no root":     noRoot,
		"not XML":     notXML,
		"unbalanced":  unbalanced,
	} {
		assert.Check(t, is.Error(parse(el), want), name)
	}
}
