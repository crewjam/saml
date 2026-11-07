package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// An encrypted element may arrive in an unsigned Response, and each
// xenc:EncryptedKey costs a private-key operation per decryption key, so
// only the first maxEncryptedKeyCandidates are tried.
func TestDecryptWithKeysBoundsEncryptedKeyCandidates(t *testing.T) {
	e := spcovSetup(t)
	plaintext := spcovSerialize(t, e.idpSign(t, e.assertion().Element()))
	otherCert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))

	junk := make([]multiKeyRecipient, maxEncryptedKeyCandidates)
	for i := range junk {
		junk[i] = multiKeyRecipient{cert: otherCert}
	}

	parse := func(t *testing.T, recipients ...multiKeyRecipient) (*Assertion, error) {
		t.Helper()
		ea := multiKeyEncrypt(t, "saml:EncryptedAssertion", plaintext, recipients...)
		return e.specSigParse(t, e.specSigResponse(ea))
	}

	t.Run("key past the limit is not tried", func(t *testing.T) {
		_, err := parse(t, append(junk, multiKeyRecipient{cert: e.sp.Certificate})...)
		assert.Check(t, errors.Is(err, ErrDecryptionFailed), "%v", err)
	})

	t.Run("key within the limit", func(t *testing.T) {
		assertion, err := parse(t, append(junk[1:], multiKeyRecipient{cert: e.sp.Certificate})...)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("matching Recipient is tried first", func(t *testing.T) {
		mine := multiKeyRecipient{cert: e.sp.Certificate, recipient: e.sp.entityID()}
		assertion, err := parse(t, append(append(junk, junk...), mine)...)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})
}
