package inspect

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml/xmlenc"
)

// parsePrivateKeys reads the PEM private keys in text ("PRIVATE KEY",
// "RSA PRIVATE KEY" or "EC PRIVATE KEY" blocks), skipping other blocks.
func parsePrivateKeys(text string) ([]crypto.PrivateKey, error) {
	var keys []crypto.PrivateKey
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return keys, nil
		}
		var key crypto.PrivateKey
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return keys, fmt.Errorf("a PEM block is not a valid %s: %w", strings.ToLower(block.Type), err)
		}
		keys = append(keys, key)
	}
}

// decryptAssertions adds, after each message that has an
// EncryptedAssertion, a message for the assertion decrypted with one of
// keys. It runs before the signatures are checked, so that the
// assertion's own signature is checked too. A message whose assertion
// cannot be decrypted with any of the keys gets a warning saying so.
func decryptAssertions(res *Result, keys []crypto.PrivateKey, now time.Time) {
	var out []*Message
	for _, m := range res.Messages {
		out = append(out, m)
		if m.raw == nil {
			continue
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(m.raw); err != nil {
			continue
		}
		for _, ea := range doc.FindElements("//EncryptedAssertion") {
			plain, err := decryptWithAny(keys, ea)
			if err != nil {
				m.Warnings = append(m.Warnings, "the encrypted assertion cannot be decrypted with the private key given: "+err.Error())
				continue
			}
			dm := parseXML(plain, "", "decrypted", now)
			dm.Sections = append([]Section{{Title: "Decrypted", Rows: []KV{{"With", "the private key given to decrypt with"}}}}, dm.Sections...)
			out = append(out, dm)
		}
	}
	res.Messages = out
}

// decryptWithAny decrypts an EncryptedAssertion with the first of keys
// that works. The content key may be in the EncryptedData's KeyInfo or,
// as Entra ID sends it, beside the EncryptedData.
func decryptWithAny(keys []crypto.PrivateKey, ea *etree.Element) ([]byte, error) {
	data := ea.FindElement("./EncryptedData")
	if data == nil {
		return nil, errors.New("it has no EncryptedData")
	}
	err := errors.New("no private key was given")
	for _, key := range keys {
		var plain []byte
		if ek := ea.FindElement("./EncryptedKey"); ek != nil {
			var cek []byte
			if cek, err = xmlenc.Decrypt(key, ek); err == nil {
				plain, err = xmlenc.Decrypt(cek, data)
			}
		} else {
			plain, err = xmlenc.Decrypt(key, data)
		}
		if err == nil {
			return plain, nil
		}
	}
	return nil, err
}
