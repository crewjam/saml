package inspect

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml/xmlenc"
)

func TestDecryptAssertion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	assertion := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1" Version="2.0" IssueInstant="2026-01-02T15:04:05Z"><saml:Issuer>https://idp.example.com/</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion>`
	e := xmlenc.OAEP()
	e.BlockCipher = xmlenc.AES128GCM
	data, err := e.Encrypt(cert, []byte(assertion), nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	resp.CreateAttr("ID", "r1")
	resp.CreateElement("saml:EncryptedAssertion").AddChild(data)
	msg, _ := doc.WriteToString()

	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	res := ParseWithKeys(msg, keyPEM, time.Now())
	if res.KeysError != "" {
		t.Fatalf("keys error: %s", res.KeysError)
	}
	if len(res.Messages) != 2 || res.Messages[1].Type != "Assertion" {
		t.Fatalf("got %d messages", len(res.Messages))
	}
	dec := res.Messages[1]
	if !strings.Contains(dec.XML, "alice@example.com") {
		t.Errorf("decrypted XML: %s", dec.XML)
	}
	found := false
	for _, c := range dec.View.Checks {
		found = found || c.Text == "Decrypted"
	}
	if !found {
		t.Errorf("no Decrypted check: %+v", dec.View.Checks)
	}

	// The wrong key: a warning, and no decrypted message.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	res = ParseWithKeys(msg, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})), time.Now())
	if len(res.Messages) != 1 || !strings.Contains(strings.Join(res.Messages[0].Warnings, "\n"), "cannot be decrypted") {
		t.Errorf("wrong key: %d messages, warnings %q", len(res.Messages), res.Messages[0].Warnings)
	}
}
