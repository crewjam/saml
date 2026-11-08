package inspect

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func TestVerifyFixtures(t *testing.T) {
	okta := testdata(t, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_response")
	oktaMD := testdata(t, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_IDPMetadata")
	oneloginMD := testdata(t, "TestSPCanHandleOneloginResponse_IDPMetadata")

	// Without keys, only the integrity check, with the KeyInfo
	// certificate, is made.
	m := only(t, Parse(okta, now))
	if len(m.Signatures) != 1 || m.Signatures[0].Trust != nil {
		t.Fatalf("%+v", m.Signatures)
	}
	m = only(t, ParseWithKeys(okta, "", now))
	if c := m.Signatures[0].Integrity; c == nil || !c.OK {
		t.Fatalf("integrity: %+v", c)
	}

	// With the IdP's metadata, the signature is trusted.
	res := ParseWithKeys(okta, oktaMD, now)
	if res.KeysError != "" || len(res.Keys) == 0 {
		t.Fatalf("keys: %q %d", res.KeysError, len(res.Keys))
	}
	if c := only(t, res).Signatures[0].Trust; c == nil || !c.OK || c.By == "" {
		t.Fatalf("trust: %+v", c)
	}

	// With another IdP's certificate, it is not.
	if c := only(t, ParseWithKeys(okta, oneloginMD, now)).Signatures[0].Trust; c == nil || c.OK || c.Error == "" {
		t.Fatalf("untrusted: %+v", c)
	}

	// A tampered message fails the integrity check.
	xml, _ := DecodeBase64Message(okta)
	tampered := strings.Replace(string(xml), "http://localhost:8000/saml/acs", "http://evil.example/saml/acs", 1)
	if c := only(t, ParseWithKeys(tampered, oktaMD, now)).Signatures[0]; c.Integrity.OK || c.Trust.OK {
		t.Fatalf("tampered: %+v %+v", c.Integrity, c.Trust)
	}

	if res := ParseWithKeys(okta, "not a certificate", now); res.KeysError == "" {
		t.Error("expected a keys error")
	}
}

func newCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// The three ways an SP signs an AuthnRequest, made by x/samlsp, each
// checked with its certificate and with another.
func TestVerifyBindings(t *testing.T) {
	key, cert, certPEM := newCert(t)
	_, _, otherPEM := newCert(t)
	config, err := samlsp.New("https://sp.example.com/saml/metadata",
		samlsp.StaticMetadataBytes([]byte(idpMetadata(otherPEM))),
		samlsp.WithSigningKey(key, cert), samlsp.SignAuthnRequests,
		samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { sp.IgnoreCertificateExpiry = true }))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	at := time.Now()

	// HTTP-Redirect: the signature is in the query string.
	msg, err := config.AuthnRequest(ctx, "relay", samlsp.WithBinding(saml.HTTPRedirectBinding))
	if err != nil {
		t.Fatal(err)
	}
	u := msg.RedirectURL().String()
	res := ParseWithKeys(u, certPEM, at)
	if res.Detached == nil || res.Detached.Trust == nil || !res.Detached.Trust.OK {
		t.Fatalf("redirect: %+v %+v", res.Detached, res.Detached.Trust)
	}
	if res := ParseWithKeys(u, otherPEM, at); res.Detached.Trust.OK {
		t.Error("redirect: verified with another certificate")
	}
	if res := ParseWithKeys(strings.Replace(u, "RelayState=relay", "RelayState=other", 1), certPEM, at); res.Detached.Trust.OK {
		t.Error("redirect: verified with a changed RelayState")
	}

	// HTTP-POST: an enveloped XML signature.
	msg, err = config.AuthnRequest(ctx, "relay", samlsp.WithBinding(saml.HTTPPostBinding))
	if err != nil {
		t.Fatal(err)
	}
	body := msg.FormFields().Encode()
	m := only(t, ParseWithKeys(body, certPEM, at))
	if len(m.Signatures) != 1 || m.Signatures[0].Trust == nil || !m.Signatures[0].Trust.OK {
		t.Fatalf("post: %+v", m.Signatures)
	}
	if m := only(t, ParseWithKeys(body, otherPEM, at)); m.Signatures[0].Trust.OK {
		t.Error("post: verified with another certificate")
	}

	// HTTP-POST-SimpleSign: the signature is in the form.
	msg, err = config.AuthnRequest(ctx, "relay", samlsp.WithBinding(saml.HTTPPostSimpleSignBinding))
	if err != nil {
		t.Fatal(err)
	}
	body = msg.FormFields().Encode()
	res = ParseWithKeys(body, certPEM, at)
	if res.Binding != "HTTP-POST-SimpleSign" || res.Detached == nil || !res.Detached.Trust.OK {
		t.Fatalf("simplesign: %q %+v", res.Binding, res.Detached)
	}
	if res := ParseWithKeys(body, otherPEM, at); res.Detached.Trust.OK {
		t.Error("simplesign: verified with another certificate")
	}
}

// idpMetadata is the metadata of an IdP that offers every binding.
func idpMetadata(certPEM string) string {
	b, _ := pem.Decode([]byte(certPEM))
	cert := base64.StdEncoding.EncodeToString(b.Bytes)
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + cert + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
}
