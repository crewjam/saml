// Command entra_id_gen regenerates the TestSPCanHandleEntraIDResponse_*
// fixtures used by entra_id_test.go. Run it from the repository root:
//
//	go run ./testdata/entra_id_gen
//
// The responses are synthetic but follow the wire format Microsoft Entra ID
// (Azure AD) uses; see the comment on TestSPCanHandleEntraIDResponse. They
// are signed with the throwaway key in testdata/entra_id_gen/idp_key.pem and
// encrypted to testdata/sp_cert.pem. RSA PKCS#1 v1.5 signatures are
// deterministic, so rerunning reproduces every fixture except the encrypted
// one, whose content key and IV are random.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Entra wraps the content key with RSA-OAEP-MGF1P (SHA-1).
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	entraTenant  = "8c3a9b2e-4f1d-4e6a-9b7c-2d5e8f1a3c4b"
	entraIssuer  = "https://sts.windows.net/" + entraTenant + "/"
	entraLogin   = "https://login.microsoftonline.com/" + entraTenant + "/saml2"
	entraACS     = "https://sp.example.com/saml/acs"
	entraSPID    = "https://sp.example.com/saml/metadata"
	entraReqID   = "id-4f6e2c9d8a7b1e3f5d0c2b4a6e8f1d3c5b7a9e0f"
	entraRespID  = "_b2f6a1c4-7d3e-4c8b-9a5f-1e2d3c4b5a69"
	entraAsrtID  = "_d4e7f2a9-3b1c-4e6d-8f0a-5c2b9e7d1a38"
	entraSession = "_d4e7f2a9-3b1c-4e6d-8f0a-5c2b9e7d1a38"
)

func entraSign(kp tls.Certificate, el *etree.Element) *etree.Element {
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(kp))
	ctx.Prefix = ""
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		log.Fatal(err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		log.Fatal(err)
	}
	// Entra puts the Signature right after Issuer rather than last.
	// goxmldsig appends it without setting its parent, so rebuild Child.
	sig := signed.ChildElements()[len(signed.ChildElements())-1]
	out := signed.Copy()
	out.Child = nil
	for _, c := range signed.ChildElements() {
		if c == sig {
			continue
		}
		out.AddChild(c.Copy())
		if c.Tag == "Issuer" {
			out.AddChild(sig.Copy())
		}
	}
	if out.FindElement("./Issuer") == nil {
		out.InsertChildAt(0, sig.Copy())
	}
	signed = out
	return signed
}

func entraAssertion(idpInitiated bool) string {
	irt := ` InResponseTo="` + entraReqID + `"`
	if idpInitiated {
		irt = ""
	}
	attr := func(name string, values ...string) string {
		s := `<Attribute Name="` + name + `">`
		for _, v := range values {
			s += `<AttributeValue>` + v + `</AttributeValue>`
		}
		return s + `</Attribute>`
	}
	return `<Assertion ID="` + entraAsrtID + `" IssueInstant="2025-06-02T15:04:05.123Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Issuer>` + entraIssuer + `</Issuer>` +
		`<Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@contoso.example</NameID>` +
		`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData` + irt + ` NotOnOrAfter="2025-06-02T15:09:05.123Z" Recipient="` + entraACS + `"/></SubjectConfirmation></Subject>` +
		`<Conditions NotBefore="2025-06-02T14:59:05.123Z" NotOnOrAfter="2025-06-02T16:14:05.123Z"><AudienceRestriction><Audience>` + entraSPID + `</Audience></AudienceRestriction></Conditions>` +
		`<AttributeStatement>` +
		attr("http://schemas.microsoft.com/identity/claims/tenantid", entraTenant) +
		attr("http://schemas.microsoft.com/identity/claims/objectidentifier", "5e1c9a7f-2b4d-4a8e-9c3f-7d1b6e2a4c90") +
		attr("http://schemas.microsoft.com/identity/claims/displayname", "Alice Example") +
		attr("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "0f3b5d7e-1a2c-4e6f-8b9d-3c5e7f9a1b2d", "a7c9e1f3-5b7d-4f2a-8c4e-6d8f0a2c4e6b") +
		attr("http://schemas.microsoft.com/identity/claims/identityprovider", entraIssuer) +
		attr("http://schemas.microsoft.com/claims/authnmethodsreferences", "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password", "http://schemas.microsoft.com/claims/multipleauthn") +
		attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "Alice") +
		attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "Example") +
		attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "alice@contoso.example") +
		attr("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "alice@contoso.example") +
		`</AttributeStatement>` +
		`<AuthnStatement AuthnInstant="2025-06-02T15:03:58.456Z" SessionIndex="` + entraSession + `"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext></AuthnStatement>` +
		`</Assertion>`
}

func parseEl(s string) *etree.Element {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(s); err != nil {
		log.Fatal(err)
	}
	return doc.Root()
}

func entraResponse(kp tls.Certificate, signResponse, signAssertion, encrypt, idpInitiated bool) []byte {
	irt := ` InResponseTo="` + entraReqID + `"`
	if idpInitiated {
		irt = ""
	}
	resp := parseEl(`<samlp:Response ID="` + entraRespID + `" Version="2.0" IssueInstant="2025-06-02T15:04:05.123Z" Destination="` + entraACS + `"` + irt + ` xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` + entraIssuer + `</Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`</samlp:Response>`)
	assertion := parseEl(entraAssertion(idpInitiated))
	if signAssertion {
		assertion = entraSign(kp, assertion)
	}
	if encrypt {
		resp.AddChild(entraEncrypt(assertion))
	} else {
		resp.AddChild(assertion)
	}
	if signResponse {
		resp = entraSign(kp, resp)
	}
	doc := etree.NewDocument()
	doc.SetRoot(resp)
	b, err := doc.WriteToBytes()
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// entraEncrypt mimics the WIF-style EncryptedAssertion Entra ID produces when
// token encryption is enabled: AES-256-CBC content, RSA-OAEP key transport,
// an "e:" prefix on EncryptedKey and an unprefixed default-namespace KeyInfo.
func entraEncrypt(assertion *etree.Element) *etree.Element {
	spCert := readCert("testdata/sp_cert.pem")
	doc := etree.NewDocument()
	doc.SetRoot(assertion.Copy())
	plaintext, err := doc.WriteToBytes()
	if err != nil {
		log.Fatal(err)
	}
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(key)
	_, _ = rand.Read(iv)
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte{}, plaintext...), make([]byte, pad)...)
	padded[len(padded)-1] = byte(pad)
	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, spCert.PublicKey.(*rsa.PublicKey), key, nil)
	if err != nil {
		log.Fatal(err)
	}
	s := `<EncryptedAssertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">` +
		`<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>` +
		`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">` +
		`<e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></e:EncryptionMethod>` +
		`<KeyInfo><o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><X509Data><X509IssuerSerial>` +
		`<X509IssuerName>` + spCert.Issuer.String() + `</X509IssuerName><X509SerialNumber>` + spCert.SerialNumber.String() + `</X509SerialNumber>` +
		`</X509IssuerSerial></X509Data></o:SecurityTokenReference></KeyInfo>` +
		`<e:CipherData><e:CipherValue>` + base64.StdEncoding.EncodeToString(wrapped) + `</e:CipherValue></e:CipherData></e:EncryptedKey></KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(append(iv, ct...)) + `</xenc:CipherValue></xenc:CipherData>` +
		`</xenc:EncryptedData></EncryptedAssertion>`
	return parseEl(s)
}

func entraMetadata(kp tls.Certificate) []byte {
	cert := base64.StdEncoding.EncodeToString(kp.Certificate[0])
	kd := `<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + cert + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>`
	claims := []string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		"http://schemas.microsoft.com/identity/claims/objectidentifier",
	}
	var offered strings.Builder
	for _, c := range claims {
		offered.WriteString(`<auth:ClaimType Uri="` + c + `" xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706"><auth:DisplayName>` + c[strings.LastIndex(c, "/")+1:] + `</auth:DisplayName></auth:ClaimType>`)
	}
	ed := parseEl(`<EntityDescriptor ID="_6a1e3c5b-8d7f-4b2a-9e0c-1f3d5b7a9c2e" entityID="` + entraIssuer + `" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` +
		`<RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706">` +
		kd + `<fed:ClaimTypesOffered>` + offered.String() + `</fed:ClaimTypesOffered>` +
		`<fed:SecurityTokenServiceEndpoint><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>https://login.microsoftonline.com/` + entraTenant + `/wsfed</wsa:Address></wsa:EndpointReference></fed:SecurityTokenServiceEndpoint>` +
		`<fed:PassiveRequestorEndpoint><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>https://login.microsoftonline.com/` + entraTenant + `/wsfed</wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint>` +
		`</RoleDescriptor>` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + kd +
		`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + entraLogin + `"/>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + entraLogin + `"/>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + entraLogin + `"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`)
	ed = entraSign(kp, ed)
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="utf-8"`)
	doc.AddChild(ed)
	b, err := doc.WriteToBytes()
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func readCert(path string) *x509.Certificate {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		log.Fatalf("%s: no PEM data", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func main() {
	kp, err := tls.LoadX509KeyPair("testdata/entra_id_gen/idp_cert.pem", "testdata/entra_id_gen/idp_key.pem")
	if err != nil {
		log.Fatal(err)
	}
	w := func(name string, b []byte) {
		if err := os.WriteFile("testdata/TestSPCanHandleEntraIDResponse_"+name, b, 0o644); err != nil { //nolint:gosec // test fixtures
			log.Fatal(err)
		}
	}
	w("IDPMetadata", entraMetadata(kp))
	w("assertion_signed", entraResponse(kp, false, true, false, false))
	w("response_signed", entraResponse(kp, true, false, false, false))
	w("response_and_assertion_signed", entraResponse(kp, true, true, false, false))
	w("encrypted_assertion_signed", entraResponse(kp, false, true, true, false))
	w("idp_initiated", entraResponse(kp, false, true, false, true))
}
