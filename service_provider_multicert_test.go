package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

type multiCertTestKey struct {
	key  *rsa.PrivateKey
	cert []byte
}

func newMultiCertTestKey(t *testing.T, name string) multiCertTestKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	assert.NilError(t, err)
	return multiCertTestKey{key: key, cert: der}
}

// TestSPValidateSignatureMultipleCertsWithoutX509Certificate covers IdPs
// whose metadata lists several signing certificates and whose Signature
// KeyInfo carries no X509Certificate (only a KeyValue, or no KeyInfo at all).
func TestSPValidateSignatureMultipleCertsWithoutX509Certificate(t *testing.T) {
	keyA := newMultiCertTestKey(t, "a.idp.example.com")
	keyB := newMultiCertTestKey(t, "b.idp.example.com")
	untrusted := newMultiCertTestKey(t, "untrusted.example.com")

	newSP := func(now time.Time, trusted ...multiCertTestKey) *ServiceProvider {
		descriptor := IDPSSODescriptor{}
		for _, k := range trusted {
			descriptor.KeyDescriptors = append(descriptor.KeyDescriptors, KeyDescriptor{
				Use: "signing",
				KeyInfo: KeyInfo{X509Data: X509Data{
					X509Certificates: []X509Certificate{{Data: base64.StdEncoding.EncodeToString(k.cert)}},
				}},
			})
		}
		return &ServiceProvider{
			IDPMetadata: &EntityDescriptor{
				EntityID:          "https://idp.example.com/metadata",
				IDPSSODescriptors: []IDPSSODescriptor{descriptor},
			},
			Clock: dsig.NewFakeClockAt(now),
		}
	}

	// signedResponse returns a Response signed by signer, with its KeyInfo
	// rewritten according to keyInfo: "x509" leaves the X509Certificate
	// dsig adds, "keyvalue" replaces it with an RSAKeyValue, and "none"
	// removes KeyInfo. tamper, if set, changes the signed content.
	signedResponse := func(t *testing.T, signer multiCertTestKey, keyInfo string, tamper bool) *etree.Element {
		t.Helper()
		doc := etree.NewDocument()
		responseEl := doc.CreateElement("samlp:Response")
		responseEl.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
		responseEl.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
		responseEl.CreateAttr("ID", "_response")
		responseEl.CreateElement("saml:Issuer").SetText("https://idp.example.com/metadata")

		signingContext, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert})
		assert.NilError(t, err)
		signingContext.IdAttribute = "ID"
		signingContext.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		assert.NilError(t, signingContext.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
		signedEl, err := signingContext.SignEnveloped(responseEl)
		assert.NilError(t, err)

		// Round-trip through bytes, as a received response would be, so
		// that the Signature's namespace declarations are resolved.
		doc = etree.NewDocument()
		doc.SetRoot(signedEl)
		buf, err := doc.WriteToBytes()
		assert.NilError(t, err)
		doc = etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(buf))
		signedEl = doc.Root()
		sigEl := signedEl.FindElement("./Signature")
		keyInfoEl := sigEl.FindElement("./KeyInfo")
		assert.Assert(t, keyInfoEl != nil)
		switch keyInfo {
		case "x509":
		case "keyvalue":
			for _, child := range keyInfoEl.ChildElements() {
				keyInfoEl.RemoveChild(child)
			}
			rsaKeyValue := keyInfoEl.CreateElement(keyInfoEl.Space + ":KeyValue").CreateElement(keyInfoEl.Space + ":RSAKeyValue")
			rsaKeyValue.CreateElement(keyInfoEl.Space + ":Modulus").SetText(base64.StdEncoding.EncodeToString(signer.key.N.Bytes()))
			rsaKeyValue.CreateElement(keyInfoEl.Space + ":Exponent").SetText(base64.StdEncoding.EncodeToString(big.NewInt(int64(signer.key.E)).Bytes()))
		case "none":
			sigEl.RemoveChild(keyInfoEl)
		default:
			t.Fatalf("unknown keyInfo %q", keyInfo)
		}
		if tamper {
			signedEl.FindElement("./Issuer").SetText("https://evil.example.com/metadata")
		}
		return signedEl
	}

	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		now      time.Time
		trusted  []multiCertTestKey
		signer   multiCertTestKey
		keyInfo  string
		tamper   bool
		wantErrs string
	}{
		{name: "second cert, KeyValue", trusted: []multiCertTestKey{keyA, keyB}, signer: keyB, keyInfo: "keyvalue"},
		{name: "second cert, no KeyInfo", trusted: []multiCertTestKey{keyA, keyB}, signer: keyB, keyInfo: "none"},
		{name: "first cert, KeyValue", trusted: []multiCertTestKey{keyA, keyB}, signer: keyA, keyInfo: "keyvalue"},
		{name: "second cert, X509Certificate", trusted: []multiCertTestKey{keyA, keyB}, signer: keyB, keyInfo: "x509"},
		{name: "single cert, KeyValue", trusted: []multiCertTestKey{keyB}, signer: keyB, keyInfo: "keyvalue"},
		{
			name: "untrusted signer, KeyValue", trusted: []multiCertTestKey{keyA, keyB}, signer: untrusted, keyInfo: "keyvalue",
			wantErrs: "cannot validate signature on Response: crypto/rsa: verification error",
		},
		{
			name: "untrusted signer, no KeyInfo", trusted: []multiCertTestKey{keyA, keyB}, signer: untrusted, keyInfo: "none",
			wantErrs: "cannot validate signature on Response: crypto/rsa: verification error",
		},
		{
			name: "untrusted signer, X509Certificate", trusted: []multiCertTestKey{keyA, keyB}, signer: untrusted, keyInfo: "x509",
			wantErrs: "cannot validate signature on Response: Could not verify certificate against trusted certs",
		},
		{
			name: "tampered, KeyValue", trusted: []multiCertTestKey{keyA, keyB}, signer: keyB, keyInfo: "keyvalue", tamper: true,
			wantErrs: "cannot validate signature on Response: Signature could not be verified",
		},
		{
			name: "signer not in single-cert metadata", trusted: []multiCertTestKey{keyA}, signer: keyB, keyInfo: "keyvalue",
			wantErrs: "cannot validate signature on Response: crypto/rsa: verification error",
		},
		{
			name: "expired certs, KeyValue", now: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
			trusted: []multiCertTestKey{keyA, keyB}, signer: keyB, keyInfo: "keyvalue",
			wantErrs: "cannot validate signature on Response: Cert is not valid at this time",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := now
			if !tc.now.IsZero() {
				at = tc.now
			}
			sp := newSP(at, tc.trusted...)
			err := sp.validateSignature(signedResponse(t, tc.signer, tc.keyInfo, tc.tamper))
			if tc.wantErrs == "" {
				assert.Check(t, err)
			} else {
				assert.Check(t, is.Error(err, tc.wantErrs))
			}
		})
	}
}
