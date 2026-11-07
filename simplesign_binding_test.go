package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"
)

// simpleSignMsg builds the form fields of an HTTP-POST-SimpleSign message the
// way a peer would, signing with key and sigAlg.
type simpleSignMsg struct {
	param      string
	xml        []byte
	relayState *string
	sigAlg     string
	key        crypto.Signer
}

func strPtr(s string) *string { return &s }

func (m simpleSignMsg) values(t *testing.T) url.Values {
	t.Helper()
	v := url.Values{}
	v.Set(m.param, base64.StdEncoding.EncodeToString(m.xml))
	content := m.param + "=" + string(m.xml)
	if m.relayState != nil {
		v.Set("RelayState", *m.relayState)
		content += "&RelayState=" + *m.relayState
	}
	content += "&SigAlg=" + m.sigAlg
	v.Set("SigAlg", m.sigAlg)
	v.Set("Signature", base64.StdEncoding.EncodeToString(redirectSign(t, m.key, m.sigAlg, content)))
	return v
}

// simpleSignPost returns a parsed POST request to target carrying v.
func simpleSignPost(t *testing.T, target string, v url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.NilError(t, req.ParseForm())
	return req
}

var (
	formInputRe  = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
	formActionRe = regexp.MustCompile(`<form method="post" action="([^"]*)"`)
)

// formFields returns the action and the hidden fields of an HTML form.
func formFields(t *testing.T, form []byte) (string, url.Values) {
	t.Helper()
	action := formActionRe.FindSubmatch(form)
	assert.Assert(t, action != nil, string(form))
	v := url.Values{}
	for _, m := range formInputRe.FindAllSubmatch(form, -1) {
		v.Add(string(m[1]), html.UnescapeString(string(m[2])))
	}
	return html.UnescapeString(string(action[1])), v
}

func TestSimpleSignSignedContent(t *testing.T) {
	// sstc-saml-binding-simplesign-cs-01 section 2.5: the raw XML (not the
	// base64 text), the RelayState and the SigAlg, none URL encoded and
	// whitespace kept as is.
	xml := []byte("<samlp:LogoutRequest ID=\"a&amp;b\">\n  <Issuer>x</Issuer>\r\n</samlp:LogoutRequest>")
	assert.Equal(t,
		string(simpleSignSignedContent("SAMLRequest", xml, "a b&c=d/é", true, dsig.RSASHA1SignatureMethod)),
		"SAMLRequest=<samlp:LogoutRequest ID=\"a&amp;b\">\n  <Issuer>x</Issuer>\r\n</samlp:LogoutRequest>"+
			"&RelayState=a b&c=d/é&SigAlg=http://www.w3.org/2000/09/xmldsig#rsa-sha1")
	assert.Equal(t,
		string(simpleSignSignedContent("SAMLResponse", []byte("<r/>"), "", false, dsig.RSASHA256SignatureMethod)),
		"SAMLResponse=<r/>&SigAlg=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
	// A RelayState control that is present but empty is still signed, as
	// OpenSAML's SAML2HTTPPostSimpleSignSecurityHandler does.
	assert.Equal(t,
		string(simpleSignSignedContent("SAMLResponse", []byte("<r/>"), "", true, dsig.RSASHA256SignatureMethod)),
		"SAMLResponse=<r/>&RelayState=&SigAlg=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
}

// TestSimpleSignKnownAnswer pins the whole signing path: RSA PKCS#1 v1.5 is
// deterministic, so the Signature for a fixed message, relay state and key
// never changes.
func TestSimpleSignKnownAnswer(t *testing.T) {
	e := spcovSetup(t)
	ctx, err := dsig.NewSigningContext(e.idpKey, nil)
	assert.NilError(t, err)
	assert.NilError(t, ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
	sigAlg, signature, err := signSimpleSign(ctx, "SAMLResponse", []byte("<samlp:Response/>"), "token")
	assert.NilError(t, err)
	assert.Equal(t, sigAlg, dsig.RSASHA256SignatureMethod)
	assert.Equal(t, signature, "AW4WbYmeV5ZjSdnxFUAouuzk3bMUZslSnPrukjUTYL7wQs7rX9JRVlPzpzRgFOHYpKtahC/XMRWMMC1PUZEKVfl2vNnC1V6XLcMAoZticUPTLvJaLJ0N7Ujek18gG1t6hvAwN+GaFezqwbdAQvjpuWzi1A32/n+Ax1QFT0txuuY=")

	// It is a plain RSA-SHA256 signature over the literal octet string.
	sig, err := base64.StdEncoding.DecodeString(signature)
	assert.NilError(t, err)
	assert.NilError(t, e.idpCert.CheckSignature(x509.SHA256WithRSA,
		[]byte("SAMLResponse=<samlp:Response/>&RelayState=token&SigAlg=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"), sig))
}

// otherKey returns a key that no test certificate trusts as the IDP's, and
// its certificate.
func otherKey(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	return mustParsePrivateKey(golden.Get(t, "key_2017.pem")), mustParseCertificate(golden.Get(t, "cert_2017.pem"))
}

// The example form values in sstc-saml-binding-simplesign-cs-01 section 2.11
// are line wrapped; they must still decode.
func TestSimpleSignDecodesLineWrappedSpecExample(t *testing.T) {
	const samlRequest = "PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1l\n" +
		"czp0YzpTQU1MOjIuMDpwcm90b2NvbCIgeG1sbnM9InVybjpvYXNpczpuYW1lczp0\n" +
		"YzpTQU1MOjIuMDphc3NlcnRpb24iCiAgICBJRD0iZDJiN2MzODhjZWMzNmZhN2Mz\n" +
		"OWMyOGZkMjk4NjQ0YTgiIElzc3VlSW5zdGFudD0iMjAwNC0wMS0yMVQxOTowMDo0\n" +
		"OVoiIFZlcnNpb249IjIuMCI+CiAgICA8SXNzdWVyPmh0dHBzOi8vSWRlbnRpdHlQ\n" +
		"cm92aWRlci5jb20vU0FNTDwvSXNzdWVyPgogICAgPE5hbWVJRCBGb3JtYXQ9InVy\n" +
		"bjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnBlcnNpc3Rl\n" +
		"bnQiPjAwNWEwNmUwLWFkODItMTEwZC1hNTU2LTAwNDAwNWIxM2EyYjwvTmFtZUlE\n" +
		"PgogICAgPHNhbWxwOlNlc3Npb25JbmRleD4xPC9zYW1scDpTZXNzaW9uSW5kZXg+\n" +
		"Cjwvc2FtbHA6TG9nb3V0UmVxdWVzdD4K"
	v := url.Values{}
	v.Set("RelayState", "0043bfc1bc45110dae17004005b13a2b")
	v.Set("SAMLRequest", samlRequest)
	v.Set("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
	v.Set("Signature", "J4if7CCeHVfn4H6hMZN5fijOjQIyZ/laoFUZWz4LCRN3J82UeoyYvAiTDoQOUZHT\n"+
		"RJNU1lWGub1pW4QR9MH5bwfLEa8XDivA118dR0Q7YN5L/U5rmbxnGlQ9pV0jT44c\n"+
		"RNeqtbLW0YF4plfcqg7E5iOSljE3QLkiaAdkAec2a4HwPFkn/JP7wO11Mc6kU8ML\n"+
		"CBbZAa3+94ZvVwHBEdyCdU+1yEvf+JGxTw66BwI2ugmPfxvoJdsOOAWwS3KhAFhL\n"+
		"LSPXnhb3nd/ovKNNV/khZYwqsFTFNTMA+0JraKsZiCRtEZzEPXaP9KilrjPIIvRV\n"+
		"xDQhETj96flk5zMkEM3ruw==")
	m, err := parseSimpleSignRequest(simpleSignPost(t, "https://sp.example.com/saml/slo", v), "SAMLRequest")
	assert.NilError(t, err)
	content := string(m.signedContent())
	assert.Check(t, strings.HasPrefix(content, "SAMLRequest=<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\"\n    ID=\"d2b7c388cec36fa7c39c28fd298644a8\""), content)
	assert.Check(t, strings.HasSuffix(content, "</samlp:LogoutRequest>\n&RelayState=0043bfc1bc45110dae17004005b13a2b&SigAlg=http://www.w3.org/2000/09/xmldsig#rsa-sha1"), content)
	_, sig, err := decodeDetachedSignature(m.SigAlg, m.Signature, simpleSignBase64)
	assert.NilError(t, err)
	assert.Check(t, is.Len(sig, 256))
}

// simpleSignResponse returns a valid Response for e.sp whose assertion is
// not signed.
func (e *spcovEnv) simpleSignResponseXML(t *testing.T, mutate func(*Response)) []byte {
	t.Helper()
	resp := e.response()
	if mutate != nil {
		mutate(resp)
	}
	el := resp.Element()
	el.AddChild(e.assertion().Element())
	return spcovSerialize(t, el)
}

func TestSimpleSignResponseAtACS(t *testing.T) {
	e := spcovSetup(t)
	acs := e.sp.AcsURL.String()
	unsigned := e.simpleSignResponseXML(t, nil)
	valid := simpleSignMsg{param: "SAMLResponse", xml: unsigned, sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
	parse := func(t *testing.T, sp *ServiceProvider, v url.Values) (*Assertion, error) {
		t.Helper()
		return sp.ParseResponse(simpleSignPost(t, acs, v), []string{spcovRequestID})
	}
	accept := func(t *testing.T, sp *ServiceProvider, v url.Values) {
		t.Helper()
		assertion, err := parse(t, sp, v)
		if err != nil {
			t.Fatalf("unexpected error: %v", spcovPrivateErr(t, err))
		}
		assert.Check(t, is.Equal("id-assertion", assertion.ID))
	}
	reject := func(t *testing.T, sp *ServiceProvider, v url.Values, wantErr string) {
		t.Helper()
		_, err := parse(t, sp, v)
		assert.Assert(t, err != nil)
		assert.ErrorContains(t, spcovPrivateErr(t, err), wantErr)
	}

	t.Run("valid, assertion unsigned", func(t *testing.T) {
		accept(t, e.sp, valid.values(t))
	})
	t.Run("plain HTTP-POST with an unsigned assertion is still rejected", func(t *testing.T) {
		v := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(unsigned)}}
		reject(t, e.sp, v, "signature element not present")
	})
	for _, alg := range []string{dsig.RSASHA1SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod} {
		t.Run("algorithm "+alg, func(t *testing.T) {
			m := valid
			m.sigAlg = alg
			accept(t, e.sp, m.values(t))
		})
	}
	t.Run("with relay state", func(t *testing.T) {
		m := valid
		m.relayState = strPtr("a b&c=d/é")
		accept(t, e.sp, m.values(t))
	})
	t.Run("empty relay state field is signed", func(t *testing.T) {
		m := valid
		m.relayState = strPtr("")
		accept(t, e.sp, m.values(t))
	})
	t.Run("empty relay state field added after signing", func(t *testing.T) {
		v := valid.values(t)
		v.Set("RelayState", "")
		reject(t, e.sp, v, "verification error")
	})
	t.Run("tampered relay state", func(t *testing.T) {
		m := valid
		m.relayState = strPtr("token")
		v := m.values(t)
		v.Set("RelayState", "other")
		reject(t, e.sp, v, "verification error")
	})
	t.Run("relay state removed", func(t *testing.T) {
		m := valid
		m.relayState = strPtr("token")
		v := m.values(t)
		v.Del("RelayState")
		reject(t, e.sp, v, "verification error")
	})
	t.Run("tampered XML", func(t *testing.T) {
		v := valid.values(t)
		tampered := strings.Replace(string(unsigned), "alice@example.com", "mallory@example.com", 1)
		assert.Assert(t, tampered != string(unsigned))
		v.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(tampered)))
		reject(t, e.sp, v, "verification error")
	})
	t.Run("SigAlg changed", func(t *testing.T) {
		v := valid.values(t)
		v.Set("SigAlg", dsig.RSASHA512SignatureMethod)
		reject(t, e.sp, v, "verification error")
	})
	t.Run("SigAlg of the wrong key type", func(t *testing.T) {
		m := valid
		m.sigAlg = dsig.ECDSASHA256SignatureMethod
		v := url.Values{}
		v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(unsigned))
		v.Set("SigAlg", m.sigAlg)
		v.Set("Signature", valid.values(t).Get("Signature"))
		reject(t, e.sp, v, "cannot validate signature")
	})
	t.Run("unsupported SigAlg", func(t *testing.T) {
		v := valid.values(t)
		v.Set("SigAlg", "http://www.w3.org/2000/09/xmldsig#dsa-sha1")
		reject(t, e.sp, v, "unsupported signature algorithm")
	})
	t.Run("wrong key", func(t *testing.T) {
		m := valid
		m.key, _ = otherKey(t)
		reject(t, e.sp, m.values(t), "verification error")
	})
	t.Run("signature is not base64", func(t *testing.T) {
		v := valid.values(t)
		v.Set("Signature", "not base64!")
		reject(t, e.sp, v, "cannot decode signature")
	})
	t.Run("message is not base64", func(t *testing.T) {
		v := valid.values(t)
		v.Set("SAMLResponse", "not base64!")
		reject(t, e.sp, v, "cannot decode SAMLResponse")
	})
	for _, field := range []string{"SAMLResponse", "RelayState", "SigAlg", "Signature", "KeyInfo"} {
		t.Run("duplicate "+field, func(t *testing.T) {
			m := valid
			m.relayState = strPtr("token")
			v := m.values(t)
			v.Add(field, v.Get(field))
			v.Add(field, "x")
			reject(t, e.sp, v, "form field "+field+" appears more than once")
		})
	}
	t.Run("missing Signature", func(t *testing.T) {
		v := valid.values(t)
		v.Del("Signature")
		reject(t, e.sp, v, "form must contain both SigAlg and Signature")
	})
	t.Run("missing SigAlg", func(t *testing.T) {
		v := valid.values(t)
		v.Del("SigAlg")
		reject(t, e.sp, v, "form must contain both SigAlg and Signature")
	})
	t.Run("empty Signature", func(t *testing.T) {
		v := valid.values(t)
		v.Set("Signature", "")
		reject(t, e.sp, v, "form must contain both SigAlg and Signature")
	})
	t.Run("missing SAMLResponse", func(t *testing.T) {
		v := valid.values(t)
		v.Del("SAMLResponse")
		reject(t, e.sp, v, "form does not contain SAMLResponse")
	})
	t.Run("SAMLRequest alongside", func(t *testing.T) {
		v := valid.values(t)
		v.Set("SAMLRequest", "x")
		reject(t, e.sp, v, "form contains both SAMLRequest and SAMLResponse")
	})
	t.Run("binding field in the URL query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, acs+"?RelayState=evil", strings.NewReader(valid.values(t).Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NilError(t, req.ParseForm())
		_, err := e.sp.ParseResponse(req, []string{spcovRequestID})
		assert.ErrorContains(t, spcovPrivateErr(t, err), "must not carry RelayState in the URL query")
	})

	t.Run("invalid SimpleSign signature with valid XML signatures is rejected", func(t *testing.T) {
		resp := e.response()
		el := resp.Element()
		el.AddChild(e.idpSign(t, e.assertion().Element()))
		signedXML := spcovSerialize(t, e.idpSign(t, el))
		// The XML alone is acceptable over HTTP-POST.
		_, err := e.sp.ParseResponse(simpleSignPost(t, acs, url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(signedXML)}}), []string{spcovRequestID})
		assert.NilError(t, err)

		m := valid
		m.xml = signedXML
		m.key, _ = otherKey(t)
		reject(t, e.sp, m.values(t), "verification error")
	})
	t.Run("valid SimpleSign signature and valid XML signatures", func(t *testing.T) {
		el := e.response().Element()
		el.AddChild(e.idpSign(t, e.assertion().Element()))
		m := valid
		m.xml = spcovSerialize(t, e.idpSign(t, el))
		accept(t, e.sp, m.values(t))
	})
	t.Run("valid SimpleSign signature but invalid Response XML signature", func(t *testing.T) {
		el := e.response().Element()
		el.AddChild(e.assertion().Element())
		signed := e.idpSign(t, el)
		signed.FindElement("./Issuer").SetText("https://idp.example.com/other")
		m := valid
		m.xml = spcovSerialize(t, signed)
		reject(t, e.sp, m.values(t), "cannot validate signature on Response")
	})

	t.Run("Destination is required", func(t *testing.T) {
		m := valid
		m.xml = e.simpleSignResponseXML(t, func(r *Response) { r.Destination = "" })
		reject(t, e.sp, m.values(t), "`Destination` does not match")
	})
	t.Run("wrong Destination", func(t *testing.T) {
		m := valid
		m.xml = e.simpleSignResponseXML(t, func(r *Response) { r.Destination = "https://other.example.com/acs" })
		reject(t, e.sp, m.values(t), "`Destination` does not match")
	})
	t.Run("wrong InResponseTo", func(t *testing.T) {
		m := valid
		m.xml = e.simpleSignResponseXML(t, func(r *Response) { r.InResponseTo = "id-other" })
		reject(t, e.sp, m.values(t), "`InResponseTo` does not match")
	})
	t.Run("wrong Issuer", func(t *testing.T) {
		m := valid
		m.xml = e.simpleSignResponseXML(t, func(r *Response) { r.Issuer = &Issuer{Value: "https://other.example.com"} })
		reject(t, e.sp, m.values(t), "response Issuer does not match")
	})
	t.Run("bad status", func(t *testing.T) {
		m := valid
		m.xml = e.simpleSignResponseXML(t, func(r *Response) { r.Status.StatusCode.Value = StatusRequester })
		_, err := parse(t, e.sp, m.values(t))
		var bs ErrBadStatus
		assert.Assert(t, errors.As(spcovPrivateErr(t, err), &bs))
		assert.Check(t, is.Equal(StatusRequester, bs.Status))
	})
	t.Run("expired assertion", func(t *testing.T) {
		sp := *e.sp
		sp.Clock = dsig.NewFakeClockAt(spcovNow.Add(time.Hour))
		sp.IgnoreCertificateExpiry = true
		m := valid
		reject(t, &sp, m.values(t), "response IssueInstant expired")
	})
	t.Run("encrypted assertion", func(t *testing.T) {
		el := e.response().Element()
		el.AddChild(e.encryptedAssertion(t, spcovSerialize(t, e.assertion().Element())))
		m := valid
		m.xml = spcovSerialize(t, el)
		accept(t, e.sp, m.values(t))
	})
	t.Run("replay cache", func(t *testing.T) {
		sp := *e.sp
		sp.ReplayCache = &recordingReplayCache{seen: map[string]time.Time{}}
		accept(t, &sp, valid.values(t))
		reject(t, &sp, valid.values(t), ErrAssertionReplayed.Error())
	})

	t.Run("certificate expiry is checked with Clock", func(t *testing.T) {
		later := spcovNow.AddDate(30, 0, 0)
		sp := *e.sp
		sp.Clock = dsig.NewFakeClockAt(later)
		m := valid
		m.xml = e.simpleSignResponseXML(t, nil)
		reject(t, &sp, m.values(t), "certificate is not valid at this time")
	})
	t.Run("IDPCertificate", func(t *testing.T) {
		sp := *e.sp
		cert := base64.StdEncoding.EncodeToString(e.idpCert.Raw)
		sp.IDPCertificate = &cert
		sp.IDPMetadata = &EntityDescriptor{EntityID: spcovIDPEntityID}
		accept(t, &sp, valid.values(t))
		_, otherCert := otherKey(t)
		other := base64.StdEncoding.EncodeToString(otherCert.Raw)
		sp.IDPCertificate = &other
		sp.IgnoreCertificateExpiry = true
		reject(t, &sp, valid.values(t), "verification error")
	})
	t.Run("fingerprint", func(t *testing.T) {
		sp := *e.sp
		alg := "http://www.w3.org/2001/04/xmlenc#sha256"
		fp, err := fingerprint(e.idpCert, alg)
		assert.NilError(t, err)
		sp.IDPCertificateFingerprint = &fp
		sp.IDPCertificateFingerprintAlgorithm = &alg
		sp.IDPMetadata = &EntityDescriptor{EntityID: spcovIDPEntityID}

		reject(t, &sp, valid.values(t), "can only verify HTTP-POST-SimpleSign signatures that carry a KeyInfo")

		keyInfo := func(cert []byte) string {
			return base64.StdEncoding.EncodeToString([]byte(`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` +
				base64.StdEncoding.EncodeToString(cert) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`))
		}
		v := valid.values(t)
		v.Set("KeyInfo", keyInfo(e.idpCert.Raw))
		accept(t, &sp, v)

		_, otherCert := otherKey(t)
		v.Set("KeyInfo", keyInfo(otherCert.Raw))
		reject(t, &sp, v, "fingerprint mismatch")

		v.Set("KeyInfo", base64.StdEncoding.EncodeToString([]byte(`<KeyInfo/>`)))
		reject(t, &sp, v, "does not contain a ds:KeyInfo element")
	})
	t.Run("KeyInfo is ignored when certificates are configured", func(t *testing.T) {
		v := valid.values(t)
		v.Set("KeyInfo", "not even base64!")
		accept(t, e.sp, v)
	})
}

// redirectECDSAKeyPair returns a P-256 key and a self-signed certificate for
// it that is valid at spcovNow.
func redirectECDSAKeyPair(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    spcovNow.Add(-time.Hour),
		NotAfter:     spcovNow.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, cert
}

type recordingReplayCache struct {
	seen map[string]time.Time
}

func (c *recordingReplayCache) Consume(id string, expiresAt time.Time) error {
	if _, ok := c.seen[id]; ok {
		return ErrAssertionReplayed
	}
	c.seen[id] = expiresAt
	return nil
}

func TestSimpleSignLogoutValidation(t *testing.T) {
	e := spcovSetup(t)
	slo := e.sp.SloURL.String()

	t.Run("LogoutRequest", func(t *testing.T) {
		valid := simpleSignMsg{param: "SAMLRequest", xml: spcovSerialize(t, e.logoutRequest().Element()), relayState: strPtr("rs"), sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
		req, err := e.sp.ValidateLogoutRequest(simpleSignPost(t, slo, valid.values(t)))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", req.NameID.Value))

		v := valid.values(t)
		v.Set("RelayState", "other")
		_, err = e.sp.ValidateLogoutRequest(simpleSignPost(t, slo, v))
		assert.ErrorContains(t, spcovPrivateErr(t, err), "verification error")

		m := valid
		m.key, _ = otherKey(t)
		_, err = e.sp.ValidateLogoutRequest(simpleSignPost(t, slo, m.values(t)))
		assert.ErrorContains(t, spcovPrivateErr(t, err), "verification error")

		v = valid.values(t)
		v.Add("Signature", "x")
		_, err = e.sp.ValidateLogoutRequest(simpleSignPost(t, slo, v))
		assert.ErrorContains(t, spcovPrivateErr(t, err), "appears more than once")

		// Unsigned HTTP-POST is still rejected.
		_, err = e.sp.ValidateLogoutRequest(simpleSignPost(t, slo, url.Values{"SAMLRequest": {v.Get("SAMLRequest")}}))
		assert.ErrorContains(t, spcovPrivateErr(t, err), "signature element not present")

		// The request fields are still validated.
		bad := e.logoutRequest()
		bad.Destination = "https://other.example.com/slo"
		m = valid
		m.xml = spcovSerialize(t, bad.Element())
		_, err = e.sp.ValidateLogoutRequest(simpleSignPost(t, slo, m.values(t)))
		assert.ErrorContains(t, spcovPrivateErr(t, err), "`Destination` does not match SloURL")
	})

	t.Run("LogoutResponse", func(t *testing.T) {
		valid := simpleSignMsg{param: "SAMLResponse", xml: e.unsignedLogoutResponse(t), sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(simpleSignPost(t, slo, valid.values(t))))

		v := valid.values(t)
		v.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(valid.xml), "id-logout-response", "id-other", 1))))
		assert.ErrorContains(t, spcovPrivateErr(t, e.sp.ValidateLogoutResponseRequest(simpleSignPost(t, slo, v))), "verification error")

		v = valid.values(t)
		v.Del("SigAlg")
		assert.ErrorContains(t, spcovPrivateErr(t, e.sp.ValidateLogoutResponseRequest(simpleSignPost(t, slo, v))), "form must contain both SigAlg and Signature")

		// A valid SimpleSign signature does not excuse an invalid XML one.
		signed := e.idpSign(t, e.logoutResponse().Element())
		signed.FindElement("./Issuer").SetText("https://idp.example.com/other")
		m := valid
		m.xml = spcovSerialize(t, signed)
		assert.ErrorContains(t, spcovPrivateErr(t, e.sp.ValidateLogoutResponseRequest(simpleSignPost(t, slo, m.values(t)))), "cannot validate signature on LogoutResponse")
	})
}

func TestSimpleSignOutgoing(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	e.sp.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices = append(e.sp.IDPMetadata.IDPSSODescriptors[0].SingleSignOnServices,
		Endpoint{Binding: HTTPPostSimpleSignBinding, Location: "https://idp.example.com/sso/simplesign"})
	e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices = append(e.sp.IDPMetadata.IDPSSODescriptors[0].SingleLogoutServices,
		Endpoint{Binding: HTTPPostSimpleSignBinding, Location: "https://idp.example.com/slo/simplesign"})
	verifier := verifierFor(e.sp)
	const relayState = "a b&c=d\"<>"

	check := func(t *testing.T, form []byte, wantAction, param string, wantRelayState bool) *etree.Element {
		t.Helper()
		action, v := formFields(t, form)
		assert.Check(t, is.Equal(wantAction, action))
		_, hasRelayState := v["RelayState"]
		assert.Check(t, is.Equal(wantRelayState, hasRelayState))
		assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, v.Get("SigAlg")))

		req := simpleSignPost(t, action, v)
		m, err := parseSimpleSignRequest(req, param)
		assert.NilError(t, err)
		assert.NilError(t, verifier.verifySimpleSignSignature(m))

		// The XML is sent unsigned and not deflated.
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(m.XML))
		assert.Check(t, is.Nil(doc.Root().FindElement("./Signature")))
		assert.Check(t, is.Equal(wantAction, doc.Root().SelectAttrValue("Destination", "")))
		return doc.Root()
	}

	t.Run("AuthnRequest", func(t *testing.T) {
		form, err := e.sp.MakeSimpleSignAuthenticationRequest(relayState)
		assert.NilError(t, err)
		root := check(t, form, "https://idp.example.com/sso/simplesign", "SAMLRequest", true)
		assert.Check(t, is.Equal("AuthnRequest", root.Tag))
		_, v := formFields(t, form)
		assert.Check(t, is.Equal(relayState, v.Get("RelayState")))
	})
	t.Run("AuthnRequest without relay state", func(t *testing.T) {
		form, err := e.sp.MakeSimpleSignAuthenticationRequest("")
		assert.NilError(t, err)
		check(t, form, "https://idp.example.com/sso/simplesign", "SAMLRequest", false)
	})
	t.Run("AuthnRequest form script matches the HTTP-POST form", func(t *testing.T) {
		req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/simplesign", HTTPPostSimpleSignBinding, HTTPPostBinding)
		assert.NilError(t, err)
		form, err := req.SimpleSignWithNonce(relayState, "n0nce", e.sp)
		assert.NilError(t, err)
		post := req.PostWithNonce(relayState, "n0nce")
		script := func(b []byte) string { return string(b[strings.Index(string(b), "<script"):]) }
		assert.Equal(t, script(form), script(post))
		assert.Check(t, strings.Contains(string(form), `<script nonce="n0nce">`))
	})
	t.Run("LogoutRequest", func(t *testing.T) {
		form, err := e.sp.MakeSimpleSignLogoutRequest("alice", relayState, WithSessionIndex("s1"))
		assert.NilError(t, err)
		root := check(t, form, "https://idp.example.com/slo/simplesign", "SAMLRequest", true)
		assert.Check(t, is.Equal("LogoutRequest", root.Tag))
	})
	t.Run("LogoutResponse", func(t *testing.T) {
		form, err := e.sp.MakeSimpleSignLogoutResponse("id-req", relayState)
		assert.NilError(t, err)
		root := check(t, form, "https://idp.example.com/slo/simplesign", "SAMLResponse", true)
		assert.Check(t, is.Equal("LogoutResponse", root.Tag))
		resp, err := e.sp.MakeLogoutResponse("https://idp.example.com/slo/simplesign", "id-req")
		assert.NilError(t, err)
		form, err = resp.SimpleSignWithNonce("", "n0nce", e.sp)
		assert.NilError(t, err)
		post := resp.PostWithNonce("", "n0nce")
		script := func(b []byte) string { return string(b[strings.Index(string(b), "<script"):]) }
		assert.Equal(t, script(form), script(post))
	})
	t.Run("ECDSA", func(t *testing.T) {
		key, cert := redirectECDSAKeyPair(t)
		sp := *e.sp
		sp.Key, sp.Certificate = key, cert
		sp.SignatureMethod = dsig.ECDSASHA256SignatureMethod
		form, err := sp.MakeSimpleSignLogoutRequest("alice", relayState)
		assert.NilError(t, err)
		action, v := formFields(t, form)
		assert.Check(t, is.Equal(dsig.ECDSASHA256SignatureMethod, v.Get("SigAlg")))
		m, err := parseSimpleSignRequest(simpleSignPost(t, action, v), "SAMLRequest")
		assert.NilError(t, err)
		assert.NilError(t, verifierFor(&sp).verifySimpleSignSignature(m))
	})
	t.Run("requires SignatureMethod", func(t *testing.T) {
		sp := *e.sp
		sp.SignatureMethod = ""
		_, err := sp.MakeSimpleSignAuthenticationRequest(relayState)
		assert.ErrorContains(t, err, "requires ServiceProvider.SignatureMethod")
		_, err = sp.MakeSimpleSignLogoutRequest("alice", relayState)
		assert.ErrorContains(t, err, "requires ServiceProvider.SignatureMethod")
		_, err = sp.MakeSimpleSignLogoutResponse("id", relayState)
		assert.ErrorContains(t, err, "requires ServiceProvider.SignatureMethod")
	})
	t.Run("requires a key", func(t *testing.T) {
		sp := *e.sp
		sp.Key = nil
		_, err := sp.MakeSimpleSignAuthenticationRequest(relayState)
		assert.ErrorContains(t, err, "requires a non-nil private key")
	})
	t.Run("GetSSOBindingLocation", func(t *testing.T) {
		assert.Equal(t, e.sp.GetSSOBindingLocation(HTTPPostSimpleSignBinding), "https://idp.example.com/sso/simplesign")
		assert.Equal(t, e.sp.GetSLOBindingLocation(HTTPPostSimpleSignBinding), "https://idp.example.com/slo/simplesign")
	})
}

func TestSimpleSignSPMetadata(t *testing.T) {
	e := spcovSetup(t)
	e.sp.AssertionConsumerServiceBindings = []string{HTTPPostSimpleSignBinding, HTTPPostBinding}
	e.sp.LogoutBindings = []string{HTTPPostSimpleSignBinding}
	md := e.sp.Metadata()
	acs := md.SPSSODescriptors[0].AssertionConsumerServices
	assert.Assert(t, is.Len(acs, 2))
	assert.Check(t, is.Equal(HTTPPostSimpleSignBinding, acs[0].Binding))
	assert.Check(t, is.Equal(e.sp.AcsURL.String(), acs[0].Location))
	assert.Check(t, is.Equal(HTTPPostSimpleSignBinding, md.SPSSODescriptors[0].SingleLogoutServices[0].Binding))
}
