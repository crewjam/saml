package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// redirectQuery builds an HTTP-Redirect binding query the way an IDP would:
// SAMLx=...&RelayState=...&SigAlg=..., signed with key using sigAlg, then
// &Signature=... appended. escape is used to URL-encode each value so tests
// can mimic senders that encode differently from Go (e.g. ADFS).
type redirectQuery struct {
	param      string
	xml        []byte
	relayState string
	sigAlg     string
	key        crypto.Signer
	escape     func(string) string
}

func (q redirectQuery) build(t *testing.T) string {
	t.Helper()
	escape := q.escape
	if escape == nil {
		escape = url.QueryEscape
	}
	raw := q.param + "=" + escape(base64.StdEncoding.EncodeToString(spcovDeflate(t, q.xml)))
	if q.relayState != "" {
		raw += "&RelayState=" + escape(q.relayState)
	}
	if q.sigAlg == "" {
		return raw
	}
	raw += "&SigAlg=" + escape(q.sigAlg)
	sig := redirectSign(t, q.key, q.sigAlg, raw)
	return raw + "&Signature=" + escape(base64.StdEncoding.EncodeToString(sig))
}

func redirectSign(t *testing.T, key crypto.Signer, sigAlg, content string) []byte {
	t.Helper()
	ctx, err := dsig.NewSigningContext(key, nil)
	assert.NilError(t, err)
	assert.NilError(t, ctx.SetSignatureMethod(sigAlg))
	sig, err := ctx.SignString(content)
	assert.NilError(t, err)
	return sig
}

// lowerCaseEscape URL-encodes s with lower case hex digits, as ADFS does.
func lowerCaseEscape(s string) string {
	escaped := url.QueryEscape(s)
	var b strings.Builder
	for i := 0; i < len(escaped); i++ {
		if escaped[i] == '%' && i+2 < len(escaped) {
			b.WriteByte('%')
			b.WriteString(strings.ToLower(escaped[i+1 : i+3]))
			i += 2
			continue
		}
		b.WriteByte(escaped[i])
	}
	return b.String()
}

func (e *spcovEnv) unsignedLogoutResponse(t *testing.T) []byte {
	return spcovSerialize(t, e.logoutResponse().Element())
}

func (e *spcovEnv) logoutRequest() *LogoutRequest {
	return &LogoutRequest{
		ID:           "id-idp-logout-request",
		Version:      "2.0",
		IssueInstant: spcovNow,
		Destination:  e.sp.SloURL.String(),
		Issuer:       &Issuer{Value: spcovIDPEntityID},
		NameID:       &NameID{Value: "alice@example.com"},
	}
}

func redirectRequest(sp *ServiceProvider, rawQuery string) *http.Request {
	return httptest.NewRequest(http.MethodGet, sp.SloURL.String()+"?"+rawQuery, nil)
}

func TestRedirectBindingLogoutResponseSignature(t *testing.T) {
	e := spcovSetup(t)
	unsigned := e.unsignedLogoutResponse(t)
	valid := redirectQuery{param: "SAMLResponse", xml: unsigned, sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}

	t.Run("valid query signature", func(t *testing.T) {
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, valid.build(t))))
	})

	// The IDP certificate is itself signed with sha1WithRSA; the algorithm
	// used to sign the certificate must not restrict SigAlg.
	for _, alg := range []string{
		dsig.RSASHA1SignatureMethod, dsig.RSASHA256SignatureMethod,
		dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod,
	} {
		t.Run("algorithm "+alg, func(t *testing.T) {
			q := valid
			q.sigAlg = alg
			assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t))))
		})
	}

	t.Run("with relay state", func(t *testing.T) {
		q := valid
		q.relayState = "a b&c=d/é"
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t))))
	})

	t.Run("lower case percent encoding", func(t *testing.T) {
		q := valid
		q.relayState = "https://sp.example.com/after?x=1"
		q.escape = lowerCaseEscape
		raw := q.build(t)
		assert.Assert(t, strings.Contains(raw, "%3a%2f%2f"), raw)
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw)))
	})

	t.Run("unsigned is rejected", func(t *testing.T) {
		q := valid
		q.sigAlg = ""
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t)))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "signature element not present"))
	})

	t.Run("SigAlg without Signature is rejected", func(t *testing.T) {
		raw := valid.build(t)
		raw, _, _ = strings.Cut(raw, "&Signature=")
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Error(t, spcovPrivateErr(t, err), "query must contain both SigAlg and Signature, or neither")
	})

	t.Run("Signature without SigAlg is rejected", func(t *testing.T) {
		raw := valid.build(t)
		sigAlg := "&SigAlg=" + url.QueryEscape(valid.sigAlg)
		raw = strings.Replace(raw, sigAlg, "", 1)
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Error(t, spcovPrivateErr(t, err), "query must contain both SigAlg and Signature, or neither")
	})

	t.Run("tampered message is rejected", func(t *testing.T) {
		forged := e.logoutResponse()
		forged.InResponseTo = "id-forged"
		raw := valid.build(t)
		_, rest, _ := strings.Cut(raw, "&")
		raw = "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString(spcovDeflate(t, spcovSerialize(t, forged.Element())))) + "&" + rest
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "verification error"))
	})

	t.Run("tampered relay state is rejected", func(t *testing.T) {
		q := valid
		q.relayState = "original"
		raw := strings.Replace(q.build(t), "RelayState=original", "RelayState=changed", 1)
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "verification error"))
	})

	t.Run("signed message smuggled in another parameter is rejected", func(t *testing.T) {
		// A signed message is moved to a parameter whose name merely ends in
		// SAMLResponse, and a forged message is placed in SAMLResponse.
		forged := e.logoutResponse()
		forged.InResponseTo = "id-forged"
		forgedValue := url.QueryEscape(base64.StdEncoding.EncodeToString(spcovDeflate(t, spcovSerialize(t, forged.Element()))))
		raw := "x" + valid.build(t)
		raw = strings.Replace(raw, "&SigAlg=", "&SAMLResponse="+forgedValue+"&SigAlg=", 1)
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "verification error"))
	})

	for _, param := range []string{"SAMLResponse", "RelayState", "SigAlg", "Signature"} {
		t.Run("duplicate "+param+" is rejected", func(t *testing.T) {
			q := valid
			q.relayState = "state"
			raw := q.build(t) + "&" + param + "=other"
			err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
			assert.Error(t, spcovPrivateErr(t, err), "query parameter "+param+" appears more than once")
		})
	}

	t.Run("SAMLRequest and SAMLResponse together are rejected", func(t *testing.T) {
		raw := valid.build(t) + "&SAMLRequest=x"
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Error(t, spcovPrivateErr(t, err), "query contains both SAMLRequest and SAMLResponse")
	})

	t.Run("unsupported algorithm is rejected", func(t *testing.T) {
		raw := strings.Replace(valid.build(t), url.QueryEscape(dsig.RSASHA256SignatureMethod), url.QueryEscape("http://www.w3.org/2001/04/xmldsig-more#rsa-md5"), 1)
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Error(t, spcovPrivateErr(t, err), `unsupported signature algorithm "http://www.w3.org/2001/04/xmldsig-more#rsa-md5"`)
	})

	t.Run("SigAlg not matching the key type is rejected", func(t *testing.T) {
		raw := strings.Replace(valid.build(t), url.QueryEscape(dsig.RSASHA256SignatureMethod), url.QueryEscape(dsig.ECDSASHA256SignatureMethod), 1)
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature"))
	})

	t.Run("signature by another key is rejected", func(t *testing.T) {
		// The SP and IDP test fixtures share a key, so use a fresh one.
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NilError(t, err)
		q := valid
		q.key = otherKey
		err = e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t)))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "verification error"))
	})

	t.Run("bad signature encoding is rejected", func(t *testing.T) {
		raw := valid.build(t)
		raw, _, _ = strings.Cut(raw, "&Signature=")
		raw += "&Signature=%21%21"
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot decode signature"))
	})

	t.Run("expired certificate is rejected", func(t *testing.T) {
		Clock = dsig.NewFakeClockAt(spcovNow.AddDate(2, 0, 0))
		defer func() { Clock = dsig.NewFakeClockAt(spcovNow) }()
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, valid.build(t)))
		assert.Error(t, spcovPrivateErr(t, err), "cannot validate signature: certificate is not valid at this time")
	})

	t.Run("expired certificate is accepted with IgnoreCertificateExpiry", func(t *testing.T) {
		Clock = dsig.NewFakeClockAt(spcovNow.AddDate(2, 0, 0))
		defer func() { Clock = dsig.NewFakeClockAt(spcovNow) }()
		sp := *e.sp
		sp.IgnoreCertificateExpiry = true
		assert.NilError(t, sp.ValidateLogoutResponseRequest(redirectRequest(&sp, valid.build(t))))

		q := valid
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.NilError(t, err)
		q.key = otherKey
		err = sp.ValidateLogoutResponseRequest(redirectRequest(&sp, q.build(t)))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "verification error"))
	})

	t.Run("explicit IDP certificate", func(t *testing.T) {
		sp := *e.sp
		certStr := base64.StdEncoding.EncodeToString(e.idpCert.Raw)
		sp.IDPCertificate = &certStr
		sp.IDPMetadata = &EntityDescriptor{EntityID: spcovIDPEntityID}
		assert.NilError(t, sp.ValidateLogoutResponseRequest(redirectRequest(&sp, valid.build(t))))
	})

	t.Run("fingerprint-only configuration is rejected", func(t *testing.T) {
		sp := *e.sp
		fp, alg := "00", "sha256"
		sp.IDPCertificateFingerprint, sp.IDPCertificateFingerprintAlgorithm = &fp, &alg
		err := sp.ValidateLogoutResponseRequest(redirectRequest(&sp, valid.build(t)))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "fingerprints cannot be used"))
	})

	t.Run("enveloped XML signature is still accepted", func(t *testing.T) {
		q := redirectQuery{param: "SAMLResponse", xml: e.signedLogoutResponse(t, nil)}
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t))))
	})

	t.Run("message content is still validated", func(t *testing.T) {
		lr := e.logoutResponse()
		lr.Destination = "https://evil.example.com/slo"
		q := valid
		q.xml = spcovSerialize(t, lr.Element())
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t)))
		assert.Error(t, spcovPrivateErr(t, err), "`Destination` does not match SloURL (expected \"https://sp.example.com/saml/slo\")")
	})
}

func TestRedirectBindingECDSASignature(t *testing.T) {
	e := spcovSetup(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "idp.example.com"},
		NotBefore:    spcovNow.Add(-time.Hour),
		NotAfter:     spcovNow.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	e.sp.IDPMetadata = spcovIDPMetadata(cert)

	for _, alg := range []string{dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA512SignatureMethod} {
		t.Run(alg, func(t *testing.T) {
			q := redirectQuery{param: "SAMLResponse", xml: e.unsignedLogoutResponse(t), sigAlg: alg, key: key}
			assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, q.build(t))))
		})
	}

	t.Run("RSA SigAlg with an ECDSA certificate is rejected", func(t *testing.T) {
		q := redirectQuery{param: "SAMLResponse", xml: e.unsignedLogoutResponse(t), sigAlg: dsig.ECDSASHA256SignatureMethod, key: key}
		raw := strings.Replace(q.build(t), url.QueryEscape(dsig.ECDSASHA256SignatureMethod), url.QueryEscape(dsig.RSASHA256SignatureMethod), 1)
		err := e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, raw))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature"))
	})
}

func TestValidateLogoutRequest(t *testing.T) {
	e := spcovSetup(t)
	unsigned := spcovSerialize(t, e.logoutRequest().Element())
	valid := redirectQuery{param: "SAMLRequest", xml: unsigned, relayState: "state", sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}

	t.Run("redirect binding", func(t *testing.T) {
		req, err := e.sp.ValidateLogoutRequest(redirectRequest(e.sp, valid.build(t)))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("id-idp-logout-request", req.ID))
		assert.Check(t, is.Equal("alice@example.com", req.NameID.Value))
	})

	t.Run("redirect binding unsigned", func(t *testing.T) {
		q := valid
		q.sigAlg = ""
		req, err := e.sp.ValidateLogoutRequest(redirectRequest(e.sp, q.build(t)))
		assert.Check(t, is.Nil(req))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "signature element not present"))
	})

	t.Run("redirect binding with SAMLResponse is rejected", func(t *testing.T) {
		req, err := e.sp.ValidateLogoutRequest(redirectRequest(e.sp, valid.build(t)+"&SAMLResponse=x"))
		assert.Check(t, is.Nil(req))
		assert.Error(t, spcovPrivateErr(t, err), "query contains both SAMLRequest and SAMLResponse")
	})

	postRequest := func(buf []byte) *http.Request {
		form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)}}
		r := httptest.NewRequest(http.MethodPost, e.sp.SloURL.String(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}

	t.Run("post binding", func(t *testing.T) {
		signed := spcovSerialize(t, e.idpSign(t, e.logoutRequest().Element()))
		req, err := e.sp.ValidateLogoutRequest(postRequest(signed))
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", req.NameID.Value))
	})

	t.Run("post binding unsigned", func(t *testing.T) {
		req, err := e.sp.ValidateLogoutRequest(postRequest(unsigned))
		assert.Check(t, is.Nil(req))
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "signature element not present"))
	})

	t.Run("post binding bad base64", func(t *testing.T) {
		req, err := e.sp.ValidateLogoutRequestForm("!!!")
		assert.Check(t, is.Nil(req))
		assert.Error(t, spcovPrivateErr(t, err), "unable to parse base64: illegal base64 data at input byte 0")
	})

	t.Run("unparsable form", func(t *testing.T) {
		req, err := e.sp.ValidateLogoutRequest(httptest.NewRequest(http.MethodPost, e.sp.SloURL.String()+"?a=%zz", nil))
		assert.Check(t, is.Nil(req))
		assert.Error(t, spcovPrivateErr(t, err), `unable to parse form: invalid URL escape "%zz"`)
	})

	future := spcovNow.Add(time.Hour)
	past := spcovNow.Add(-time.Hour)
	tests := []struct {
		name    string
		mutate  func(r *LogoutRequest)
		wantErr string
	}{
		{"wrong destination", func(r *LogoutRequest) { r.Destination = "https://evil.example.com/slo" },
			"`Destination` does not match SloURL (expected \"https://sp.example.com/saml/slo\")"},
		{"expired", func(r *LogoutRequest) { r.IssueInstant = past },
			"issueInstant expired at " + past.Add(MaxIssueDelay).String()},
		{"issued in the future", func(r *LogoutRequest) { r.IssueInstant = future },
			"issueInstant " + future.String() + " is in the future"},
		{"past NotOnOrAfter", func(r *LogoutRequest) { r.NotOnOrAfter = &past },
			"request expired at " + past.String()},
		{"missing issuer", func(r *LogoutRequest) { r.Issuer = nil },
			"issuer does not match the IDP metadata (expected \"https://idp.example.com/metadata\")"},
		{"wrong issuer", func(r *LogoutRequest) { r.Issuer.Value = "https://evil.example.com" },
			"issuer does not match the IDP metadata (expected \"https://idp.example.com/metadata\")"},
		{"missing NameID", func(r *LogoutRequest) { r.NameID = nil },
			"request does not contain a NameID"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lr := e.logoutRequest()
			tc.mutate(lr)
			q := valid
			q.xml = spcovSerialize(t, lr.Element())
			req, err := e.sp.ValidateLogoutRequest(redirectRequest(e.sp, q.build(t)))
			assert.Check(t, is.Nil(req))
			assert.Error(t, spcovPrivateErr(t, err), tc.wantErr)
		})
	}
}

// verifierFor returns a ServiceProvider that trusts sp's certificate as the
// IDP signing certificate, to check what sp sends.
func verifierFor(sp *ServiceProvider) *ServiceProvider {
	return &ServiceProvider{IDPMetadata: spcovIDPMetadata(sp.Certificate)}
}

func TestRedirectBindingOutgoingSignature(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	verifier := verifierFor(e.sp)
	const relayState = "a b&c=d"

	check := func(t *testing.T, u *url.URL, param string) {
		t.Helper()
		assert.Check(t, is.Equal(relayState, u.Query().Get("RelayState")))
		m, err := parseRedirectBindingQuery(u.RawQuery, param)
		assert.NilError(t, err)
		assert.Assert(t, m.SignedContent != nil)
		assert.Check(t, !strings.Contains(string(m.SignedContent), "tenant="), string(m.SignedContent))
		assert.NilError(t, verifier.verifyRedirectBindingSignature(m))

		// The binding requires the XML signature to be removed.
		buf, err := base64.StdEncoding.DecodeString(m.Message)
		assert.NilError(t, err)
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(spcovInflate(t, buf)))
		assert.Check(t, is.Nil(doc.Root().FindElement("./Signature")))
	}

	t.Run("AuthnRequest", func(t *testing.T) {
		req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso?tenant=a", HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		u, err := req.Redirect(relayState, e.sp)
		assert.NilError(t, err)
		assert.Check(t, strings.HasPrefix(u.RawQuery, "tenant=a&SAMLRequest="), u.RawQuery)
		check(t, u, "SAMLRequest")
	})

	t.Run("LogoutRequest", func(t *testing.T) {
		u, err := e.sp.MakeRedirectLogoutRequest("alice", relayState)
		assert.NilError(t, err)
		check(t, u, "SAMLRequest")
	})

	t.Run("LogoutRequest from MakeLogoutRequest", func(t *testing.T) {
		// MakeLogoutRequest adds an enveloped signature, which
		// RedirectLogoutRequestURL must leave out.
		req, err := e.sp.MakeLogoutRequest("https://idp.example.com/slo/redirect", "alice")
		assert.NilError(t, err)
		assert.Assert(t, req.Signature != nil)
		u, err := e.sp.RedirectLogoutRequestURL(req, relayState)
		assert.NilError(t, err)
		assert.Check(t, req.Signature != nil, "req must not be modified")
		check(t, u, "SAMLRequest")

		buf, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
		assert.NilError(t, err)
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(spcovInflate(t, buf)))
		assert.Check(t, is.Equal(req.ID, doc.Root().SelectAttrValue("ID", "")))
	})

	t.Run("LogoutResponse", func(t *testing.T) {
		u, err := e.sp.MakeRedirectLogoutResponse("id-req", relayState)
		assert.NilError(t, err)
		check(t, u, "SAMLResponse")
	})

	t.Run("unsigned when no SignatureMethod", func(t *testing.T) {
		sp := *e.sp
		sp.SignatureMethod = ""
		u, err := sp.MakeRedirectLogoutRequest("alice", relayState)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("", u.Query().Get("SigAlg")))
		assert.Check(t, is.Equal("", u.Query().Get("Signature")))
	})
}

func spcovInflate(t *testing.T, buf []byte) []byte {
	t.Helper()
	rv, err := io.ReadAll(newSaferFlateReader(strings.NewReader(string(buf))))
	assert.NilError(t, err)
	return rv
}
