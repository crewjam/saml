package saml

import (
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// signWithMethod returns el with an enveloped signature made by key with
// signatureMethod (which also sets the digest method), embedding cert.
func signWithMethod(t *testing.T, key crypto.Signer, cert *x509.Certificate, el *etree.Element, signatureMethod string) *etree.Element {
	t.Helper()
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	assert.NilError(t, err)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	assert.NilError(t, ctx.SetSignatureMethod(signatureMethod))
	signed, err := ctx.SignEnveloped(el)
	assert.NilError(t, err)
	return signed
}

// withSHA1Digest changes the DigestMethod of the enveloped signature of el
// to SHA-1, leaving the SignatureMethod alone. The signature no longer
// verifies, but the policy must reject it before verification is tried.
func withSHA1Digest(el *etree.Element) *etree.Element {
	el.FindElement("./Signature/SignedInfo/Reference/DigestMethod").CreateAttr("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
	return el
}

func TestSPRejectSHA1XMLSignatures(t *testing.T) {
	e := spcovSetup(t)
	parse := func(t *testing.T, signatureMethod string, mutate func(*etree.Element) *etree.Element) error {
		assertionEl := signWithMethod(t, e.idpKey, e.idpCert, e.assertion().Element(), signatureMethod)
		if mutate != nil {
			assertionEl = mutate(assertionEl)
		}
		responseEl := e.response().Element()
		responseEl.AddChild(assertionEl)
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, responseEl), []string{spcovRequestID}, e.sp.AcsURL)
		return err
	}

	t.Run("SHA-1 is accepted by default", func(t *testing.T) {
		e.sp.RejectSHA1Signatures = false
		assert.NilError(t, parse(t, dsig.RSASHA1SignatureMethod, nil))
	})
	t.Run("SHA-256 is accepted with the policy", func(t *testing.T) {
		e.sp.RejectSHA1Signatures = true
		assert.NilError(t, parse(t, dsig.RSASHA256SignatureMethod, nil))
	})
	t.Run("rsa-sha1 is rejected with the policy", func(t *testing.T) {
		e.sp.RejectSHA1Signatures = true
		err := spcovPrivateErr(t, parse(t, dsig.RSASHA1SignatureMethod, nil))
		assert.Check(t, is.ErrorIs(err, ErrUnsupported))
		assert.Check(t, is.ErrorIs(err, ErrInvalidSignature))
		assert.Check(t, is.ErrorContains(err, "SHA-1"))
	})
	t.Run("a SHA-1 digest is rejected with the policy", func(t *testing.T) {
		e.sp.RejectSHA1Signatures = true
		err := spcovPrivateErr(t, parse(t, dsig.RSASHA256SignatureMethod, withSHA1Digest))
		assert.Check(t, is.ErrorIs(err, ErrUnsupported))
		assert.Check(t, is.ErrorContains(err, "DigestMethod"))
	})
	t.Run("the policy also applies with a SignatureVerifier", func(t *testing.T) {
		e.sp.RejectSHA1Signatures = true
		verifier := &spcovVerifier{}
		e.sp.SignatureVerifier = verifier
		t.Cleanup(func() { e.sp.SignatureVerifier = nil })
		err := spcovPrivateErr(t, parse(t, dsig.RSASHA1SignatureMethod, nil))
		assert.Check(t, is.ErrorIs(err, ErrUnsupported))
	})
}

func TestSPRejectSHA1DetachedSignatures(t *testing.T) {
	e := spcovSetup(t)
	unsigned := e.unsignedLogoutResponse(t)
	slo := e.sp.SloURL.String()

	for _, tc := range []struct {
		name    string
		request func(t *testing.T, sigAlg string) *http.Request
	}{
		{"redirect", func(t *testing.T, sigAlg string) *http.Request {
			q := redirectQuery{param: "SAMLResponse", xml: unsigned, sigAlg: sigAlg, key: e.idpKey}
			return redirectRequest(e.sp, q.build(t))
		}},
		{"simplesign", func(t *testing.T, sigAlg string) *http.Request {
			m := simpleSignMsg{param: "SAMLResponse", xml: unsigned, sigAlg: sigAlg, key: e.idpKey}
			return simpleSignPost(t, slo, m.values(t))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.sp.RejectSHA1Signatures = false
			assert.NilError(t, e.sp.ValidateLogoutResponseRequest(tc.request(t, dsig.RSASHA1SignatureMethod)))

			e.sp.RejectSHA1Signatures = true
			assert.NilError(t, e.sp.ValidateLogoutResponseRequest(tc.request(t, dsig.RSASHA256SignatureMethod)))
			err := spcovPrivateErr(t, e.sp.ValidateLogoutResponseRequest(tc.request(t, dsig.RSASHA1SignatureMethod)))
			assert.Check(t, is.ErrorIs(err, ErrUnsupported))
			assert.Check(t, is.ErrorContains(err, dsig.RSASHA1SignatureMethod))
		})
	}
}

func TestIDPRejectSHA1LogoutRequestSignatures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request func(t *testing.T, test *sloTest) *http.Request
	}{
		{"redirect", func(t *testing.T, test *sloTest) *http.Request {
			return test.redirectRequest(t, test.logoutRequest())
		}},
		{"post", func(t *testing.T, test *sloTest) *http.Request {
			return test.signedPostRequest(t, test.logoutRequest())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct {
				signatureMethod string
				reject          bool
				wantOK          bool
			}{
				{dsig.RSASHA1SignatureMethod, false, true},
				{dsig.RSASHA1SignatureMethod, true, false},
				{dsig.RSASHA256SignatureMethod, true, true},
			} {
				test := newSLOTest(t)
				test.SP.SignatureMethod = c.signatureMethod
				test.IDP.RejectSHA1Signatures = c.reject
				r := tc.request(t, test)

				req, err := NewIdpLogoutRequest(&test.IDP, r)
				assert.NilError(t, err)
				err = req.Validate()
				if c.wantOK {
					assert.Check(t, err, "%s reject=%v", c.signatureMethod, c.reject)
				} else {
					assert.Check(t, errors.Is(err, ErrUnsupported), "%s reject=%v: %v", c.signatureMethod, c.reject, err)
					assert.Check(t, is.Equal(http.StatusBadRequest, test.serve(tc.request(t, test)).Code))
					assert.Check(t, is.Equal(0, test.sessions.calls))
				}
			}
		})
	}

	t.Run("post with a SHA-1 digest", func(t *testing.T) {
		test := newSLOTest(t)
		test.IDP.RejectSHA1Signatures = true
		logoutRequest := test.logoutRequest()
		assert.NilError(t, test.SP.SignLogoutRequest(logoutRequest))
		el := withSHA1Digest(logoutRequest.Element())
		req, err := NewIdpLogoutRequest(&test.IDP, postRequestBytes(test.IDP.LogoutURL.String(), spcovSerialize(t, el)))
		assert.NilError(t, err)
		err = req.Validate()
		assert.Check(t, errors.Is(err, ErrUnsupported), "%v", err)
	})
}

func TestIDPRejectSHA1SimpleSignAuthnRequest(t *testing.T) {
	for _, c := range []struct {
		signatureMethod string
		reject          bool
		wantOK          bool
	}{
		{dsig.RSASHA1SignatureMethod, false, true},
		{dsig.RSASHA1SignatureMethod, true, false},
		{dsig.RSASHA256SignatureMethod, true, true},
	} {
		test := newSimpleSignIDPTest(t)
		test.SP.SignatureMethod = c.signatureMethod
		test.IDP.RejectSHA1Signatures = c.reject
		form, err := test.SP.MakeSimpleSignAuthenticationRequest("")
		assert.NilError(t, err)

		req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, form))
		assert.NilError(t, err)
		err = req.Validate()
		if c.wantOK {
			assert.Check(t, err, "%s reject=%v", c.signatureMethod, c.reject)
			continue
		}
		assert.Check(t, errors.Is(err, ErrUnsupported), "%s reject=%v: %v", c.signatureMethod, c.reject, err)

		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, postForm(t, form))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	}
}

func TestCheckXMLSignatureNotSHA1(t *testing.T) {
	sig := func(signatureMethod, digestMethod string) *etree.Element {
		el := etree.NewElement("ds:Signature")
		signedInfo := el.CreateElement("ds:SignedInfo")
		signedInfo.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", signatureMethod)
		signedInfo.CreateElement("ds:Reference").CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestMethod)
		return el
	}
	const sha1Digest = "http://www.w3.org/2000/09/xmldsig#sha1"
	const sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256"

	assert.Check(t, checkXMLSignatureNotSHA1(false, sig(dsig.RSASHA1SignatureMethod, sha1Digest)))
	assert.Check(t, checkXMLSignatureNotSHA1(true, nil))
	assert.Check(t, checkXMLSignatureNotSHA1(true, sig(dsig.RSASHA256SignatureMethod, sha256Digest)))
	assert.Check(t, checkXMLSignatureNotSHA1(true, sig(dsig.ECDSASHA512SignatureMethod, sha256Digest)))
	for _, s := range []*etree.Element{
		sig(dsig.RSASHA1SignatureMethod, sha256Digest),
		sig(dsig.ECDSASHA1SignatureMethod, sha256Digest),
		sig("http://www.w3.org/2000/09/xmldsig#dsa-sha1", sha256Digest),
		sig("http://www.w3.org/2000/09/xmldsig#hmac-sha1", sha256Digest),
		sig(dsig.RSASHA256SignatureMethod, sha1Digest),
	} {
		assert.Check(t, is.ErrorIs(checkXMLSignatureNotSHA1(true, s), ErrUnsupported))
	}

	// A second Reference with a SHA-1 digest is found too.
	s := sig(dsig.RSASHA256SignatureMethod, sha256Digest)
	s.FindElement("./SignedInfo").CreateElement("ds:Reference").CreateElement("ds:DigestMethod").CreateAttr("Algorithm", sha1Digest)
	assert.Check(t, is.ErrorIs(checkXMLSignatureNotSHA1(true, s), ErrUnsupported))

	assert.Check(t, checkSigAlgNotSHA1(false, dsig.RSASHA1SignatureMethod))
	assert.Check(t, checkSigAlgNotSHA1(true, dsig.RSASHA256SignatureMethod))
	assert.Check(t, is.ErrorIs(checkSigAlgNotSHA1(true, dsig.ECDSASHA1SignatureMethod), ErrUnsupported))
}
