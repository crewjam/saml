package saml

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
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
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/logger"
)

// signedResponse returns a Response (signed by the IDP) containing an unsigned assertion.
func (e *spcovEnv) signedResponse(t *testing.T) []byte {
	t.Helper()
	r := e.response()
	r.Assertion = e.assertion()
	return spcovSerialize(t, e.idpSign(t, r.Element()))
}

func TestSpcovParseXMLResponseHappyPath(t *testing.T) {
	e := spcovSetup(t)
	assertion, err := e.sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Equal(t, "alice@example.com", assertion.Subject.NameID.Value)
}

func TestSpcovParseXMLResponseErrors(t *testing.T) {
	e := spcovSetup(t)

	t.Run("etree rejects document", func(t *testing.T) {
		_, err := e.sp.ParseXMLResponse([]byte("<a>"), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err), "etree: invalid XML format")
	})

	t.Run("signed response without assertions", func(t *testing.T) {
		buf := spcovSerialize(t, e.idpSign(t, e.response().Element()))
		_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err), "expected at least one valid Assertion, none found")
	})

	t.Run("signed by an untrusted key", func(t *testing.T) {
		otherKey := mustParsePrivateKey(golden.Get(t, "key_2017.pem"))
		otherCert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
		r := e.response()
		r.Assertion = e.assertion()
		buf := spcovSerialize(t, spcovSign(t, otherKey, otherCert, r.Element()))
		_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err),
			"cannot validate signature on Response: Could not verify certificate against trusted certs")
		// matched through the *InvalidResponseError, not just PrivateErr
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
		assert.Check(t, errors.Is(err, ErrUntrustedCertificate))
		assert.Check(t, !errors.Is(err, ErrCertificateNotValidNow))
	})

	t.Run("response tampered after signing", func(t *testing.T) {
		buf := e.signedResponse(t)
		buf = bytes.Replace(buf, []byte("alice@example.com"), []byte("admin@example.com"), 1)
		_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err), "cannot validate signature on Response: Signature could not be verified")
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
		assert.Check(t, !errors.Is(err, ErrUntrustedCertificate))
		assert.Check(t, !errors.Is(err, ErrCertificateNotValidNow))
	})

	t.Run("unsigned response with unsigned assertion", func(t *testing.T) {
		r := e.response()
		r.Assertion = e.assertion()
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, r.Element()), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err), "signature element not present")
	})

	t.Run("unsigned response with signed assertion", func(t *testing.T) {
		r := e.response()
		el := r.Element()
		el.AddChild(e.idpSign(t, e.assertion().Element()))
		assertion, err := e.sp.ParseXMLResponse(spcovSerialize(t, el), []string{spcovRequestID}, e.sp.AcsURL)
		assert.NilError(t, err)
		assert.Equal(t, "id-assertion", assertion.ID)
	})

	t.Run("signed assertion fails to unmarshal", func(t *testing.T) {
		el := e.response().Element()
		assertionEl := e.assertion().Element()
		assertionEl.CreateAttr("IssueInstant", "not-a-time")
		el.AddChild(e.idpSign(t, assertionEl))
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, el), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err), "cannot unmarshal response: parsing time \"not-a-time\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"not-a-time\" as \"2006\"")
	})
}

func TestSpcovParseResponseFindChildrenErrors(t *testing.T) {
	e := spcovSetup(t)
	for _, tag := range []string{"EncryptedAssertion", "Assertion"} {
		t.Run(tag, func(t *testing.T) {
			el := e.response().Element()
			el.CreateElement("undeclared:" + tag)
			_, err := e.sp.parseResponse(el, []string{spcovRequestID}, spcovNow, signatureNotRequired, e.sp.AcsURL)
			assert.Error(t, err, "[urn:oasis:names:tc:SAML:2.0:assertion]:"+tag+
				" cannot find prefix undeclared: undeclared namespace prefix: 'undeclared'")
		})
	}
}

func TestSpcovParseAssertionWithoutSignatureRequirement(t *testing.T) {
	e := spcovSetup(t)

	assertionEl := e.assertion().Element()
	assertion, err := e.sp.parseAssertion(assertionEl, []string{spcovRequestID}, spcovNow, signatureNotRequired)
	assert.NilError(t, err)
	assert.Equal(t, "id-assertion", assertion.ID)

	a := e.assertion()
	a.Issuer.Value = "https://evil.example.com/"
	_, err = e.sp.parseAssertion(a.Element(), []string{spcovRequestID}, spcovNow, signatureNotRequired)
	assert.Error(t, err, `issuer is not "`+spcovIDPEntityID+`"`)

	bad := e.assertion().Element()
	bad.CreateAttr("IssueInstant", "not-a-time")
	_, err = e.sp.parseAssertion(bad, []string{spcovRequestID}, spcovNow, signatureNotRequired)
	assert.Error(t, err, "parsing time \"not-a-time\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"not-a-time\" as \"2006\"")
}

func TestSpcovDecryptElement(t *testing.T) {
	e := spcovSetup(t)

	t.Run("round trip", func(t *testing.T) {
		el, err := e.sp.decryptElement(e.encryptedAssertion(t, []byte(`<x attr="1"/>`)))
		assert.NilError(t, err)
		assert.Equal(t, "x", el.Tag)
		assert.Equal(t, "1", el.SelectAttrValue("attr", ""))
	})

	t.Run("no EncryptedData", func(t *testing.T) {
		el := etree.NewElement("saml:EncryptedAssertion")
		_, err := e.sp.decryptElement(el)
		assert.Error(t, err, "cannot find http://www.w3.org/2001/04/xmlenc#:EncryptedData element")
	})

	t.Run("bad sibling EncryptedKey", func(t *testing.T) {
		el := e.encryptedAssertion(t, []byte(`<x/>`))
		keyInfo := el.FindElement("./EncryptedData/KeyInfo")
		keyInfo.RemoveChild(keyInfo.FindElement("./EncryptedKey"))
		keyEl := el.CreateElement("xenc:EncryptedKey")
		keyEl.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
		keyEl.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", "urn:bogus")
		_, err := e.sp.decryptElement(el)
		assert.Error(t, err, "failed to decrypt key from response: algorithm is not implemented: urn:bogus")
	})

	t.Run("plaintext rejected by round trip validator", func(t *testing.T) {
		_, err := e.sp.decryptElement(e.encryptedAssertion(t, []byte("<a>\x01</a>")))
		assert.Error(t, err, "xmlenc: decryption failed")
	})

	t.Run("plaintext rejected by etree", func(t *testing.T) {
		_, err := e.sp.decryptElement(e.encryptedAssertion(t, []byte("<a>")))
		assert.Error(t, err, "xmlenc: decryption failed")
	})

	t.Run("plaintext without root element", func(t *testing.T) {
		_, err := e.sp.decryptElement(e.encryptedAssertion(t, []byte("<!-- nothing -->")))
		assert.Error(t, err, "xmlenc: decryption failed")
	})

	// Regression: an EncryptedAssertion whose plaintext has no root element used to
	// cause a nil pointer dereference. Anyone can produce one, since it only needs
	// the SP's public certificate, and the response need not be signed.
	t.Run("rootless plaintext via ParseXMLResponse", func(t *testing.T) {
		el := e.response().Element()
		el.AddChild(e.encryptedAssertion(t, []byte("<!-- nothing -->")))
		_, err := e.sp.ParseXMLResponse(spcovSerialize(t, el), []string{spcovRequestID}, e.sp.AcsURL)
		assert.Error(t, spcovPrivateErr(t, err), "failed to decrypt EncryptedAssertion: xmlenc: decryption failed")
	})
}

// artifactResponseEl builds an ArtifactResponse (optionally signed) wrapping an
// unsigned Response with an unsigned Assertion.
func (e *spcovEnv) artifactResponseEl(t *testing.T, inResponseTo string, sign bool, mutate func(ar *ArtifactResponse)) *etree.Element {
	t.Helper()
	r := e.response()
	r.Assertion = e.assertion()
	ar := &ArtifactResponse{
		ID:           "id-artifact-response",
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: spcovNow,
		Issuer:       &Issuer{Value: spcovIDPEntityID},
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
		Response:     *r,
	}
	if mutate != nil {
		mutate(ar)
	}
	el := ar.Element()
	if sign {
		el = e.idpSign(t, el)
	}
	return el
}

func TestSpcovParseXMLArtifactResponse(t *testing.T) {
	e := spcovSetup(t)
	const artifactReqID = "id-artifact-request"
	parse := func(t *testing.T, buf []byte) (*Assertion, error) {
		t.Helper()
		return e.sp.ParseXMLArtifactResponse(buf, []string{spcovRequestID}, artifactReqID, e.sp.AcsURL)
	}
	envelope := func(t *testing.T, el *etree.Element) []byte {
		t.Helper()
		return spcovSerialize(t, spcovSOAPEnvelope(el))
	}

	t.Run("signed artifact response", func(t *testing.T) {
		assertion, err := parse(t, envelope(t, e.artifactResponseEl(t, artifactReqID, true, nil)))
		assert.NilError(t, err)
		assert.Equal(t, "alice@example.com", assertion.Subject.NameID.Value)
	})

	t.Run("unsigned artifact response requires signed assertions", func(t *testing.T) {
		_, err := parse(t, envelope(t, e.artifactResponseEl(t, artifactReqID, false, nil)))
		assert.Error(t, spcovPrivateErr(t, err), "signature element not present")
	})

	t.Run("unsigned artifact response with signed inner response", func(t *testing.T) {
		el := e.artifactResponseEl(t, artifactReqID, false, nil)
		inner := el.FindElement("./Response")
		el.RemoveChild(inner)
		el.AddChild(e.idpSign(t, inner))
		assertion, err := parse(t, envelope(t, el))
		assert.NilError(t, err)
		assert.Equal(t, "id-assertion", assertion.ID)
	})

	t.Run("etree rejects document", func(t *testing.T) {
		_, err := parse(t, []byte("<a>"))
		assert.Error(t, spcovPrivateErr(t, err), "cannot unmarshal response: etree: invalid XML format")
	})

	t.Run("not a SOAP envelope", func(t *testing.T) {
		_, err := parse(t, spcovSerialize(t, e.artifactResponseEl(t, artifactReqID, true, nil)))
		assert.Error(t, spcovPrivateErr(t, err), "expected a SOAP Envelope")

		_, err = parse(t, []byte(`<Envelope xmlns="urn:not-soap"/>`))
		assert.Error(t, spcovPrivateErr(t, err), "expected a SOAP Envelope")
	})

	t.Run("no SOAP body", func(t *testing.T) {
		_, err := parse(t, []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"/>`))
		assert.Error(t, spcovPrivateErr(t, err), "cannot find http://schemas.xmlsoap.org/soap/envelope/:Body element")
	})

	t.Run("no ArtifactResponse", func(t *testing.T) {
		_, err := parse(t, []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`))
		assert.Error(t, spcovPrivateErr(t, err), "cannot find urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse element")
	})

	t.Run("ArtifactResponse fails to unmarshal", func(t *testing.T) {
		el := e.artifactResponseEl(t, artifactReqID, true, nil)
		el.CreateAttr("IssueInstant", "not-a-time")
		_, err := parse(t, envelope(t, el))
		assert.Error(t, spcovPrivateErr(t, err), "parsing time \"not-a-time\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"not-a-time\" as \"2006\"")
	})

	t.Run("bad status", func(t *testing.T) {
		el := e.artifactResponseEl(t, artifactReqID, true, func(ar *ArtifactResponse) {
			ar.Status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Requester"
		})
		_, err := parse(t, envelope(t, el))
		privateErr := spcovPrivateErr(t, err)
		var badStatus ErrBadStatus
		assert.Assert(t, errors.As(privateErr, &badStatus))
		assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Requester", badStatus.Status)
	})

	t.Run("ArtifactResponse tampered after signing", func(t *testing.T) {
		el := e.artifactResponseEl(t, artifactReqID, true, nil)
		el.FindElement("./Response/Assertion/Subject/NameID").SetText("admin@example.com")
		_, err := parse(t, envelope(t, el))
		assert.Error(t, spcovPrivateErr(t, err), "cannot validate signature on ArtifactResponse: Signature could not be verified")
	})

	t.Run("no Response", func(t *testing.T) {
		el := e.artifactResponseEl(t, artifactReqID, false, nil)
		el.RemoveChild(el.FindElement("./Response"))
		_, err := parse(t, envelope(t, e.idpSign(t, el)))
		assert.Error(t, spcovPrivateErr(t, err), "cannot find urn:oasis:names:tc:SAML:2.0:protocol:Response element")
	})
}

// spcovArtifactHandler acts as the IDP's artifact resolution service.
func (e *spcovEnv) artifactHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "text/xml" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		doc := etree.NewDocument()
		if _, err := doc.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resolveEl := doc.FindElement("//ArtifactResolve")
		if resolveEl == nil || resolveEl.FindElement("./Artifact").Text() != "the-artifact" {
			http.Error(w, "unknown artifact", http.StatusNotFound)
			return
		}
		el := e.artifactResponseEl(t, resolveEl.SelectAttrValue("ID", ""), true, nil)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(spcovSerialize(t, spcovSOAPEnvelope(el)))
	}
}

func spcovArtifactRequest(artifact string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://sp.example.com/saml/acs?SAMLart="+url.QueryEscape(artifact), nil)
	if err := req.ParseForm(); err != nil {
		panic(err)
	}
	return req
}

func TestSpcovParseResponseArtifact(t *testing.T) {
	e := spcovSetup(t)
	srv := httptest.NewTLSServer(e.artifactHandler(t))
	t.Cleanup(srv.Close)
	e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = srv.URL + "/artifact"
	e.sp.HTTPClient = srv.Client()

	t.Run("success", func(t *testing.T) {
		assertion, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Equal(t, "alice@example.com", assertion.Subject.NameID.Value)
	})

	t.Run("http error status", func(t *testing.T) {
		_, err := e.sp.ParseResponse(spcovArtifactRequest("unknown-artifact"), []string{spcovRequestID})
		assert.Error(t, spcovPrivateErr(t, err), "Error during artifact resolution: HTTP status 404 (404 Not Found)")
	})

	t.Run("signed artifact resolve request", func(t *testing.T) {
		sp := *e.sp
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		assertion, err := sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Equal(t, "id-assertion", assertion.ID)
	})

	t.Run("cannot make artifact resolve request", func(t *testing.T) {
		sp := *e.sp
		sp.SignatureMethod = "bogus"
		_, err := sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
		assert.Error(t, spcovPrivateErr(t, err), "cannot generate artifact resolution request: invalid signing method bogus")
	})
}

func TestSpcovHandleArtifactRequestTransportErrors(t *testing.T) {
	e := spcovSetup(t)
	ctx := context.Background()

	t.Run("invalid resolution URL", func(t *testing.T) {
		sp := *e.sp
		sp.IDPMetadata = spcovIDPMetadata(e.idpCert)
		sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = "http://bad host/"
		_, err := sp.handleArtifactRequest(ctx, "the-artifact", nil)
		assert.Error(t, spcovPrivateErr(t, err), `cannot resolve artifact: invalid SOAP endpoint "http://bad host/": parse "http://bad host/": invalid character " " in host name`)
	})

	t.Run("default client, no resolution service", func(t *testing.T) {
		sp := *e.sp
		sp.HTTPClient = nil
		sp.IDPMetadata = spcovIDPMetadata(e.idpCert)
		sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices = nil
		_, err := sp.handleArtifactRequest(ctx, "the-artifact", nil)
		assert.Check(t, is.ErrorIs(spcovPrivateErr(t, err), ErrInsecureSOAPEndpoint))
	})

	transportErr := errors.New("connection refused by test")
	readErr := errors.New("read failed by test")
	closeErr := errors.New("close failed by test")
	var gotReq *http.Request
	withTransport := func(rt spcovRoundTripper) *ServiceProvider {
		sp := *e.sp
		sp.HTTPClient = &http.Client{Transport: rt}
		return &sp
	}
	respond := func(body *spcovBody) spcovRoundTripper {
		return func(req *http.Request) (*http.Response, error) {
			gotReq = req
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: body, Request: req}, nil
		}
	}

	t.Run("transport error", func(t *testing.T) {
		sp := withTransport(func(*http.Request) (*http.Response, error) { return nil, transportErr })
		_, err := sp.handleArtifactRequest(ctx, "the-artifact", nil)
		assert.Error(t, spcovPrivateErr(t, err),
			`cannot resolve artifact: Post "`+spcovArtifactLocation+`": connection refused by test`)
	})

	t.Run("body read error", func(t *testing.T) {
		sp := withTransport(respond(&spcovBody{r: bytes.NewReader(nil), readErr: readErr}))
		_, err := sp.handleArtifactRequest(ctx, "the-artifact", nil)
		assert.Error(t, spcovPrivateErr(t, err), "Error during artifact resolution: read failed by test")
		assert.Equal(t, "text/xml", gotReq.Header.Get("Content-Type"))
		assert.Equal(t, spcovArtifactLocation, gotReq.URL.String())
	})

	t.Run("invalid response body and close error is logged", func(t *testing.T) {
		var logBuf bytes.Buffer
		oldLogger := logger.DefaultLogger
		t.Cleanup(func() { logger.DefaultLogger = oldLogger })
		logger.DefaultLogger = log.New(&logBuf, "", 0)

		sp := withTransport(respond(&spcovBody{r: bytes.NewReader([]byte("<not-soap/>")), closeErr: closeErr}))
		_, err := sp.handleArtifactRequest(ctx, "the-artifact", nil)
		assert.Error(t, spcovPrivateErr(t, err), "expected a SOAP Envelope")
		assert.Equal(t, "Error while closing response body during artifact resolution: close failed by test\n", logBuf.String())
	})

	t.Run("artifact response for a different request", func(t *testing.T) {
		body := spcovSerialize(t, spcovSOAPEnvelope(e.artifactResponseEl(t, "id-someone-else", true, nil)))
		sp := withTransport(respond(&spcovBody{r: bytes.NewReader(body)}))
		_, err := sp.handleArtifactRequest(ctx, "the-artifact", []string{spcovRequestID})
		assert.Error(t, spcovPrivateErr(t, err), "`InResponseTo` does not match the artifact request ID (expected id-c8caccced0d2d4d6d8dadcdee0e2e4e6e8eaecee)")
	})
}

func TestSpcovValidateSignatureCertificateSources(t *testing.T) {
	e := spcovSetup(t)
	signed := func(t *testing.T) *etree.Element {
		t.Helper()
		return spcovParse(t, string(e.signedResponse(t)))
	}
	certB64 := base64.StdEncoding.EncodeToString(e.idpCert.Raw)
	sum := sha256.Sum256(e.idpCert.Raw)
	goodFP := spcovColonHex(sum[:])
	alg256 := "http://www.w3.org/2001/04/xmlenc#sha256"
	alg512 := "http://www.w3.org/2001/04/xmlenc#sha512"
	strp := func(s string) *string { return &s }

	withFingerprint := func(fp, alg string) *ServiceProvider {
		sp := *e.sp
		sp.IDPCertificateFingerprint = strp(fp)
		sp.IDPCertificateFingerprintAlgorithm = strp(alg)
		return &sp
	}

	t.Run("fingerprint sha256", func(t *testing.T) {
		assert.NilError(t, withFingerprint(goodFP, alg256).validateSignature(signed(t)))
	})

	t.Run("fingerprint sha512", func(t *testing.T) {
		fp, err := fingerprint(e.idpCert, alg512)
		assert.NilError(t, err)
		assert.NilError(t, withFingerprint(fp, alg512).validateSignature(signed(t)))
	})

	t.Run("fingerprint mismatch", func(t *testing.T) {
		badFP := strings.Repeat("00:", 31) + "00"
		err := withFingerprint(badFP, alg256).validateSignature(signed(t))
		assert.Error(t, err,
			"cannot validate signature on Response: cannot validate signature on Response: fingerprint mismatch")
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
		assert.Check(t, errors.Is(err, ErrUntrustedCertificate))
	})

	t.Run("fingerprint unknown algorithm", func(t *testing.T) {
		assert.Error(t, withFingerprint(goodFP, "urn:bogus").validateSignature(signed(t)),
			"cannot validate signature on Response: cannot validate signature on Response: fingerprint, unknown algorithm: urn:bogus")
	})

	t.Run("fingerprint with no embedded certificate", func(t *testing.T) {
		el := signed(t)
		keyInfo := el.FindElement("./Signature/KeyInfo")
		keyInfo.Parent().RemoveChild(keyInfo)
		assert.Error(t, withFingerprint(goodFP, alg256).validateSignature(el),
			"cannot validate signature on Response: cannot validate signature on Response: no certificate present")
	})

	t.Run("fingerprint with empty certificate element", func(t *testing.T) {
		el := signed(t)
		certEl := el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate")
		for _, c := range append([]etree.Token{}, certEl.Child...) {
			certEl.RemoveChild(c)
		}
		assert.Error(t, withFingerprint(goodFP, alg256).validateSignature(el),
			"cannot validate signature on Response: cannot validate signature on Response: x509 cert el child len != 1: 0")
	})

	t.Run("fingerprint with element inside certificate element", func(t *testing.T) {
		el := signed(t)
		certEl := el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate")
		for _, c := range append([]etree.Token{}, certEl.Child...) {
			certEl.RemoveChild(c)
		}
		certEl.CreateElement("Nested")
		assert.Error(t, withFingerprint(goodFP, alg256).validateSignature(el),
			"cannot validate signature on Response: cannot validate signature on Response: x509 cert el first child not char data: *etree.Element")
	})

	t.Run("fingerprint with garbage certificate", func(t *testing.T) {
		el := signed(t)
		el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate").SetText("!!!")
		assert.Error(t, withFingerprint(goodFP, alg256).validateSignature(el),
			"cannot validate signature on Response: cannot validate signature on Response: parse cert, cannot base64 decode cert string: illegal base64 data at input byte 0")
	})

	t.Run("fingerprint matches but signature does not", func(t *testing.T) {
		el := signed(t)
		el.FindElement("./Status/StatusCode").CreateAttr("Value", "urn:tampered")
		err := withFingerprint(goodFP, alg256).validateSignature(el)
		assert.Error(t, err, "cannot validate signature on Response: Signature could not be verified")
	})

	t.Run("explicit certificate", func(t *testing.T) {
		sp := *e.sp
		sp.IDPCertificate = strp(certB64)
		sp.IDPMetadata = &EntityDescriptor{} // metadata certificates are not consulted
		assert.NilError(t, sp.validateSignature(signed(t)))
	})

	t.Run("explicit certificate that does not parse", func(t *testing.T) {
		sp := *e.sp
		sp.IDPCertificate = strp("!!!")
		assert.Error(t, sp.validateSignature(signed(t)),
			"cannot validate signature on Response: parse cert, cannot base64 decode cert string: illegal base64 data at input byte 0")
	})

	t.Run("explicit certificate that is not the signer", func(t *testing.T) {
		sp := *e.sp
		sp.IDPCertificate = strp(base64.StdEncoding.EncodeToString(mustParseCertificate(golden.Get(t, "cert_2017.pem")).Raw))
		err := sp.validateSignature(signed(t))
		assert.Error(t, err,
			"cannot validate signature on Response: Could not verify certificate against trusted certs")
		assert.Check(t, errors.Is(err, ErrInvalidSignature))
		assert.Check(t, errors.Is(err, ErrUntrustedCertificate))
	})

	misconfigured := "cannot validate signature on Response: saml config not set up properly, specify either idp metadata url, fingerprints or actual certificate"

	t.Run("no IDP metadata", func(t *testing.T) {
		sp := *e.sp
		sp.IDPMetadata = nil
		assert.Error(t, sp.validateSignature(signed(t)), misconfigured)
	})

	t.Run("fingerprint without algorithm", func(t *testing.T) {
		sp := *e.sp
		sp.IDPCertificateFingerprint = strp(goodFP)
		assert.Error(t, sp.validateSignature(signed(t)), misconfigured)
	})

	t.Run("fingerprint and certificate both set", func(t *testing.T) {
		sp := withFingerprint(goodFP, alg256)
		sp.IDPCertificate = strp(certB64)
		assert.Error(t, sp.validateSignature(signed(t)), misconfigured)
	})
}

func TestSpcovValidateSignatureMisc(t *testing.T) {
	e := spcovSetup(t)

	t.Run("two signatures", func(t *testing.T) {
		el := spcovParse(t, string(e.signedResponse(t)))
		el.AddChild(el.FindElement("./Signature").Copy())
		assert.Error(t, e.sp.validateSignature(el), "expected at most one http://www.w3.org/2000/09/xmldsig#:Signature element")
	})

	t.Run("signature-like element in another namespace is ignored", func(t *testing.T) {
		el := e.response().Element()
		fake := el.CreateElement("x:Signature")
		fake.CreateAttr("xmlns:x", "urn:not-dsig")
		assert.Equal(t, errSignatureElementNotPresent, e.sp.validateSignature(el))
	})

	t.Run("custom verifier", func(t *testing.T) {
		sentinel := errors.New("rejected by custom verifier")
		v := &spcovVerifier{err: sentinel}
		sp := *e.sp
		sp.SignatureVerifier = v
		el := spcovParse(t, string(e.signedResponse(t)))
		assert.Assert(t, errors.Is(sp.validateSignature(el), sentinel))
		assert.Assert(t, v.called)

		v.err = nil
		assert.NilError(t, sp.validateSignature(el))
	})
}

// --- logout responses ---

func (e *spcovEnv) signedLogoutResponse(t *testing.T, mutate func(lr *LogoutResponse)) []byte {
	t.Helper()
	lr := e.logoutResponse()
	if mutate != nil {
		mutate(lr)
	}
	return spcovSerialize(t, e.idpSign(t, lr.Element()))
}

func TestSpcovValidateLogoutResponseRequest(t *testing.T) {
	e := spcovSetup(t)
	buf := e.signedLogoutResponse(t, nil)

	t.Run("redirect binding", func(t *testing.T) {
		q := base64.StdEncoding.EncodeToString(spcovDeflate(t, buf))
		req := httptest.NewRequest(http.MethodGet, e.sp.SloURL.String()+"?SAMLResponse="+url.QueryEscape(q), nil)
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(req))
	})

	t.Run("post binding", func(t *testing.T) {
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(buf)}}
		req := httptest.NewRequest(http.MethodPost, e.sp.SloURL.String(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(req))
	})

	t.Run("unparsable form", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, e.sp.SloURL.String()+"?a=%zz", nil)
		assert.Error(t, e.sp.ValidateLogoutResponseRequest(req), `unable to parse form: invalid URL escape "%zz"`)
	})

	t.Run("empty post", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, e.sp.SloURL.String(), nil)
		assert.Error(t, spcovPrivateErr(t, e.sp.ValidateLogoutResponseRequest(req)), "invalid xml: no root")
	})
}

func TestParseLogoutResponse(t *testing.T) {
	e := spcovSetup(t)
	postRequest := func(buf []byte) *http.Request {
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(buf)}}
		req := httptest.NewRequest(http.MethodPost, e.sp.SloURL.String(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	valid := e.signedLogoutResponse(t, nil)

	t.Run("post binding", func(t *testing.T) {
		resp, err := e.sp.ParseLogoutResponse(postRequest(valid), []string{"id-other", "id-logout-request"})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("id-logout-response", resp.ID))
		assert.Check(t, is.Equal("id-logout-request", resp.InResponseTo))
	})

	t.Run("redirect binding", func(t *testing.T) {
		q := redirectQuery{param: "SAMLResponse", xml: e.unsignedLogoutResponse(t), sigAlg: dsig.RSASHA256SignatureMethod, key: e.idpKey}
		resp, err := e.sp.ParseLogoutResponse(redirectRequest(e.sp, q.build(t)), []string{"id-logout-request"})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("id-logout-request", resp.InResponseTo))
	})

	t.Run("InResponseTo not pending", func(t *testing.T) {
		resp, err := e.sp.ParseLogoutResponse(postRequest(valid), []string{"id-other"})
		assert.Check(t, is.Nil(resp))
		assert.Error(t, err, "`InResponseTo` does not match any of the possible request IDs (expected [id-other])")
		assert.Check(t, errors.Is(err, ErrRequestIDMismatch))
	})

	t.Run("no pending requests", func(t *testing.T) {
		resp, err := e.sp.ParseLogoutResponse(postRequest(valid), nil)
		assert.Check(t, is.Nil(resp))
		assert.Error(t, err, "`InResponseTo` does not match any of the possible request IDs (expected [])")
	})

	t.Run("empty InResponseTo", func(t *testing.T) {
		buf := e.signedLogoutResponse(t, func(lr *LogoutResponse) { lr.InResponseTo = "" })
		resp, err := e.sp.ParseLogoutResponse(postRequest(buf), []string{""})
		assert.Check(t, is.Nil(resp))
		assert.Error(t, err, "`InResponseTo` does not match any of the possible request IDs (expected [])")
	})

	t.Run("invalid response", func(t *testing.T) {
		buf := e.signedLogoutResponse(t, func(lr *LogoutResponse) { lr.Destination = "https://evil.example.com/slo" })
		resp, err := e.sp.ParseLogoutResponse(postRequest(buf), []string{"id-logout-request"})
		assert.Check(t, is.Nil(resp))
		assert.Error(t, err, "`Destination` does not match SloURL (expected \"https://sp.example.com/saml/slo\")")
		assert.Check(t, errors.Is(err, ErrDestinationMismatch))
	})
}

// spcovLogoutValidators runs a check against both the POST and the Redirect variant.
func spcovLogoutValidators(e *spcovEnv) map[string]func(t *testing.T, buf []byte) error {
	return map[string]func(t *testing.T, buf []byte) error{
		"form": func(_ *testing.T, buf []byte) error {
			return e.sp.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString(buf))
		},
		"redirect": func(t *testing.T, buf []byte) error {
			return e.sp.ValidateLogoutResponseRedirect(base64.StdEncoding.EncodeToString(spcovDeflate(t, buf)))
		},
	}
}

func TestSpcovValidateLogoutResponseContent(t *testing.T) {
	e := spcovSetup(t)
	tests := []struct {
		name    string
		buf     func(t *testing.T) []byte
		wantErr string
	}{
		{
			name: "valid",
			buf:  func(t *testing.T) []byte { return e.signedLogoutResponse(t, nil) },
		},
		{
			name: "wrong destination",
			buf: func(t *testing.T) []byte {
				return e.signedLogoutResponse(t, func(lr *LogoutResponse) { lr.Destination = "https://evil.example.com/slo" })
			},
			wantErr: "`Destination` does not match SloURL (expected \"https://sp.example.com/saml/slo\")",
		},
		{
			name: "expired",
			buf: func(t *testing.T) []byte {
				return e.signedLogoutResponse(t, func(lr *LogoutResponse) { lr.IssueInstant = spcovNow.Add(-MaxIssueDelay - time.Second) })
			},
			wantErr: "issueInstant expired at " + spcovNow.Add(-time.Second).String(),
		},
		{
			name: "no issuer",
			buf: func(t *testing.T) []byte {
				return e.signedLogoutResponse(t, func(lr *LogoutResponse) { lr.Issuer = nil })
			},
			wantErr: `issuer does not match the IDP metadata (expected "` + spcovIDPEntityID + `")`,
		},
		{
			name: "wrong issuer",
			buf: func(t *testing.T) []byte {
				return e.signedLogoutResponse(t, func(lr *LogoutResponse) { lr.Issuer.Value = "https://evil.example.com/" })
			},
			wantErr: `issuer does not match the IDP metadata (expected "` + spcovIDPEntityID + `")`,
		},
		{
			name: "status not success",
			buf: func(t *testing.T) []byte {
				return e.signedLogoutResponse(t, func(lr *LogoutResponse) {
					lr.Status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Requester"
				})
			},
			wantErr: "status code was not " + StatusSuccess,
		},
	}
	for _, tc := range tests {
		for variant, validate := range spcovLogoutValidators(e) {
			t.Run(tc.name+"/"+variant, func(t *testing.T) {
				err := validate(t, tc.buf(t))
				if tc.wantErr == "" {
					assert.NilError(t, err)
				} else {
					assert.Error(t, err, tc.wantErr)
				}
			})
		}
	}
}

func TestSpcovValidateLogoutResponseMalformed(t *testing.T) {
	e := spcovSetup(t)
	tests := []struct {
		name string
		buf  func(t *testing.T) []byte
		// wantPrivateErr is the PrivateErr of the returned InvalidResponseError, or
		// wantErr the plain error when the validator returns one.
		wantPrivateErr string
		wantErr        string
	}{
		{
			name:    "round trip validator rejects document",
			buf:     func(*testing.T) []byte { return []byte("<a>\x01</a>") },
			wantErr: "XML syntax error on line 1: illegal character code U+0001",
		},
		{
			name:           "etree rejects document",
			buf:            func(*testing.T) []byte { return []byte("<a>") },
			wantPrivateErr: "etree: invalid XML format",
		},
		{
			// regression: used to be a nil pointer dereference
			name:           "no root element",
			buf:            func(*testing.T) []byte { return []byte("<!-- nothing -->") },
			wantPrivateErr: "invalid xml: no root",
		},
		{
			name: "unsigned",
			buf: func(t *testing.T) []byte {
				return spcovSerialize(t, e.logoutResponse().Element())
			},
			wantPrivateErr: "signature element not present",
		},
		{
			name: "tampered",
			buf: func(t *testing.T) []byte {
				return bytes.Replace(e.signedLogoutResponse(t, nil), []byte(spcovIDPEntityID), []byte("https://evil.example.com/"), 1)
			},
			wantPrivateErr: "cannot validate signature on LogoutResponse: Signature could not be verified",
		},
		{
			name: "signed but does not unmarshal",
			buf: func(t *testing.T) []byte {
				el := e.logoutResponse().Element()
				el.CreateAttr("IssueInstant", "not-a-time")
				return spcovSerialize(t, e.idpSign(t, el))
			},
			wantPrivateErr: `parsing time "not-a-time" as "2006-01-02T15:04:05Z07:00": cannot parse "not-a-time" as "2006"`,
		},
	}
	for _, tc := range tests {
		for variant, validate := range spcovLogoutValidators(e) {
			t.Run(tc.name+"/"+variant, func(t *testing.T) {
				err := validate(t, tc.buf(t))
				if tc.wantErr != "" {
					// the POST variant adds context, the Redirect variant does not
					want := tc.wantErr
					if variant == "form" {
						want = "response contains invalid XML: " + want
					}
					assert.Error(t, err, want)
					return
				}
				assert.Error(t, spcovPrivateErr(t, err), tc.wantPrivateErr)
			})
		}
	}

	t.Run("form: bad base64", func(t *testing.T) {
		err := e.sp.ValidateLogoutResponseForm("!!!")
		assert.Error(t, spcovPrivateErr(t, err), "unable to parse base64: illegal base64 data at input byte 0")
	})

	t.Run("redirect: bad base64", func(t *testing.T) {
		err := e.sp.ValidateLogoutResponseRedirect("!!!")
		assert.Error(t, spcovPrivateErr(t, err), "unable to parse base64: illegal base64 data at input byte 0")
	})

	t.Run("redirect: not deflated", func(t *testing.T) {
		err := e.sp.ValidateLogoutResponseRedirect(base64.StdEncoding.EncodeToString([]byte{0xff, 0xff, 0xff}))
		privateErr := spcovPrivateErr(t, err)
		assert.Error(t, privateErr, "flate: corrupt input before offset 1")
	})

	t.Run("redirect: truncated deflate stream", func(t *testing.T) {
		deflated := spcovDeflate(t, e.signedLogoutResponse(t, nil))
		err := e.sp.ValidateLogoutResponseRedirect(base64.StdEncoding.EncodeToString(deflated[:len(deflated)/2]))
		assert.Assert(t, errors.Is(spcovPrivateErr(t, err), io.ErrUnexpectedEOF))
	})
}

func TestSpcovSignedRedirectRequestCarriesVerifiableSignature(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	u, err := e.sp.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)

	raw := u.RawQuery
	idx := strings.Index(raw, "&Signature=")
	assert.Assert(t, idx > 0)
	signed := raw[:idx]
	sig, err := url.QueryUnescape(raw[idx+len("&Signature="):])
	assert.NilError(t, err)
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	assert.NilError(t, err)
	assert.Assert(t, strings.Contains(signed, "&RelayState=relay&SigAlg="), signed)

	digest := sha256.Sum256([]byte(signed))
	pub := e.sp.Certificate.PublicKey.(*rsa.PublicKey)
	assert.NilError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigBytes))
	assert.Check(t, is.Equal(e.sp.GetSSOBindingLocation(HTTPRedirectBinding), u.Scheme+"://"+u.Host+u.Path))
}
