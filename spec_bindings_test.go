package saml

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Tests pinning behavior required by the OASIS SAML V2.0 Bindings
// specification (saml-bindings-2.0-os) and the HTTP-POST-SimpleSign binding
// (sstc-saml-binding-simplesign-cs-01).

var (
	specFormRe      = regexp.MustCompile(`<form method="([^"]*)" action="([^"]*)"`)
	specFormInputRe = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)" />`)
)

// specParseForm extracts the method, action and hidden controls of the first
// HTML form in body, unescaping HTML entities.
func specParseForm(t *testing.T, body string) (method, action string, fields url.Values) {
	t.Helper()
	m := specFormRe.FindStringSubmatch(body)
	assert.Assert(t, m != nil, body)
	fields = url.Values{}
	for _, in := range specFormInputRe.FindAllStringSubmatch(body, -1) {
		fields.Add(html.UnescapeString(in[1]), html.UnescapeString(in[2]))
	}
	return m[1], html.UnescapeString(m[2]), fields
}

// specRawParams splits a raw query string into its parameters, in order,
// without decoding them.
func specRawParams(rawQuery string) (names []string, raw map[string]string) {
	raw = map[string]string{}
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(pair, "=")
		names = append(names, k)
		raw[k] = v
	}
	return names, raw
}

// specWrap inserts CRLF line breaks every n characters of s, as a sender
// that line-wraps base64 would.
func specWrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n])
		b.WriteString("\r\n")
		s = s[n:]
	}
	b.WriteString(s)
	return b.String()
}

// specIDPTest returns an IdentityProviderTest whose session provider always
// returns a session, restoring the globals NewIdentityProviderTest changes.
func specIDPTest(t *testing.T) *IdentityProviderTest {
	t.Helper()
	oldTimeNow, oldRandReader := TimeNow, RandReader
	t.Cleanup(func() { TimeNow, RandReader = oldTimeNow, oldRandReader })
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", UserName: "alice"}
		},
	}
	return test
}

// saml-bindings-2.0-os §3.4.4.1 steps 2-4: the message is compressed with
// DEFLATE as specified in RFC 1951 (raw, no zlib/gzip wrapper), base64
// encoded with linefeeds and other whitespace removed, and carried in a
// SAMLRequest (or SAMLResponse) query parameter.
func TestSpecBinding_3_4_4_1_DeflateBase64NoWhitespace(t *testing.T) {
	e := spcovSetup(t)
	req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/redirect", HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	// Make the request large enough that a line-wrapping encoder would wrap.
	req.ProviderName = strings.Repeat("A long provider name. ", 40)
	u, err := req.Redirect("", e.sp)
	assert.NilError(t, err)

	encoded := u.Query().Get("SAMLRequest")
	assert.Assert(t, len(encoded) > 76, "test message too short to exercise line wrapping")
	assert.Check(t, !strings.ContainsAny(encoded, " \t\r\n"), "base64 must not contain whitespace")

	compressed, err := base64.StdEncoding.Strict().DecodeString(encoded)
	assert.NilError(t, err)
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	assert.NilError(t, err, "SAMLRequest must be raw RFC 1951 DEFLATE")

	var decoded AuthnRequest
	assert.NilError(t, xml.Unmarshal(inflated, &decoded))
	assert.Check(t, is.Equal(req.ID, decoded.ID))
	assert.Check(t, is.Equal(u.Query().Get("SAMLResponse"), ""))
}

// saml-bindings-2.0-os §3.4.4.1 (signing steps 1-4): the signed octet string
// is "SAMLRequest=value&RelayState=value&SigAlg=value" (or SAMLResponse=...)
// built from the URL-encoded values, in that order; the signature is base64
// encoded and carried in a Signature parameter. Verified here independently
// of the library's own parser, with the SP certificate.
func TestSpecBinding_3_4_4_1_SignedOctetString(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	const relayState = "state with spaces/&=+"

	check := func(t *testing.T, u *url.URL, messageParam string, withRelayState bool) {
		t.Helper()
		names, raw := specRawParams(u.RawQuery)
		want := []string{messageParam, "RelayState", "SigAlg", "Signature"}
		if !withRelayState {
			want = []string{messageParam, "SigAlg", "Signature"}
		}
		assert.Check(t, is.DeepEqual(want, names))

		signed := messageParam + "=" + raw[messageParam]
		if withRelayState {
			signed += "&RelayState=" + raw["RelayState"]
		}
		signed += "&SigAlg=" + raw["SigAlg"]
		assert.Check(t, strings.HasPrefix(u.RawQuery, signed+"&Signature="))

		assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, u.Query().Get("SigAlg")))
		sigB64 := u.Query().Get("Signature")
		assert.Check(t, !strings.ContainsAny(sigB64, " \t\r\n"))
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		assert.NilError(t, err)
		assert.NilError(t, e.sp.Certificate.CheckSignature(x509.SHA256WithRSA, []byte(signed), sig))
		if withRelayState {
			assert.Check(t, is.Equal(relayState, u.Query().Get("RelayState")))
		}
	}

	t.Run("AuthnRequest with RelayState", func(t *testing.T) {
		u, err := e.sp.MakeRedirectAuthenticationRequest(relayState)
		assert.NilError(t, err)
		check(t, u, "SAMLRequest", true)
	})

	// §3.4.4.1: "if there is no RelayState value, the entire parameter
	// should be omitted from the signature computation (and not included as
	// an empty parameter name)".
	t.Run("AuthnRequest without RelayState", func(t *testing.T) {
		u, err := e.sp.MakeRedirectAuthenticationRequest("")
		assert.NilError(t, err)
		check(t, u, "SAMLRequest", false)
	})

	t.Run("LogoutResponse", func(t *testing.T) {
		u, err := e.sp.MakeRedirectLogoutResponse("id-req", relayState)
		assert.NilError(t, err)
		check(t, u, "SAMLResponse", true)
	})
}

// saml-bindings-2.0-os §3.4.4.1: "the order of the query string parameters on
// the resulting URL to be verified is not prescribed by this binding ... the
// relying party MUST ensure that the parameter values to be verified are
// ordered as required by the signing rules", "Any other content in the
// original query string is not included and not signed", and "The relying
// party MUST therefore perform the verification step using the original
// URL-encoded values it received".
func TestSpecBinding_3_4_4_1_VerifyReordersAndUsesOriginalEncoding(t *testing.T) {
	e := spcovSetup(t)
	unsigned := e.unsignedLogoutResponse(t)

	// An escape function that differs from Go's url.QueryEscape: spaces as
	// %20 rather than '+', and '~' and '-' percent-encoded.
	oddEscape := func(s string) string {
		escaped := strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
		escaped = strings.ReplaceAll(escaped, "~", "%7E")
		return strings.ReplaceAll(escaped, "-", "%2D")
	}
	q := redirectQuery{
		param:      "SAMLResponse",
		xml:        unsigned,
		relayState: "a b~c-d",
		sigAlg:     dsig.RSASHA256SignatureMethod,
		key:        e.idpKey,
		escape:     oddEscape,
	}
	built := q.build(t)
	assert.Assert(t, strings.Contains(built, "RelayState=a%20b%7Ec%2Dd"), built)

	t.Run("original encoding", func(t *testing.T) {
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, built)))
	})

	t.Run("parameters in another order with unrelated parameters", func(t *testing.T) {
		names, raw := specRawParams(built)
		assert.Assert(t, is.Len(names, 4))
		reordered := strings.Join([]string{
			"foo=bar",
			"Signature=" + raw["Signature"],
			"SigAlg=" + raw["SigAlg"],
			"RelayState=" + raw["RelayState"],
			"tenant=x%20y",
			"SAMLResponse=" + raw["SAMLResponse"],
		}, "&")
		assert.NilError(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, reordered)))
	})

	t.Run("re-encoded values do not verify", func(t *testing.T) {
		// Re-encoding the RelayState the Go way changes the signed octets;
		// the signature was made over the sender's encoding.
		reencoded := strings.Replace(built, "RelayState=a%20b%7Ec%2Dd", "RelayState="+url.QueryEscape("a b~c-d"), 1)
		assert.Assert(t, reencoded != built)
		assert.Check(t, e.sp.ValidateLogoutResponseRequest(redirectRequest(e.sp, reencoded)) != nil)
	})
}

// saml-bindings-2.0-os §3.4.4.1 step 5: RSAwithSHA1
// (http://www.w3.org/2000/09/xmldsig#rsa-sha1) MUST be supported, here for an
// HTTP-Redirect LogoutRequest received by the service provider.
func TestSpecBinding_3_4_4_1_RSASHA1LogoutRequest(t *testing.T) {
	e := spcovSetup(t)
	q := redirectQuery{
		param:      "SAMLRequest",
		xml:        spcovSerialize(t, e.logoutRequest().Element()),
		relayState: "rs",
		sigAlg:     dsig.RSASHA1SignatureMethod,
		key:        e.idpKey,
	}
	r := redirectRequest(e.sp, q.build(t))
	lr, err := e.sp.ValidateLogoutRequest(r)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("id-idp-logout-request", lr.ID))
}

// saml-bindings-2.0-os §3.4.3 and §3.5.3: "If a SAML request message is
// accompanied by RelayState data, then the SAML responder MUST return its
// SAML protocol response using a binding that also supports a RelayState
// mechanism, and it MUST place the exact data it received with the request
// into the corresponding RelayState parameter in the response."
func TestSpecBinding_3_4_3_IDPReturnsExactRelayState(t *testing.T) {
	// 80 bytes, with characters that need URL and HTML escaping.
	relayState := `a b+c&d=e"f'g<h>i%j/` + strings.Repeat("z", 60)
	assert.Assert(t, is.Len(relayState, 80))

	check := func(t *testing.T, w *httptest.ResponseRecorder, test *IdentityProviderTest) {
		t.Helper()
		assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
		method, action, fields := specParseForm(t, w.Body.String())
		assert.Check(t, is.Equal("post", method))
		assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
		assert.Check(t, is.DeepEqual([]string{relayState}, fields["RelayState"]))
	}

	t.Run("HTTP-Redirect request", func(t *testing.T) {
		test := specIDPTest(t)
		u, err := test.SP.MakeRedirectAuthenticationRequest(relayState)
		assert.NilError(t, err)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
		check(t, w, test)
	})

	t.Run("HTTP-POST request", func(t *testing.T) {
		test := specIDPTest(t)
		_, _, fields := specParseForm(t, string(mustPost(t, &test.SP, relayState)))
		r := httptest.NewRequest(http.MethodPost, test.IDP.SSOURL.String(), strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		check(t, w, test)
	})
}

func mustPost(t *testing.T, sp *ServiceProvider, relayState string) []byte {
	t.Helper()
	form, err := sp.MakePostAuthenticationRequest(relayState)
	assert.NilError(t, err)
	return form
}

// saml-bindings-2.0-os §3.5.4: the message is base64 encoded into a form
// control named SAMLRequest (or SAMLResponse), RelayState goes into a hidden
// control named RelayState, the form's action is the recipient's endpoint and
// its method is "POST", and control values "MUST be transformed so as to be
// safe to include in the XHTML document. This includes transforming
// characters such as quotes into HTML entities".
func TestSpecBinding_3_5_4_FormEncoding(t *testing.T) {
	const relayState = `"><script>alert('x')</script>&amp;`

	t.Run("SP AuthnRequest", func(t *testing.T) {
		e := spcovSetup(t)
		req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/post", HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		body := string(req.Post(relayState))
		assert.Check(t, !strings.Contains(body, "<script>alert"), body)

		method, action, fields := specParseForm(t, body)
		assert.Check(t, is.Equal("post", method))
		assert.Check(t, is.Equal("https://idp.example.com/sso/post", action))
		assert.Check(t, is.DeepEqual([]string{relayState}, fields["RelayState"]))
		buf, err := base64.StdEncoding.DecodeString(fields.Get("SAMLRequest"))
		assert.NilError(t, err)
		var decoded AuthnRequest
		assert.NilError(t, xml.Unmarshal(buf, &decoded))
		assert.Check(t, is.Equal(req.ID, decoded.ID))
	})

	t.Run("IdP Response", func(t *testing.T) {
		test := specIDPTest(t)
		u, err := test.SP.MakeRedirectAuthenticationRequest(relayState)
		assert.NilError(t, err)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
		assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
		body := w.Body.String()
		assert.Check(t, !strings.Contains(body, "<script>alert"), body)

		method, action, fields := specParseForm(t, body)
		assert.Check(t, is.Equal("post", method))
		assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
		assert.Check(t, is.DeepEqual([]string{relayState}, fields["RelayState"]))
		buf, err := base64.StdEncoding.DecodeString(fields.Get("SAMLResponse"))
		assert.NilError(t, err)
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(buf))
		assert.Check(t, is.Equal("Response", doc.Root().Tag))
		assert.Check(t, is.Equal(test.SP.AcsURL.String(), doc.Root().SelectAttrValue("Destination", "")))
	})
}

// saml-bindings-2.0-os §3.5.4: "The base64-encoded value MAY be line-wrapped
// at a reasonable length in accordance with common practice." A recipient
// must therefore accept line-wrapped SAMLResponse and SAMLRequest values.
func TestSpecBinding_3_5_4_LineWrappedBase64Accepted(t *testing.T) {
	t.Run("SP ACS", func(t *testing.T) {
		e := spcovSetup(t)
		wrapped := specWrap(base64.StdEncoding.EncodeToString(e.signedResponse(t)), 76)
		assert.Assert(t, strings.Contains(wrapped, "\r\n"))
		form := url.Values{"SAMLResponse": {wrapped}}
		r := httptest.NewRequest(http.MethodPost, e.sp.AcsURL.String(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NilError(t, r.ParseForm())
		assertion, err := e.sp.ParseResponse(r, []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("IdP SSO", func(t *testing.T) {
		test := specIDPTest(t)
		_, _, fields := specParseForm(t, string(mustPost(t, &test.SP, "rs")))
		fields.Set("SAMLRequest", specWrap(fields.Get("SAMLRequest"), 64))
		assert.Assert(t, strings.Contains(fields.Get("SAMLRequest"), "\r\n"))
		r := httptest.NewRequest(http.MethodPost, test.IDP.SSOURL.String(), strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	})
}

// saml-bindings-2.0-os §3.6.3: "There are two methods of encoding an artifact
// ... All endpoints that support this binding MUST support both
// techniques": the SAMLart query parameter (§3.6.3.2, HTTP GET) and the
// SAMLart form control (§3.6.3.3, HTTP POST). §3.6.5: the receiver resolves
// the artifact with a direct exchange (here SOAP over HTTP) and does not
// alter the artifact value.
func TestSpecBinding_3_6_3_ArtifactURLAndFormEncoding(t *testing.T) {
	e := spcovSetup(t)
	// A syntactically valid type 0x0004 artifact: TypeCode, EndpointIndex,
	// 20-byte SourceID (SHA-1 of the issuer's entity ID would go here) and
	// 20-byte MessageHandle. Its base64 form contains '+' and '/', which
	// must survive URL and form encoding.
	artifactBytes := append([]byte{0x00, 0x04, 0x00, 0x00}, bytes.Repeat([]byte{0xfb, 0xff}, 20)...)
	artifact := base64.StdEncoding.EncodeToString(artifactBytes)
	assert.Assert(t, strings.ContainsAny(artifact, "+/"))

	var gotArtifacts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := etree.NewDocument()
		if _, err := doc.ReadFrom(r.Body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resolveEl := doc.FindElement("//ArtifactResolve")
		gotArtifacts = append(gotArtifacts, resolveEl.FindElement("./Artifact").Text())
		el := e.artifactResponseEl(t, resolveEl.SelectAttrValue("ID", ""), true, nil)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write(spcovSerialize(t, spcovSOAPEnvelope(el)))
	}))
	t.Cleanup(srv.Close)
	e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = srv.URL + "/artifact"
	e.sp.HTTPClient = srv.Client()

	t.Run("URL encoding (GET)", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, e.sp.AcsURL.String()+"?SAMLart="+url.QueryEscape(artifact)+"&RelayState=rs", nil)
		assert.NilError(t, r.ParseForm())
		assertion, err := e.sp.ParseResponse(r, []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	t.Run("form encoding (POST)", func(t *testing.T) {
		form := url.Values{"SAMLart": {artifact}, "RelayState": {"rs"}}
		r := httptest.NewRequest(http.MethodPost, e.sp.AcsURL.String(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NilError(t, r.ParseForm())
		assertion, err := e.sp.ParseResponse(r, []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})

	assert.Check(t, is.DeepEqual([]string{artifact, artifact}, gotArtifacts))
}

// saml-bindings-2.0-os §3.2.2.1: "SAML request-response protocol elements
// MUST be enclosed within the SOAP message body" and "The SAML requester
// MUST NOT include more than one SAML request per SOAP message or include
// any additional XML elements in the SOAP body." §3.2.2: the binding uses
// SOAP 1.1, and §3.2.3: it is carried over HTTP (POST).
func TestSpecBinding_3_2_2_1_ArtifactResolveSOAPEnvelope(t *testing.T) {
	e := spcovSetup(t)
	var method string
	var body []byte
	h := e.artifactHandler(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		var err error
		body, err = io.ReadAll(r.Body)
		assert.Check(t, err)
		r.Body = io.NopCloser(bytes.NewReader(body))
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	e.sp.IDPMetadata.IDPSSODescriptors[0].ArtifactResolutionServices[0].Location = srv.URL + "/artifact"
	e.sp.HTTPClient = srv.Client()

	_, err := e.sp.ParseResponse(spcovArtifactRequest("the-artifact"), []string{spcovRequestID})
	assert.NilError(t, err)

	assert.Check(t, is.Equal(http.MethodPost, method))
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(body))
	root := doc.Root()
	assert.Check(t, is.Equal("Envelope", root.Tag))
	assert.Check(t, is.Equal("http://schemas.xmlsoap.org/soap/envelope/", root.NamespaceURI()))
	soapBody := root.FindElement("./Body")
	assert.Assert(t, soapBody != nil)
	assert.Check(t, is.Equal("http://schemas.xmlsoap.org/soap/envelope/", soapBody.NamespaceURI()))
	children := soapBody.ChildElements()
	assert.Assert(t, is.Len(children, 1))
	assert.Check(t, is.Equal("ArtifactResolve", children[0].Tag))
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:protocol", children[0].NamespaceURI()))
}

// sstc-saml-binding-simplesign-cs-01 §2.5 and §2.6: the SimpleSign signature
// is over "SAMLResponse=<raw XML>&RelayState=<value>&SigAlg=<value>", with
// none of the values URL- or base64-encoded, and RSAwithSHA1 MUST be
// supported. The receiver reconstructs the string from the form control
// values. Here the IdP-produced form is verified independently with the IdP
// certificate, and the service provider accepts an rsa-sha1 SimpleSign
// response.
func TestSpecBinding_SimpleSign_2_5_SignedOctetString(t *testing.T) {
	t.Run("IdP output", func(t *testing.T) {
		oldTimeNow, oldRandReader := TimeNow, RandReader
		t.Cleanup(func() { TimeNow, RandReader = oldTimeNow, oldRandReader })
		test := newSimpleSignIDPTest(t)
		test.IDP.SessionProvider = &mockSessionProvider{
			GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
				return &Session{ID: "f00df00df00d", UserName: "alice"}
			},
		}
		const relayState = "a b&c=d"
		authnReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostSimpleSignBinding)
		assert.NilError(t, err)
		u, err := authnReq.Redirect(relayState, &test.SP)
		assert.NilError(t, err)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, u.String(), nil))
		assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())

		method, _, fields := specParseForm(t, w.Body.String())
		assert.Check(t, is.Equal("post", method))
		assert.Assert(t, fields.Get("SigAlg") != "", w.Body.String())
		xmlBuf, err := base64.StdEncoding.DecodeString(fields.Get("SAMLResponse"))
		assert.NilError(t, err)
		assert.Check(t, is.Equal(relayState, fields.Get("RelayState")))

		signed := "SAMLResponse=" + string(xmlBuf) + "&RelayState=" + relayState + "&SigAlg=" + fields.Get("SigAlg")
		sig, err := base64.StdEncoding.DecodeString(fields.Get("Signature"))
		assert.NilError(t, err)
		alg, ok := redirectSignatureAlgorithms[fields.Get("SigAlg")]
		assert.Assert(t, ok)
		assert.NilError(t, test.IDP.Certificate.CheckSignature(alg, []byte(signed), sig))
	})

	t.Run("SP accepts rsa-sha1", func(t *testing.T) {
		e := spcovSetup(t)
		xmlBuf := e.simpleSignResponseXML(t, nil)
		const relayState = "rs"
		signed := "SAMLResponse=" + string(xmlBuf) + "&RelayState=" + relayState + "&SigAlg=" + dsig.RSASHA1SignatureMethod
		sig := redirectSign(t, e.idpKey, dsig.RSASHA1SignatureMethod, signed)
		form := url.Values{
			"SAMLResponse": {base64.StdEncoding.EncodeToString(xmlBuf)},
			"RelayState":   {relayState},
			"SigAlg":       {dsig.RSASHA1SignatureMethod},
			"Signature":    {base64.StdEncoding.EncodeToString(sig)},
		}
		r := httptest.NewRequest(http.MethodPost, e.sp.AcsURL.String(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		assert.NilError(t, r.ParseForm())
		assertion, err := e.sp.ParseResponse(r, []string{spcovRequestID})
		assert.NilError(t, err)
		assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
	})
}

// saml-bindings-2.0-os §3.4.5 step 2: when the HTTP-Redirect binding is used,
// "the HTTP status MUST be either 303 or 302". Checked for the IdP's
// HTTP-Redirect LogoutResponse.
func TestSpecBinding_3_4_5_IDPLogoutRedirectStatus(t *testing.T) {
	e := spcovSetup(t)
	idp := &IdentityProvider{
		Key:         e.idpKey,
		Certificate: e.idpCert,
		MetadataURL: mustParseURL(spcovIDPEntityID),
		LogoutURL:   mustParseURL("https://idp.example.com/slo"),
	}
	req := &IdpLogoutRequest{
		IDP:         idp,
		HTTPRequest: httptest.NewRequest(http.MethodGet, "https://idp.example.com/slo", nil),
		RelayState:  "rs",
		Request:     LogoutRequest{ID: "id-lr"},
		SLOEndpoint: &Endpoint{Binding: HTTPRedirectBinding, Location: "https://sp.example.com/saml/slo"},
		Now:         spcovNow,
	}
	w := httptest.NewRecorder()
	assert.NilError(t, req.WriteLogoutResponse(w, req.MakeLogoutResponse(StatusSuccess)))
	assert.Check(t, w.Code == http.StatusFound || w.Code == http.StatusSeeOther, "status %d", w.Code)
	loc, err := url.Parse(w.Header().Get("Location"))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://sp.example.com/saml/slo", loc.Scheme+"://"+loc.Host+loc.Path))
	assert.Check(t, is.Equal("rs", loc.Query().Get("RelayState")))
	assert.Check(t, loc.Query().Get("SAMLResponse") != "")
	assert.Check(t, loc.Query().Get("Signature") != "")
}

// HTTP-Redirect, saml-bindings-2.0-os §3.4.4.1 (lines 578-579): "Any
// signature on the SAML protocol message, including the <ds:Signature> XML
// element itself, MUST be removed." AuthnRequest.Redirect,
// LogoutRequest.Redirect and LogoutResponse.Redirect must drop an enveloped
// signature before deflating, even when called on an already signed message,
// and must leave the caller's message signed.
func TestSpecBinding_3_4_4_1_RedirectMethodsRemoveXMLSignature(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod

	inflated := func(t *testing.T, u *url.URL, param string) *etree.Element {
		t.Helper()
		raw, err := base64.StdEncoding.DecodeString(u.Query().Get(param))
		assert.NilError(t, err)
		doc := etree.NewDocument()
		assert.NilError(t, doc.ReadFromBytes(spcovInflate(t, raw)))
		return doc.Root()
	}

	t.Run("AuthnRequest", func(t *testing.T) {
		// The POST binding makes MakeAuthenticationRequest sign the XML.
		req, err := e.sp.MakeAuthenticationRequest(e.sp.GetSSOBindingLocation(HTTPRedirectBinding), HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		assert.Assert(t, req.Signature != nil)

		u, err := req.Redirect("relay", e.sp)
		assert.NilError(t, err)
		assert.Check(t, inflated(t, u, "SAMLRequest").FindElement("./Signature") == nil)
		assert.Check(t, u.Query().Get("Signature") != "", "query string signature still added")
		assert.Check(t, req.Signature != nil, "caller's request was modified")
	})

	t.Run("LogoutRequest", func(t *testing.T) {
		req, err := e.sp.MakeLogoutRequest(e.sp.GetSLOBindingLocation(HTTPRedirectBinding), "alice")
		assert.NilError(t, err)
		assert.Assert(t, req.Signature != nil)

		u := req.Redirect("relay")
		assert.Check(t, inflated(t, u, "SAMLRequest").FindElement("./Signature") == nil)
		assert.Check(t, req.Signature != nil, "caller's request was modified")
	})

	t.Run("LogoutResponse", func(t *testing.T) {
		resp, err := e.sp.MakeLogoutResponse(e.sp.GetSLOBindingLocation(HTTPRedirectBinding), "id-1")
		assert.NilError(t, err)
		assert.Assert(t, resp.Signature != nil)

		u := resp.Redirect("relay")
		assert.Check(t, inflated(t, u, "SAMLResponse").FindElement("./Signature") == nil)
		assert.Check(t, resp.Signature != nil, "caller's response was modified")
	})
}

// saml-bindings-2.0-os §3.4.3 and §3.5.3 (and SimpleSign §2.3): RelayState
// "MUST NOT exceed 80 bytes in length". Every request this package starts
// refuses a longer one with ErrRelayStateTooLong, and an 80-byte one is
// sent unchanged. A response echoes the RelayState it was given, which "MUST
// [be] the exact data it received", so responses are not checked.
func TestSpecBinding_3_4_3_OriginatedRelayStateAtMost80Bytes(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	ok := strings.Repeat("r", MaxRelayStateLength)
	tooLong := ok + "r"

	starts := map[string]func(relayState string) error{
		"MakeRedirectAuthenticationRequest": func(rs string) error {
			_, err := e.sp.MakeRedirectAuthenticationRequest(rs)
			return err
		},
		"MakePostAuthenticationRequest": func(rs string) error {
			_, err := e.sp.MakePostAuthenticationRequest(rs)
			return err
		},
		"AuthnRequest.SimpleSign": func(rs string) error {
			req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/simplesign", HTTPPostSimpleSignBinding, HTTPPostBinding)
			assert.NilError(t, err)
			_, err = req.SimpleSign(rs, e.sp)
			return err
		},
		"MakeRedirectLogoutRequest": func(rs string) error {
			_, err := e.sp.MakeRedirectLogoutRequest("alice@example.com", rs)
			return err
		},
		"MakePostLogoutRequest": func(rs string) error {
			_, err := e.sp.MakePostLogoutRequest("alice@example.com", rs)
			return err
		},
		"LogoutRequest.SimpleSign": func(rs string) error {
			req, err := e.sp.MakeLogoutRequest("https://idp.example.com/slo/simplesign", "alice@example.com")
			assert.NilError(t, err)
			_, err = req.SimpleSign(rs, e.sp)
			return err
		},
	}
	for name, start := range starts {
		t.Run(name, func(t *testing.T) {
			assert.Check(t, start(ok))
			err := start(tooLong)
			assert.Check(t, errors.Is(err, ErrRelayStateTooLong), "%v", err)
		})
	}

	t.Run("redirect URL carries the 80-byte RelayState unchanged", func(t *testing.T) {
		u, err := e.sp.MakeRedirectAuthenticationRequest(ok)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(ok, u.Query().Get("RelayState")))
	})

	t.Run("responses echo a longer RelayState", func(t *testing.T) {
		u, err := e.sp.MakeRedirectLogoutResponse("id-logout-request", tooLong)
		assert.NilError(t, err)
		assert.Check(t, is.Equal(tooLong, u.Query().Get("RelayState")))
		_, err = e.sp.MakePostLogoutResponse("id-logout-request", tooLong)
		assert.Check(t, err)
	})

	t.Run("IdP-initiated", func(t *testing.T) {
		test := NewIdentityProviderTest(t, applyKey)
		r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/services/sp/whoami", nil)
		_, err := test.IDP.NewIdpInitiatedRequest(r, test.SP.MetadataURL.String(), tooLong)
		assert.Check(t, errors.Is(err, ErrRelayStateTooLong), "%v", err)
		_, err = test.IDP.NewIdpInitiatedRequest(r, test.SP.MetadataURL.String(), ok)
		assert.Check(t, err)

		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), tooLong)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})
}
