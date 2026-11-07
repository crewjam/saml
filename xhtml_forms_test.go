package saml

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const xhtmlNamespace = "http://www.w3.org/1999/xhtml"

// assertXHTMLDocument checks that page is a well-formed XML document whose
// root is an XHTML html element holding a head with a title and a body, as
// saml-bindings-2.0-os §3.5.4 requires of the pages that carry a SAML
// message with the HTTP-POST binding ("The HTML document MUST adhere to the
// XHTML specification").
func assertXHTMLDocument(t *testing.T, page []byte) {
	t.Helper()
	d := xml.NewDecoder(bytes.NewReader(page))
	d.Strict = true

	var path []xml.Name
	roots := 0
	seen := map[string]bool{}
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		assert.NilError(t, err, "page is not well-formed XML:\n%s", page)
		switch tok := tok.(type) {
		case xml.StartElement:
			if len(path) == 0 {
				roots++
				assert.Check(t, is.Equal(xml.Name{Space: xhtmlNamespace, Local: "html"}, tok.Name))
			}
			assert.Check(t, is.Equal(xhtmlNamespace, tok.Name.Space), "element %q is not in the XHTML namespace", tok.Name.Local)
			path = append(path, tok.Name)
			names := make([]string, 0, len(path))
			for _, n := range path {
				names = append(names, n.Local)
			}
			seen[strings.Join(names, "/")] = true
		case xml.EndElement:
			path = path[:len(path)-1]
		case xml.CharData:
			if len(path) == 0 {
				assert.Check(t, is.Equal("", strings.TrimSpace(string(tok))), "text outside the root element")
			}
		}
	}
	assert.Check(t, is.Equal(1, roots))
	assert.Check(t, seen["html/head/title"], "page has no html/head/title")
	assert.Check(t, seen["html/body"], "page has no html/body")
}

// wrapXHTML puts fragment, a form made by one of the PostWithNonce methods,
// in a page the way samlsp.Middleware does.
func wrapXHTML(fragment []byte) []byte {
	return []byte(`<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml"><head><title>Continue</title></head><body>` +
		string(fragment) + `</body></html>`)
}

// awkward values check that whatever the templates interpolate is escaped
// in a way that stays well-formed XML.
const (
	xhtmlAwkwardURL   = "https://sp.example.com/acs?a=1&b=<2>&c=\"3\""
	xhtmlAwkwardRelay = `<relay> & "state" 'x'`
)

func TestXHTMLIdPForms(t *testing.T) {
	render := func(t *testing.T, tmpl interface {
		Execute(io.Writer, any) error
	}, data any,
	) []byte {
		t.Helper()
		var buf bytes.Buffer
		assert.NilError(t, tmpl.Execute(&buf, data))
		return buf.Bytes()
	}

	t.Run("response form", func(t *testing.T) {
		page := render(t, defaultResponseFormTemplate, IdpAuthnRequestForm{
			URL:          xhtmlAwkwardURL,
			SAMLResponse: "PHNhbWxwOlJlc3BvbnNlLz4+/w==",
			RelayState:   xhtmlAwkwardRelay,
		})
		assertXHTMLDocument(t, page)
	})

	t.Run("simplesign response form", func(t *testing.T) {
		page := render(t, defaultSimpleSignResponseFormTemplate, IdpAuthnRequestSimpleSignForm{
			URL:          xhtmlAwkwardURL,
			SAMLResponse: "PHNhbWxwOlJlc3BvbnNlLz4+/w==",
			RelayState:   xhtmlAwkwardRelay,
			SigAlg:       dsig.RSASHA256SignatureMethod,
			Signature:    "c2lnbmF0dXJl+/w==",
		})
		assertXHTMLDocument(t, page)
	})

	t.Run("logout request form", func(t *testing.T) {
		page := render(t, defaultLogoutRequestFormTemplate, struct{ URL, SAMLRequest string }{
			URL:         xhtmlAwkwardURL,
			SAMLRequest: "PHNhbWxwOkxvZ291dFJlcXVlc3QvPg+/w==",
		})
		assertXHTMLDocument(t, page)
	})

	t.Run("logout complete", func(t *testing.T) {
		assertXHTMLDocument(t, render(t, defaultLogoutCompleteTemplate, IdpLogoutComplete{}))
		assertXHTMLDocument(t, render(t, defaultLogoutCompleteTemplate, IdpLogoutComplete{Failed: []string{"https://sp.example.com/<metadata>&x"}}))
	})

	t.Run("ServeSSO", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
		assert.NilError(t, err)
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", requestURL.String(), nil)
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
		assertXHTMLDocument(t, w.Body.Bytes())
	})
}

func TestXHTMLServiceProviderForms(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	sp := &test.SP

	authnRequest, err := sp.MakeAuthenticationRequest(xhtmlAwkwardURL, HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	logoutRequest, err := sp.MakeLogoutRequest(xhtmlAwkwardURL, "alice")
	assert.NilError(t, err)
	logoutResponse, err := sp.MakeLogoutResponse(xhtmlAwkwardURL, "id-1234")
	assert.NilError(t, err)

	for name, fragment := range map[string][]byte{
		"AuthnRequest":   authnRequest.PostWithNonce(xhtmlAwkwardRelay, "n0nce"),
		"LogoutRequest":  logoutRequest.PostWithNonce(xhtmlAwkwardRelay, "n0nce"),
		"LogoutResponse": logoutResponse.PostWithNonce(xhtmlAwkwardRelay, ""),
	} {
		t.Run(name, func(t *testing.T) {
			assertXHTMLDocument(t, wrapXHTML(fragment))
		})
	}

	for name, tmpl := range map[string]interface {
		Execute(io.Writer, any) error
	}{
		"SimpleSign request":  simpleSignRequestFormTemplate,
		"SimpleSign response": simpleSignResponseFormTemplate,
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			assert.NilError(t, tmpl.Execute(&buf, simpleSignFormData{
				URL:        xhtmlAwkwardURL,
				Message:    "PHNhbWxwOlJlc3BvbnNlLz4+/w==",
				RelayState: xhtmlAwkwardRelay,
				SigAlg:     dsig.RSASHA256SignatureMethod,
				Signature:  "c2lnbmF0dXJl+/w==",
				Nonce:      "n0nce",
			}))
			assertXHTMLDocument(t, wrapXHTML(buf.Bytes()))
		})
	}
}

// signedRedirectSSORequest returns an HTTP-Redirect AuthnRequest to the IdP
// whose query string is signed, with the given Destination.
func signedRedirectSSORequest(t *testing.T, test *IdentityProviderTest, destination string) *http.Request {
	t.Helper()
	test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
	authnRequest, err := test.SP.MakeAuthenticationRequest(destination, HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	redirectURL, err := authnRequest.Redirect("ThisIsTheRelayState", &test.SP)
	assert.NilError(t, err)
	query := redirectURL.Query()
	assert.Check(t, query.Get("SigAlg") != "")
	assert.Check(t, query.Get("Signature") != "")

	u := test.IDP.SSOURL
	u.RawQuery = redirectURL.RawQuery
	r, _ := http.NewRequest("GET", u.String(), nil)
	return r
}

func TestIDPSignedAuthnRequestRequiresDestination(t *testing.T) {
	t.Run("signed redirect without destination is rejected", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, signedRedirectSSORequest(t, test, ""))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("signed redirect with only a SigAlg is rejected", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		r := signedRedirectSSORequest(t, test, "")
		query := r.URL.Query()
		query.Del("Signature")
		r.URL.RawQuery = query.Encode()
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("signed redirect with the SSO URL as destination is accepted", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, signedRedirectSSORequest(t, test, test.IDP.SSOURL.String()))
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
	})

	t.Run("signed redirect with another destination is rejected", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, signedRedirectSSORequest(t, test, "https://other.example.com/saml/sso"))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("unsigned redirect without destination is accepted", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		authnRequest, err := test.SP.MakeAuthenticationRequest("", HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		redirectURL, err := authnRequest.Redirect("ThisIsTheRelayState", &test.SP)
		assert.NilError(t, err)
		assert.Check(t, !redirectURL.Query().Has("Signature"))
		u := test.IDP.SSOURL
		u.RawQuery = redirectURL.RawQuery
		r, _ := http.NewRequest("GET", u.String(), nil)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
	})

	postRequest := func(t *testing.T, test *IdentityProviderTest, destination string) *http.Request {
		t.Helper()
		test.SP.SignatureMethod = dsig.RSASHA256SignatureMethod
		authnRequest, err := test.SP.MakeAuthenticationRequest(destination, HTTPPostBinding, HTTPPostBinding)
		assert.NilError(t, err)
		assert.Check(t, authnRequest.Signature != nil)
		doc := etree.NewDocument()
		doc.SetRoot(authnRequest.Element())
		buf, err := doc.WriteToBytes()
		assert.NilError(t, err)
		form := url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)}, "RelayState": {"ThisIsTheRelayState"}}
		r, _ := http.NewRequest("POST", test.IDP.SSOURL.String(), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}

	t.Run("enveloped signature without destination is rejected", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, postRequest(t, test, ""))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("enveloped signature with the SSO URL as destination is accepted", func(t *testing.T) {
		test := newExistingSessionIDPTest(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, postRequest(t, test, test.IDP.SSOURL.String()))
		assert.Check(t, is.Equal(http.StatusOK, w.Code))
	})
}
