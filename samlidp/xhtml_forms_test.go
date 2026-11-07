package samlidp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const xhtmlNamespace = "http://www.w3.org/1999/xhtml"

// assertXHTMLDocument checks that page is a well-formed XML document whose
// root is an XHTML html element holding a head with a title and a body
// (saml-bindings-2.0-os §3.5.4: "The HTML document MUST adhere to the XHTML
// specification").
func assertXHTMLDocument(t *testing.T, page []byte) {
	t.Helper()
	d := xml.NewDecoder(bytes.NewReader(page))
	d.Strict = true

	var path []string
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
			path = append(path, tok.Name.Local)
			seen[strings.Join(path, "/")] = true
		case xml.EndElement:
			path = path[:len(path)-1]
		}
	}
	assert.Check(t, is.Equal(1, roots))
	assert.Check(t, seen["html/head/title"], "page has no html/head/title")
	assert.Check(t, seen["html/body"], "page has no html/body")
}

func TestXHTMLLoginForm(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	w := covServe(s, "GET", "/login", "")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assertXHTMLDocument(t, w.Body.Bytes())

	var buf bytes.Buffer
	assert.NilError(t, defaultLoginFormTemplate.Execute(&buf, struct {
		Toast       string
		URL         string
		SAMLRequest string
		RelayState  string
	}{
		Toast:       `<bad> & "toast"`,
		URL:         "https://idp.example.com/sso?a=1&b=<2>",
		SAMLRequest: "PHNhbWxwOkF1dGhuUmVxdWVzdC8+/w==",
		RelayState:  `<relay> & "state" 'x'`,
	}))
	assertXHTMLDocument(t, buf.Bytes())
}

func TestXHTMLLogoutPage(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	w := covServe(s, "GET", "/logout", "")
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assertXHTMLDocument(t, w.Body.Bytes())
}
