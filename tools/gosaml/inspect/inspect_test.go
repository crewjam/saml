package inspect

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func testdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func deflate(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return buf.Bytes()
}

func section(m *Message, title string) map[string]string {
	for _, s := range m.Sections {
		if s.Title == title {
			out := map[string]string{}
			for _, r := range s.Rows {
				out[r.K] = r.V
			}
			return out
		}
	}
	return nil
}

func hasWarning(m *Message, substr string) bool {
	for _, w := range m.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func only(t *testing.T, r *Result) *Message {
	t.Helper()
	if r.Error != "" {
		t.Fatalf("error: %s", r.Error)
	}
	if len(r.Messages) != 1 {
		t.Fatalf("got %d messages", len(r.Messages))
	}
	if r.Messages[0].Error != "" {
		t.Fatalf("message error: %s", r.Messages[0].Error)
	}
	return r.Messages[0]
}

func TestBase64Response(t *testing.T) {
	r := Parse(testdata(t, "TestSPCanHandleOneloginResponse_response"), now)
	m := only(t, r)
	if r.Input != "base64" || m.Type != "Response" {
		t.Fatalf("input %q type %q", r.Input, m.Type)
	}
	if got := section(m, "Response")["Issuer"]; !strings.Contains(got, "onelogin.com") {
		t.Errorf("issuer = %q", got)
	}
	if section(m, "Subject")["NameID"] == "" {
		t.Error("no NameID")
	}
	if len(section(m, "Attributes")) == 0 {
		t.Error("no attributes")
	}
	if len(m.Signatures) == 0 || len(m.Certificates) == 0 {
		t.Errorf("signatures %d certificates %d", len(m.Signatures), len(m.Certificates))
	}
	if !hasWarning(m, "expired") {
		t.Errorf("expected an expiry warning, got %q", m.Warnings)
	}
}

func TestEncryptedAssertion(t *testing.T) {
	m := only(t, Parse(testdata(t, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_response"), now))
	enc := section(m, "EncryptedAssertion")
	if enc == nil || enc["Data encryption"] == "" {
		t.Fatalf("sections %+v", m.Sections)
	}
}

func TestMetadata(t *testing.T) {
	r := Parse(testdata(t, "TestSPCanHandleOneloginResponse_IDPMetadata"), now)
	m := only(t, r)
	if r.Input != "XML" || m.Type != "EntityDescriptor" {
		t.Fatalf("input %q type %q", r.Input, m.Type)
	}
	if section(m, "IDPSSODescriptor")["SingleSignOnService"] == "" {
		t.Errorf("sections %+v", m.Sections)
	}
}

func TestRedirectURL(t *testing.T) {
	req := testdata(t, "TestIDPCanHandleUnencryptedResponse_request")
	q := url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(deflate(t, req))},
		"RelayState":  {"abc"},
		"SigAlg":      {"http://www.w3.org/2000/09/xmldsig#rsa-sha1"},
		"Signature":   {"AAAA"},
	}
	r := Parse("https://idp.example.com/sso?"+q.Encode(), now)
	m := only(t, r)
	if m.Type != "AuthnRequest" || m.Encoding != "base64+deflate" || m.Parameter != "SAMLRequest" {
		t.Fatalf("type %q encoding %q param %q", m.Type, m.Encoding, m.Parameter)
	}
	if !strings.HasPrefix(r.Binding, "HTTP-Redirect") {
		t.Errorf("binding %q", r.Binding)
	}
	params := map[string]string{}
	for _, p := range r.Params {
		params[p.K] = p.V
	}
	if params["RelayState"] != "abc" || !strings.Contains(params["Warning"], "SHA-1") {
		t.Errorf("params %+v", r.Params)
	}
	if section(m, "Request")["AssertionConsumerServiceURL"] == "" {
		t.Errorf("sections %+v", m.Sections)
	}
}

func TestFormBodyAndHTTPRequest(t *testing.T) {
	resp := testdata(t, "TestSPCanHandleOneloginResponse_response")
	body := url.Values{"SAMLResponse": {resp}, "RelayState": {"xyz"}}.Encode()

	r := Parse(body, now)
	if m := only(t, r); m.Type != "Response" || r.Binding != "HTTP-POST" {
		t.Fatalf("type %q binding %q", m.Type, r.Binding)
	}

	raw := "POST /saml/acs HTTP/1.1\nHost: sp.example.com\nContent-Type: application/x-www-form-urlencoded\n\n" + body
	r = Parse(raw, now)
	if m := only(t, r); m.Type != "Response" || r.Input != "HTTP request" {
		t.Fatalf("type %q input %q", m.Type, r.Input)
	}
}

func TestArtifact(t *testing.T) {
	raw := make([]byte, 44)
	raw[1] = 4
	art := base64.StdEncoding.EncodeToString(raw)
	r := Parse("https://sp.example.com/acs?SAMLart="+url.QueryEscape(art), now)
	m := only(t, r)
	if m.Type != "Artifact" || r.Binding != "HTTP-Artifact" {
		t.Fatalf("type %q binding %q", m.Type, r.Binding)
	}
	if section(m, "Artifact")["TypeCode"] != "0x0004" {
		t.Errorf("sections %+v", m.Sections)
	}
}

func TestGarbage(t *testing.T) {
	for _, in := range []string{"", "not base64 !!!", "aGVsbG8gd29ybGQ=", "<unclosed"} {
		r := Parse(in, now)
		if r.Error == "" && (len(r.Messages) == 0 || r.Messages[0].Error == "") {
			t.Errorf("%q: expected an error", in)
		}
	}
}

func TestDecodeBase64Message(t *testing.T) {
	xml := "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>"
	for _, enc := range []string{
		base64.StdEncoding.EncodeToString([]byte(xml)),
		base64.StdEncoding.EncodeToString(deflate(t, xml)),
	} {
		got, err := DecodeBase64Message(enc)
		if err != nil || string(got) != xml {
			t.Errorf("got %q, %v", got, err)
		}
	}
}

func TestView(t *testing.T) {
	m := only(t, Parse(testdata(t, "TestSPCanHandleOneloginResponse_response"), now))
	v := m.View
	if v == nil || v.Title != "Response" || !strings.Contains(v.Sub, "base64") || !strings.HasSuffix(v.Sub, "KB") {
		t.Fatalf("%+v", v)
	}
	var texts []string
	for _, c := range v.Checks {
		texts = append(texts, c.Level+":"+c.Text)
	}
	if !strings.Contains(strings.Join(texts, ","), "ok:Status Success") {
		t.Errorf("checks %v", texts)
	}
	var sawTime, sawMono bool
	for _, g := range v.Groups {
		for _, r := range g.Rows {
			sawTime = sawTime || (r.K == "IssueInstant" && r.Time && !r.Mono)
			sawMono = sawMono || (r.K == "Issuer" && r.Mono)
		}
	}
	if !sawTime || !sawMono {
		t.Errorf("time %v mono %v", sawTime, sawMono)
	}
	// The tokens add up to the XML.
	var b strings.Builder
	kinds := map[string]bool{}
	for _, tok := range v.XML {
		b.WriteString(tok.Text)
		kinds[tok.Kind] = true
	}
	if b.String() != m.XML || !kinds["tag"] || !kinds["attr"] || !kinds["val"] {
		t.Errorf("tokens do not add up (%v)", kinds)
	}
}

func TestHighlightXMLMalformed(t *testing.T) {
	for _, in := range []string{"<a b='>' c=\"d\">x</a>", "<unclosed", "text only", "<!-- c --><x/>", "<a\nb=\"1\"/>"} {
		var b strings.Builder
		for _, tok := range HighlightXML(in) {
			b.WriteString(tok.Text)
		}
		if b.String() != in {
			t.Errorf("%q -> %q", in, b.String())
		}
	}
}
