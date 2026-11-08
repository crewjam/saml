// Package inspect decodes SAML messages from whatever form a user has at
// hand: a redirect URL, a POST body, a raw HTTP request, base64 (deflated
// or not) or plain XML. It reports what the message says, how it is
// signed, and what in it looks wrong.
//
// It verifies nothing: it describes a message, so that a person can read
// it. It is compiled to WebAssembly and run in the browser, so that the
// messages people paste never leave their machine, and is also used by the
// server to log the messages its test IdPs and SPs exchange.
package inspect

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// MaxDecodedSize is the largest message, after decoding and
// decompressing, that Parse reads. It matches the limit package saml
// applies to the HTTP-Redirect binding.
const MaxDecodedSize = 1 << 20

// Result is what Parse found in its input.
type Result struct {
	// Input describes the form the input was in, such as
	// "HTTP-Redirect URL" or "base64".
	Input string `json:"input"`

	// Binding is the SAML binding the input appears to use, if it can be
	// told.
	Binding string `json:"binding,omitempty"`

	// Params are the binding parameters other than the message itself,
	// such as RelayState, SigAlg and Signature.
	Params []KV `json:"params,omitempty"`

	// Messages are the SAML messages found: usually one.
	Messages []*Message `json:"messages"`

	// Error, if not empty, says why nothing could be decoded.
	Error string `json:"error,omitempty"`
}

// Message is one decoded SAML message, artifact or metadata document.
type Message struct {
	// Parameter is the binding parameter it came from, such as
	// "SAMLRequest", or "" for XML given directly.
	Parameter string `json:"parameter,omitempty"`

	// Encoding is how it was encoded: "base64+deflate", "base64" or
	// "xml".
	Encoding string `json:"encoding"`

	// Type is the local name of the root element, such as "Response" or
	// "EntityDescriptor", or "Artifact".
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`

	// XML is the message, indented for reading. Indenting changes the
	// whitespace, so it would not verify: it is for display only.
	XML string `json:"xml,omitempty"`

	Sections     []Section      `json:"sections,omitempty"`
	Signatures   []Signature    `json:"signatures,omitempty"`
	Certificates []*Certificate `json:"certificates,omitempty"`

	// Warnings are things about the message that a relying party would
	// likely refuse, or that are commonly the cause of a failed login.
	Warnings []string `json:"warnings,omitempty"`

	// Error, if not empty, says why the message could not be read fully.
	Error string `json:"error,omitempty"`
}

// Section is a titled group of facts about a message.
type Section struct {
	Title string `json:"title"`
	Rows  []KV   `json:"rows"`
}

// KV is a labelled value.
type KV struct {
	K string `json:"k"`
	V string `json:"v"`
}

var httpRequestLine = regexp.MustCompile(`^(GET|POST|PUT) (\S+) HTTP/\d(\.\d)?$`)

// Parse decodes the SAML message(s) in input. now is used to say whether
// times in the message have passed.
func Parse(input string, now time.Time) *Result {
	input = strings.TrimSpace(strings.TrimPrefix(input, "\ufeff"))
	res := &Result{Messages: []*Message{}}
	if input == "" {
		res.Error = "nothing to decode"
		return res
	}

	switch {
	case strings.HasPrefix(input, "<"):
		res.Input = "XML"
		res.Messages = append(res.Messages, parseXML([]byte(input), "", "xml", now))
		return res

	case httpRequestLine.MatchString(firstLine(input)):
		return parseHTTPRequest(input, now)

	case looksLikeURL(input):
		u, err := url.Parse(input)
		if err == nil && u.RawQuery != "" {
			res.Input = "URL"
			parseValues(res, u.Query(), true, now)
			if len(res.Messages) > 0 {
				return res
			}
		}

	case strings.Contains(input, "SAMLRequest=") || strings.Contains(input, "SAMLResponse=") || strings.Contains(input, "SAMLart="):
		v, err := url.ParseQuery(strings.TrimPrefix(input, "?"))
		if err == nil {
			// A query string copied from a redirect is deflated; a form
			// body is not. decode tries both, so the source matters only
			// for the label.
			res.Input = "query string or form body"
			parseValues(res, v, strings.HasPrefix(input, "?"), now)
			if len(res.Messages) > 0 {
				return res
			}
		}
	}

	// Anything else: a bare base64 value, possibly URL-encoded.
	value := input
	if strings.Contains(value, "%") {
		if u, err := url.QueryUnescape(value); err == nil {
			value = u
		}
	}
	msg := decodeValue("", value, now)
	res.Input = "base64"
	if msg.Encoding == "base64+deflate" {
		res.Input = "base64 (deflated)"
	}
	res.Messages = append(res.Messages, msg)
	return res
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return strings.TrimSpace(line)
}

func looksLikeURL(s string) bool {
	return !strings.ContainsAny(s, " \n\t") && (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://"))
}

// parseHTTPRequest reads a raw HTTP request, as copied from a browser's
// developer tools or a proxy.
func parseHTTPRequest(input string, now time.Time) *Result {
	res := &Result{Messages: []*Message{}, Input: "HTTP request"}
	// Accept bare LF line endings, as text copied from a page has, and a
	// body without a Content-Length: split the head from the body here.
	normalized := strings.ReplaceAll(input, "\r\n", "\n")
	head, rest, _ := strings.Cut(normalized, "\n\n")
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(strings.ReplaceAll(head, "\n", "\r\n") + "\r\n\r\n")))
	if err != nil {
		res.Error = "cannot read the HTTP request: " + err.Error()
		return res
	}
	body := []byte(strings.TrimSpace(rest))
	if len(body) > MaxDecodedSize {
		body = body[:MaxDecodedSize]
	}
	if req.URL.RawQuery != "" {
		parseValues(res, req.URL.Query(), true, now)
	}
	if len(body) > 0 {
		if bytes.HasPrefix(body, []byte("<")) {
			// SOAP, as for artifact resolution or back-channel logout.
			res.Binding = "SOAP"
			res.Messages = append(res.Messages, parseXML(body, "", "xml", now))
		} else if v, err := url.ParseQuery(string(body)); err == nil {
			parseValues(res, v, false, now)
		}
	}
	if len(res.Messages) == 0 && res.Error == "" {
		res.Error = "the request carries no SAMLRequest, SAMLResponse or SAMLart"
	}
	return res
}

// parseValues decodes the SAML parameters of a query string or form body.
// redirect says whether they came from a URL, where the message is
// deflated (HTTP-Redirect) and the signature, if any, is in the query.
func parseValues(res *Result, v url.Values, redirect bool, now time.Time) {
	for _, p := range []string{"RelayState", "SigAlg", "Signature", "KeyInfo"} {
		if val := v.Get(p); val != "" {
			res.Params = append(res.Params, KV{p, val})
		}
	}
	if sigAlg := v.Get("SigAlg"); sigAlg != "" {
		if weak := weakAlgorithm(sigAlg); weak != "" {
			res.Params = append(res.Params, KV{"Warning", "SigAlg uses " + weak})
		}
	}
	if rs := v.Get("RelayState"); len(rs) > 80 {
		res.Params = append(res.Params, KV{"Warning", fmt.Sprintf("RelayState is %d bytes; the bindings allow 80 (saml-bindings §3.4.3)", len(rs))})
	}

	for _, p := range []string{"SAMLRequest", "SAMLResponse"} {
		val := v.Get(p)
		if val == "" {
			continue
		}
		msg := decodeValue(p, val, now)
		switch {
		case redirect && v.Get("SigAlg") != "":
			res.Binding = "HTTP-Redirect (signed in the query string)"
		case redirect:
			res.Binding = "HTTP-Redirect"
		case v.Get("SigAlg") != "":
			res.Binding = "HTTP-POST-SimpleSign"
		default:
			res.Binding = "HTTP-POST"
		}
		if redirect && msg.Encoding == "base64" && msg.Error == "" {
			msg.Warnings = append(msg.Warnings, "this message came in a URL but is not deflated; the HTTP-Redirect binding requires DEFLATE (saml-bindings §3.4.4.1)")
		}
		if !redirect && msg.Encoding == "base64+deflate" {
			msg.Warnings = append(msg.Warnings, "this message is deflated, which the HTTP-POST binding does not use (saml-bindings §3.5.4)")
		}
		res.Messages = append(res.Messages, msg)
	}
	if art := v.Get("SAMLart"); art != "" {
		res.Binding = "HTTP-Artifact"
		res.Messages = append(res.Messages, parseArtifact(art))
	}
}

// decodeValue decodes a base64 binding parameter, inflating it if it is
// deflated.
func decodeValue(param, value string, now time.Time) *Message {
	raw, err := decodeBase64(value)
	if err != nil {
		return &Message{Parameter: param, Encoding: "base64", Type: "unknown", Error: "not valid base64: " + err.Error()}
	}
	if len(raw) > MaxDecodedSize {
		return &Message{Parameter: param, Encoding: "base64", Type: "unknown", Error: "the message is larger than 1 MiB"}
	}
	if looksLikeXML(raw) {
		return parseXML(raw, param, "base64", now)
	}
	inflated, err := Inflate(raw)
	if err != nil {
		if len(raw) == 44 && raw[0] == 0 && raw[1] == 4 {
			return parseArtifact(value)
		}
		return &Message{Parameter: param, Encoding: "base64", Type: "unknown",
			Error: "decoded base64 is neither XML nor DEFLATE-compressed XML: " + err.Error()}
	}
	if !looksLikeXML(inflated) {
		return &Message{Parameter: param, Encoding: "base64+deflate", Type: "unknown", Error: "inflated data is not XML"}
	}
	return parseXML(inflated, param, "base64+deflate", now)
}

// DecodeBase64Message decodes a binding parameter as the server receives
// it, inflating it if it is deflated, and returns the XML.
func DecodeBase64Message(value string) ([]byte, error) {
	raw, err := decodeBase64(value)
	if err != nil {
		return nil, err
	}
	if looksLikeXML(raw) {
		return raw, nil
	}
	return Inflate(raw)
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	// Accept the URL-safe alphabet and missing padding, which tools that
	// copy values out of URLs sometimes produce.
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	s = strings.TrimRight(s, "=")
	return base64.RawStdEncoding.DecodeString(s)
}

// Inflate decompresses raw DEFLATE data, as the HTTP-Redirect binding
// uses, up to MaxDecodedSize.
func Inflate(raw []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(raw))
	defer r.Close() //nolint:errcheck // a flate reader over a bytes.Reader has nothing to report
	out, err := io.ReadAll(io.LimitReader(r, MaxDecodedSize+1))
	if err != nil {
		return nil, err
	}
	if len(out) > MaxDecodedSize {
		return nil, errors.New("inflated message is larger than 1 MiB")
	}
	return out, nil
}

func looksLikeXML(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && b[0] == '<'
}

// Pretty indents XML for reading. If doc is not well-formed it is
// returned unchanged.
func Pretty(doc []byte) string {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		return string(doc)
	}
	d.Indent(2)
	s, err := d.WriteToString()
	if err != nil {
		return string(doc)
	}
	return s
}

// parseArtifact describes a SAML 2.0 artifact (saml-bindings §3.6.4):
// it holds no message, only where to resolve one.
func parseArtifact(value string) *Message {
	msg := &Message{Parameter: "SAMLart", Encoding: "base64", Type: "Artifact"}
	raw, err := decodeBase64(value)
	if err != nil {
		msg.Error = "not valid base64: " + err.Error()
		return msg
	}
	rows := []KV{{"Length", fmt.Sprintf("%d bytes", len(raw))}}
	if len(raw) >= 4 {
		rows = append(rows,
			KV{"TypeCode", fmt.Sprintf("0x%04x", int(raw[0])<<8|int(raw[1]))},
			KV{"EndpointIndex", fmt.Sprintf("%d", int(raw[2])<<8|int(raw[3]))})
	}
	if len(raw) == 44 {
		rows = append(rows,
			KV{"SourceID", hex.EncodeToString(raw[4:24]) + " (SHA-1 of the issuer's entity ID)"},
			KV{"MessageHandle", hex.EncodeToString(raw[24:44])})
	}
	if len(raw) != 44 || raw[0] != 0 || raw[1] != 4 {
		msg.Warnings = append(msg.Warnings, "not a type 0x0004 artifact of 44 bytes, the only type SAML 2.0 defines")
	}
	msg.Sections = []Section{{Title: "Artifact", Rows: rows}}
	msg.Warnings = append(msg.Warnings, "an artifact is a reference: the message itself must be fetched from the issuer's ArtifactResolutionService with an ArtifactResolve request")
	return msg
}
