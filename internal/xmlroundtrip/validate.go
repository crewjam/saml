// Package xmlroundtrip rejects XML documents that encoding/xml would change
// if it decoded and re-encoded them.
//
// Go's encoding/xml does not round-trip some namespace prefixes on elements
// and attributes, or some directives, unchanged (CVE-2020-29509,
// CVE-2020-29510, CVE-2020-29511). This package rejects any document with
// a token that is not stable under such a round trip. It makes the same
// check as github.com/mattermost/xml-roundtrip-validator, but without
// allocating a new encoder and decoder for every token, so the memory it
// allocates is a small multiple of the size of its input.
package xmlroundtrip

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

// Error reports the token of a document that does not survive a round
// trip, or that could not be checked.
type Error struct {
	// Line and Column give the position (1-based) of the start of the token.
	Line, Column int64
	Err          error
}

func (e *Error) Error() string {
	return fmt.Sprintf("xml: in token starting at %d:%d: %s", e.Line, e.Column, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// RoundTripError reports a token that encoding/xml decodes differently
// after encoding it.
type RoundTripError struct {
	Expected, Observed xml.Token
}

func (e *RoundTripError) Error() string {
	return fmt.Sprintf("roundtrip error: expected %v, observed %v", e.Expected, e.Observed)
}

// errOverflow is returned when the encoded form of a token decodes to a
// token followed by more input.
var errOverflow = errors.New("roundtrip error: unexpected input after token")

// sentinel follows the encoding of a CharData token. The decoder reads
// character data up to the next '<', so without it the decoder would reach
// the end of its input, which it treats as a permanent error. Every other
// token ends with a '>' after which the decoder reads nothing more.
var sentinel = []byte("<_/>")

// MaxDepth is the deepest nesting of elements Validate accepts. SAML
// messages and metadata nest a dozen or so levels.
const MaxDepth = 64

// MaxNamespacesInScope is the largest number of namespace declarations
// Validate accepts in scope at any element. SAML messages and metadata have
// about ten.
//
// What a document costs to canonicalize and namespace-resolve grows with the
// number of elements times the declarations in scope at each, and that work
// happens before the digest of a signed element is checked: with a validly
// signed element replayed over a body of thousands of declarations and
// elements, a few tens of kilobytes cost seconds and gigabytes. Declarations
// repeated on sibling elements (xmlns:xs on every AttributeValue, say) do
// not add up, so the limit is on those in scope, not on the total.
const MaxNamespacesInScope = 64

// ErrTooDeep and ErrTooManyNamespaces report a document over MaxDepth or
// MaxNamespacesInScope.
var (
	ErrTooDeep           = fmt.Errorf("xml: elements nested more than %d deep", MaxDepth)
	ErrTooManyNamespaces = fmt.Errorf("xml: more than %d namespace declarations in scope", MaxNamespacesInScope)
)

// Validate returns an error if any token of data does not survive a round
// trip through encoding/xml unchanged, or if data nests elements more than
// MaxDepth deep or has more than MaxNamespacesInScope namespace
// declarations in scope at an element. It does not check that data is
// well-formed beyond what encoding/xml's tokenizer requires.
func Validate(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = false
	decoder.CharsetReader = identityCharsetReader

	c := newChecker()
	offset := int64(0)
	// declared holds, for each open element, the number of namespaces it
	// declares; inScope is their sum.
	var declared []int
	inScope := 0
	for {
		token, err := decoder.RawToken()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := token.(type) {
		case xml.StartElement:
			n := 0
			for _, attr := range t.Attr {
				if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
					n++
				}
			}
			declared = append(declared, n)
			inScope += n
			if len(declared) > MaxDepth {
				err = ErrTooDeep
			} else if inScope > MaxNamespacesInScope {
				err = ErrTooManyNamespaces
			}
		case xml.EndElement:
			// The decoder is not strict, so an end tag may close nothing.
			if len(declared) > 0 {
				inScope -= declared[len(declared)-1]
				declared = declared[:len(declared)-1]
			}
		}
		if err == nil {
			err = c.check(token)
		}
		if err != nil {
			line := int64(bytes.Count(data[:offset], []byte{'\n'})) + 1
			column := offset - int64(bytes.LastIndexByte(data[:offset], '\n'))
			return &Error{Line: line, Column: column, Err: err}
		}
		offset = decoder.InputOffset()
	}
}

func identityCharsetReader(_ string, input io.Reader) (io.Reader, error) {
	return input, nil
}

// checker encodes a token and decodes it again, reusing its buffers and
// decoder from one token to the next.
type checker struct {
	encoded bytes.Buffer
	writer  *bufio.Writer

	// input feeds the encoded tokens to decoder.
	input   feed
	decoder *xml.Decoder
}

func newChecker() *checker {
	c := &checker{}
	c.writer = bufio.NewWriter(&c.encoded)
	c.decoder = xml.NewDecoder(&c.input)
	c.decoder.CharsetReader = identityCharsetReader
	return c
}

// check reports whether before decodes to the same token after encoding.
func (c *checker) check(before xml.Token) error {
	// A new Encoder for every token, so no namespace prefix or other state
	// carries over from one token to the next. xml.NewEncoder reuses
	// c.writer rather than allocating a buffer of its own.
	c.encoded.Reset()
	encoder := xml.NewEncoder(c.writer)
	end, isEnd := before.(xml.EndElement)
	if isEnd {
		// xml.Encoder only encodes an EndElement that closes a StartElement.
		if err := encoder.EncodeToken(xml.StartElement{Name: end.Name}); err != nil {
			return err
		}
	}
	if err := encoder.EncodeToken(before); err != nil {
		return err
	}
	if err := encoder.Flush(); err != nil {
		return err
	}

	_, isCharData := before.(xml.CharData)
	if isCharData {
		c.input.reset(c.encoded.Bytes(), sentinel)
	} else {
		c.input.reset(c.encoded.Bytes(), nil)
	}
	encodedLen := int64(c.encoded.Len())
	start := c.decoder.InputOffset()
	if isEnd {
		if _, err := c.decoder.RawToken(); err != nil {
			return err
		}
	}
	after, err := c.decoder.RawToken()
	if err != nil {
		return err
	}
	if !tokensEqual(before, after) {
		return &RoundTripError{Expected: xml.CopyToken(before), Observed: xml.CopyToken(after)}
	}
	if c.decoder.InputOffset()-start != encodedLen {
		return errOverflow
	}

	if !isCharData {
		return nil
	}
	// Read the sentinel, leaving the decoder at the end of its input.
	for _, want := range []xml.Token{xml.StartElement{}, xml.EndElement{}} {
		tok, err := c.decoder.RawToken()
		if err != nil {
			return err
		}
		if !isSentinel(tok, want) {
			return errOverflow
		}
	}
	return nil
}

func isSentinel(tok, want xml.Token) bool {
	name := xml.Name{Local: "_"}
	switch tok := tok.(type) {
	case xml.StartElement:
		_, ok := want.(xml.StartElement)
		return ok && tok.Name == name && len(tok.Attr) == 0
	case xml.EndElement:
		_, ok := want.(xml.EndElement)
		return ok && tok.Name == name
	}
	return false
}

// feed is an io.Reader and io.ByteReader over the encoded token and the
// sentinel. Being an io.ByteReader, it is read without buffering, so the
// decoder reads no further than the end of the sentinel.
type feed struct {
	buf []byte
	off int
}

func (f *feed) reset(token, sentinel []byte) {
	f.buf = append(append(f.buf[:0], token...), sentinel...)
	f.off = 0
}

func (f *feed) ReadByte() (byte, error) {
	if f.off >= len(f.buf) {
		return 0, io.EOF
	}
	b := f.buf[f.off]
	f.off++
	return b, nil
}

func (f *feed) Read(p []byte) (int, error) {
	if f.off >= len(f.buf) {
		return 0, io.EOF
	}
	n := copy(p, f.buf[f.off:])
	f.off += n
	return n, nil
}

// tokensEqual reports whether after, the result of encoding and decoding
// before, is the same token.
func tokensEqual(before, after xml.Token) bool {
	switch b := before.(type) {
	case xml.CharData:
		a, ok := after.(xml.CharData)
		return ok && bytes.Equal(b, a)
	case xml.Comment:
		a, ok := after.(xml.Comment)
		return ok && bytes.Equal(b, a)
	case xml.Directive:
		a, ok := after.(xml.Directive)
		return ok && bytes.Equal(b, a)
	case xml.ProcInst:
		a, ok := after.(xml.ProcInst)
		return ok && b.Target == a.Target && bytes.Equal(b.Inst, a.Inst)
	case xml.EndElement:
		a, ok := after.(xml.EndElement)
		// The encoder writes a prefixed name with a default namespace
		// declaration instead, so the end tag loses the prefix.
		return ok && a.Name.Local == b.Name.Local && a.Name.Space == ""
	case xml.StartElement:
		a, ok := after.(xml.StartElement)
		if !ok {
			return false
		}
		a = undoEncoderNamespaces(b, a)
		if a.Name != b.Name || len(a.Attr) != len(b.Attr) {
			return false
		}
		for i := range a.Attr {
			if a.Attr[i] != b.Attr[i] {
				return false
			}
		}
		return true
	}
	return false
}

// undoEncoderNamespaces undoes, in after, the namespace declarations that
// xml.Encoder adds when it encodes before.
//
// RawToken leaves a prefix in Name.Space, which the encoder treats as a
// namespace URI: it writes a prefixed element name as the local name with
// a default namespace declaration (xmlns="prefix") as its first attribute,
// and a prefixed attribute name with a generated prefix declared
// (xmlns:gen="prefix") just before the attribute. Mapping these back gives
// the names before had, if the token is stable.
func undoEncoderNamespaces(before, after xml.StartElement) xml.StartElement {
	if len(after.Attr) <= len(before.Attr) {
		return after
	}
	attrs := make([]xml.Attr, len(after.Attr))
	copy(attrs, after.Attr)

	if before.Name.Space != "" && after.Name.Space == "" && len(attrs) > 0 && attrs[0].Name == (xml.Name{Local: "xmlns"}) {
		after.Name.Space = attrs[0].Value
		attrs = attrs[1:]
	}

	for len(attrs) > len(before.Attr) && len(attrs) > 1 {
		i := 1
		for ; i < len(attrs); i++ {
			if attrs[i-1].Name.Space == "xmlns" && attrs[i-1].Name.Local == attrs[i].Name.Space {
				break
			}
		}
		if i == len(attrs) {
			break
		}
		prefix, uri := attrs[i-1].Name.Local, attrs[i-1].Value
		attrs = append(attrs[:i-1], attrs[i:]...)
		for j := range attrs {
			if attrs[j].Name.Space == prefix {
				attrs[j].Name.Space = uri
			}
		}
	}
	after.Attr = attrs
	return after
}
