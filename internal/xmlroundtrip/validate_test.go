package xmlroundtrip

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestValidateAcceptsStableDocuments(t *testing.T) {
	for _, doc := range []string{
		`<Root></Root>`,
		`<x:Root></x:Root>`,
		`<x:Root xmlns:x="http://example.com/"></x:Root>`,
		`<x:Root xmlns="http://example.com/"></x:Root>`,
		`<?xml version="1.0" encoding="EUC-JP"?><Root></Root>`,
		`<Root>text &quot;hello&quot;</Root>`,
		`<Root><![CDATA[text "hello"]]></Root>`,
		`<!-- comment --><Root/>`,
		`<Root xmlns="http://example.com/1" x:attr="y"/>`,
		`<x:Root xmlns="http://example.com/1" x:attr="y" x:attr2="z"/>`,
		`<x:Root xmlns:x="http://example.com/"><Element xmlns:x="http://example.com/"/></x:Root>`,
		`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">`,
		`<!name <!-- comment --><nesting <more nesting>>>`,
		`<a>x</a>y<b/>z`,
		`<?pi data?><a/>`,
		``,
	} {
		assert.Check(t, Validate([]byte(doc)), "%s", doc)
	}
}

// The constructs behind CVE-2020-29509, CVE-2020-29510 and CVE-2020-29511
// (names with extra colons, empty prefixes or local names, directives
// containing comments) are either syntax errors or round-trip unchanged in
// the Go versions this module supports. What Validate still rejects is a
// token that encoding/xml reads leniently but cannot write back, or writes
// back as something else.
func TestValidateRejectsUnstableTokens(t *testing.T) {
	for _, tc := range []struct {
		doc          string
		line, column int64
	}{
		{"<a><!>DOCTYPE a=></a>", 1, 4}, // the encoder refuses the directive
		{"<a>\n  </b:--d></a>", 2, 3},   // re-decoding refuses the name
		{"<a><![CDATA[]]></a>", 1, 4},   // empty character data encodes to nothing
		{"<a>\n<b>\n<![CDATA[]]></b></a>", 3, 1},
	} {
		err := Validate([]byte(tc.doc))
		var rtErr *Error
		if !assert.Check(t, errors.As(err, &rtErr), "%s: %v", tc.doc, err) {
			continue
		}
		assert.Check(t, is.Equal(rtErr.Line, tc.line), tc.doc)
		assert.Check(t, is.Equal(rtErr.Column, tc.column), tc.doc)
	}
}

func TestValidateRejectsMalformedDocuments(t *testing.T) {
	for _, doc := range []string{`<x::Root/>`, `<a:b:c/>`, `<Root><!--`, `<Root>]]></Root>`, `<a><!--x--y--></a>`} {
		assert.Check(t, Validate([]byte(doc)) != nil, doc)
	}
}

// Validate used to allocate a new encoder and decoder, with 4 KiB buffers,
// for every token: about 2,500 bytes for every byte of input made of empty
// elements. It runs on untrusted input before any signature is checked, so
// the memory it allocates must stay a small multiple of the input size.
func TestValidateAllocationsBoundedByInputSize(t *testing.T) {
	const maxBytesPerInputByte = 300
	for name, doc := range map[string]string{
		"empty elements": "<r>" + strings.Repeat("<a/>", 50000) + "</r>",
		"elements":       "<r>" + strings.Repeat("<a>x</a>", 50000) + "</r>",
		"attributes":     "<r>" + strings.Repeat(`<s:a xmlns:s="u" s:b="c" d="e"/>`, 10000) + "</r>",
		"comments":       "<r>" + strings.Repeat("<!---->", 50000) + "</r>",
		"directives":     strings.Repeat("<!a>", 50000) + "<r/>",
		"text":           "<r>" + strings.Repeat("x", 200000) + "</r>",
	} {
		t.Run(name, func(t *testing.T) {
			data := []byte(doc)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			assert.NilError(t, Validate(data))
			runtime.ReadMemStats(&after)
			perByte := float64(after.TotalAlloc-before.TotalAlloc) / float64(len(data))
			assert.Check(t, perByte < maxBytesPerInputByte, "allocated %.0f bytes per input byte", perByte)
		})
	}
}

func BenchmarkValidate(b *testing.B) {
	data := []byte("<r>" + strings.Repeat(`<a b="c">x</a>`, 10000) + "</r>")
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		if err := Validate(data); err != nil {
			b.Fatal(err)
		}
	}
}
