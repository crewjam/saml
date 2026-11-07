package saml

import (
	"runtime"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

// The well-formedness check runs on every message before its signature is
// checked. It used to allocate a new encoder and decoder for every token,
// about 2,500 bytes for each byte of a response made of empty elements, so
// a few megabytes of unsigned XML cost gigabytes of allocation. Parsing a
// response must allocate a bounded multiple of its size.
func TestParseXMLResponseAllocationsBoundedByInputSize(t *testing.T) {
	const maxBytesPerInputByte = 500
	e := spcovSetup(t)
	buf := []byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" Version="2.0">` +
		strings.Repeat("<a/>", 50000) + `</samlp:Response>`)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	runtime.ReadMemStats(&after)
	assert.Assert(t, err != nil) // the response is not signed

	perByte := float64(after.TotalAlloc-before.TotalAlloc) / float64(len(buf))
	assert.Check(t, perByte < maxBytesPerInputByte, "allocated %.0f bytes per input byte", perByte)
}
