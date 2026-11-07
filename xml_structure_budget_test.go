package saml

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// replayedSignatureResponse returns an unsigned Response holding an
// assertion that was validly signed and then given decls namespace
// declarations and elements empty Advice elements. The SignedInfo signature
// still verifies, so the body is canonicalized before the digest fails.
func replayedSignatureResponse(t *testing.T, e *spcovEnv, decls, elements int) []byte {
	t.Helper()
	var b strings.Builder
	for i := 0; i < decls; i++ {
		fmt.Fprintf(&b, ` xmlns:p%d="urn:p%d"`, i, i)
	}
	assertion := string(spcovSerialize(t, e.idpSign(t, e.assertion().Element())))
	assertion = strings.Replace(assertion, "<saml:Assertion ", "<saml:Assertion"+b.String()+" ", 1)
	assertion = strings.Replace(assertion, "</saml:Assertion>", strings.Repeat("<saml:Advice/>", elements)+"</saml:Assertion>", 1)
	return []byte(responseOpen + ">" + responseStatus + assertion + "</samlp:Response>")
}

func parseXMLResponseCost(t *testing.T, e *spcovEnv, buf []byte) (float64, time.Duration, error) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	assert.Assert(t, err != nil)
	return float64(after.TotalAlloc-before.TotalAlloc) / float64(len(buf)), elapsed, spcovPrivateErr(t, err)
}

// A validly signed assertion replayed over a body of many namespace
// declarations and elements cost time and memory quadratic in its size
// (78 KB: 0.3 s and 4,300 bytes per input byte, doubling with each doubling
// of the input) before the digest check failed. Too many declarations in
// scope are now refused before any signature work.
func TestReplayedSignatureWithManyNamespacesRefusedBeforeCanonicalization(t *testing.T) {
	e := spcovSetup(t)
	buf := replayedSignatureResponse(t, e, 1000, 4000)
	perByte, _, err := parseXMLResponseCost(t, e, buf)
	assert.Check(t, errors.Is(err, xmlroundtrip.ErrTooManyNamespaces), "%v", err)
	assert.Check(t, perByte < 100, "allocated %.0f bytes per input byte", perByte)
}

// Within the limit, the cost of the same attack grows linearly.
func TestReplayedSignatureCostBoundedWithinNamespaceLimit(t *testing.T) {
	e := spcovSetup(t)
	buf := replayedSignatureResponse(t, e, xmlroundtrip.MaxNamespacesInScope-8, 20000)
	perByte, elapsed, err := parseXMLResponseCost(t, e, buf)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)
	t.Logf("size %d KB, %v, %.0f bytes per input byte", len(buf)/1024, elapsed, perByte)
	assert.Check(t, perByte < 2000, "allocated %.0f bytes per input byte", perByte)
}

func TestDeeplyNestedResponseRefused(t *testing.T) {
	e := spcovSetup(t)
	buf := []byte(responseOpen + ">" + strings.Repeat("<a>", xmlroundtrip.MaxDepth) + strings.Repeat("</a>", xmlroundtrip.MaxDepth) + "</samlp:Response>")
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, xmlroundtrip.ErrTooDeep), "%v", err)
}
