package saml

import (
	"math"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// TestDurationUnmarshalOutOfRange checks that a duration too large for a
// time.Duration is refused rather than wrapped around to a small or
// negative value.
func TestDurationUnmarshalOutOfRange(t *testing.T) {
	for _, in := range []string{
		"P300Y",
		"-P300Y",
		"PT99999999999S",
		"PT2562048H",
		"P106751DT23H47M16.854775808S", // MaxInt64 + 1ns
		"P99999999999999999999Y",       // does not fit in a uint64
	} {
		t.Run(in, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalText([]byte(in))
			assert.Check(t, is.ErrorContains(err, "invalid duration"))
		})
	}
}

// TestDurationUnmarshalExactSeconds checks that fractional seconds are read
// exactly rather than through a float.
func TestDurationUnmarshalExactSeconds(t *testing.T) {
	var d Duration
	assert.NilError(t, d.UnmarshalText([]byte("PT1.005S")))
	assert.Check(t, is.Equal(time.Duration(d), time.Second+5*time.Millisecond))

	text, err := d.MarshalText()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(text), "PT1.005S"))
}

// TestDurationExtremesRoundTrip checks that the largest and smallest
// durations are written in a form that reads back as the same value.
func TestDurationExtremesRoundTrip(t *testing.T) {
	for _, in := range []Duration{math.MaxInt64, math.MinInt64, math.MinInt64 + 1} {
		text, err := in.MarshalText()
		assert.NilError(t, err)
		var out Duration
		assert.NilError(t, out.UnmarshalText(text), "%s", text)
		assert.Check(t, is.Equal(out, in), "%s", text)
	}
	text, err := Duration(math.MinInt64).MarshalText()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(string(text), "-PT2562047H47M16.854775808S"))
}

// TestDurationUnmarshalCollapsesWhitespace checks that surrounding XML
// whitespace is ignored, as xsd:duration's whiteSpace="collapse" requires.
func TestDurationUnmarshalCollapsesWhitespace(t *testing.T) {
	var d Duration
	assert.NilError(t, d.UnmarshalText([]byte("\n\tPT1H ")))
	assert.Check(t, is.Equal(time.Duration(d), time.Hour))
}
