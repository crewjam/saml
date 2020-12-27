package saml

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

var durationMarshalTests = []struct {
	in       time.Duration
	expected []byte
}{
	{0, nil},
	{time.Nanosecond, []byte("PT0.000000001S")},
	{time.Millisecond, []byte("PT0.001S")},
	{time.Second, []byte("PT1S")},
	{time.Minute, []byte("PT1M")},
	{time.Hour, []byte("PT1H")},
	{-time.Hour, []byte("-PT1H")},
	{2*time.Hour + 3*time.Minute + 4*time.Second + 5*time.Nanosecond, []byte("PT2H3M4.000000005S")},
}

func TestDuration(t *testing.T) {
	for i, testCase := range durationMarshalTests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			actual, err := Duration(testCase.in).MarshalText()
			assert.Check(t, err)
			assert.Check(t, is.DeepEqual(testCase.expected, actual))
		})
	}
}

var durationUnmarshalTests = []struct {
	in       []byte
	expected time.Duration
	err      error
}{
	{nil, 0, nil},
	{[]byte("PT0.0000000001S"), 0, nil},
	{[]byte("PT0.000000001S"), time.Nanosecond, nil},
	{[]byte("PT0.001S"), time.Millisecond, nil},
	{[]byte("PT1S"), time.Second, nil},
	{[]byte("PT1M"), time.Minute, nil},
	{[]byte("PT1H"), time.Hour, nil},
	{[]byte("-PT1H"), -time.Hour, nil},
	{[]byte("P1D"), 24 * time.Hour, nil},
	{[]byte("P1M"), 720 * time.Hour, nil},
	{[]byte("P1Y"), 8760 * time.Hour, nil},
	{[]byte("P2Y3M4DT5H6M7.000000008S"), 19781*time.Hour + 6*time.Minute + 7*time.Second + 8*time.Nanosecond, nil},
	{[]byte("P0Y0M0DT0H0M0S"), 0, nil},
	{[]byte("PT0001.0000S"), time.Second, nil},
	{[]byte(""), 0, errors.New("invalid duration ()")},
	{[]byte("12345"), 0, errors.New("invalid duration (12345)")},
	{[]byte("P1D1M1Y"), 0, errors.New("invalid duration (P1D1M1Y)")},
	{[]byte("P1H1M1S"), 0, errors.New("invalid duration (P1H1M1S)")},
	{[]byte("PT1S1M1H"), 0, errors.New("invalid duration (PT1S1M1H)")},
	{[]byte(" P1Y "), 0, errors.New("invalid duration ( P1Y )")},
	{[]byte("P"), 0, errors.New("invalid duration (P)")},
	{[]byte("-P"), 0, errors.New("invalid duration (-P)")},
	{[]byte("PT"), 0, errors.New("invalid duration (PT)")},
	{[]byte("P1YMD"), 0, errors.New("invalid duration (P1YMD)")},
	{[]byte("P1YT"), 0, errors.New("invalid duration (P1YT)")},
	{[]byte("P-1Y"), 0, errors.New("invalid duration (P-1Y)")},
	{[]byte("P1.5Y"), 0, errors.New("invalid duration (P1.5Y)")},
	{[]byte("PT1.S"), 0, errors.New("invalid duration (PT1.S)")},
}

func TestDurationUnmarshal(t *testing.T) {
	for i, testCase := range durationUnmarshalTests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			var actual Duration
			err := actual.UnmarshalText(testCase.in)
			if testCase.err == nil {
				assert.Check(t, err)
			} else {
				assert.Check(t, is.Error(err, testCase.err.Error()))
			}
			assert.Check(t, is.Equal(Duration(testCase.expected), actual))
		})
	}
}
