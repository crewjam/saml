package saml

import (
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestMiscCovDurationOverflow(t *testing.T) {
	huge := strings.Repeat("9", 30)
	hugeFloat := strings.Repeat("9", 400)
	testCases := map[string]string{
		"P" + huge + "Y":         "invalid duration years",
		"P" + huge + "M":         "invalid duration months",
		"P" + huge + "D":         "invalid duration days",
		"PT" + huge + "H":        "invalid duration hours",
		"PT" + huge + "M":        "invalid duration minutes",
		"PT" + hugeFloat + ".0S": "invalid duration seconds",
		"PT" + hugeFloat + "S":   "invalid duration seconds",
	}
	for in, wantErr := range testCases {
		var d Duration
		assert.Check(t, is.ErrorContains(d.UnmarshalText([]byte(in)), wantErr), in[:10])
	}
}

func TestMiscCovRelaxedTimeEmpty(t *testing.T) {
	m := RelaxedTime(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.NilError(t, m.UnmarshalText([]byte{}))
	assert.Check(t, time.Time(m).IsZero())
}

func TestMiscCovSaferFlateReaderClose(t *testing.T) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	assert.NilError(t, err)
	_, err = w.Write([]byte("hello"))
	assert.NilError(t, err)
	assert.NilError(t, w.Close())

	r := newSaferFlateReader(&buf)
	out, err := io.ReadAll(r)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("hello", string(out)))
	assert.Check(t, r.Close())
}

func TestMiscCovRandomBytesPanicsOnReadError(t *testing.T) {
	oldRandReader := RandReader
	t.Cleanup(func() { RandReader = oldRandReader })
	readErr := errors.New("idpcov: entropy exhausted")
	RandReader = iotest.ErrReader(readErr)

	defer func() {
		r := recover()
		assert.Check(t, is.Equal(readErr, r))
	}()
	randomBytes(20)
	t.Fatal("randomBytes did not panic")
}
