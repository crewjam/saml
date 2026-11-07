package saml

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func deflateForTest(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	assert.NilError(t, err)
	_, err = w.Write(data)
	assert.NilError(t, err)
	assert.NilError(t, w.Close())
	return buf.Bytes()
}

// The limit applies to the bytes inflated, not to the size of the buffer
// they are read into: io.ReadAll grows its buffer past the limit well
// before the data does.
func TestSaferFlateReaderReadsMessageAtLimit(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit)
	got, err := io.ReadAll(newSaferFlateReader(bytes.NewReader(deflateForTest(t, data))))
	assert.NilError(t, err)
	assert.Check(t, is.Len(got, flateUncompressLimit))
}

func TestSaferFlateReaderRejectsMessageOverLimit(t *testing.T) {
	data := bytes.Repeat([]byte("a"), flateUncompressLimit+1)
	_, err := io.ReadAll(newSaferFlateReader(bytes.NewReader(deflateForTest(t, data))))
	assert.Error(t, err, "flate: uncompress limit exceeded (1048576 bytes)")
}
