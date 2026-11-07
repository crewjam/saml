package samlsp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// metadataClient returns a client whose every response has body as its body.
func metadataClient(body func() io.Reader) *http.Client {
	return &http.Client{Transport: mockTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(body())}, nil
	})}
}

// A metadata endpoint can send any amount of data; FetchMetadata must stop
// reading at MaxMetadataSize rather than hold all of it in memory.
func TestFetchMetadataStopsReadingAtMaxMetadataSize(t *testing.T) {
	defer func(old int64) { MaxMetadataSize = old }(MaxMetadataSize)
	MaxMetadataSize = 1024

	var read int64
	client := metadataClient(func() io.Reader {
		return &countingReader{r: io.LimitReader(zeros{}, 4<<20), n: &read}
	})
	_, err := FetchMetadata(context.Background(), client, mustParseURL("https://idp.example.com/metadata"))
	assert.Check(t, is.Error(err, "failed to fetch metadata: response is larger than 1024 bytes (MaxMetadataSize)"))
	assert.Check(t, read <= 1024+bytes.MinRead, "read %d bytes", read)
}

func TestFetchMetadataReadsMetadataUpToMaxMetadataSize(t *testing.T) {
	defer func(old int64) { MaxMetadataSize = old }(MaxMetadataSize)
	const md = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`
	MaxMetadataSize = int64(len(md))

	client := metadataClient(func() io.Reader { return strings.NewReader(md) })
	entity, err := FetchMetadata(context.Background(), client, mustParseURL("https://idp.example.com/metadata"))
	assert.NilError(t, err)
	assert.Check(t, is.Equal(entity.EntityID, "https://idp.example.com/metadata"))
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

type countingReader struct {
	r io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)
	return n, err
}
