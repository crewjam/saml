package samlsp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// FetchMetadata uses a default client when httpClient is nil, instead of
// panicking.
func TestFetchMetadataNilClient(t *testing.T) {
	test := NewMiddlewareTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(test.IDPMetadata)
		assert.Check(t, err)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL + "/metadata")
	assert.Assert(t, err)
	md, err := FetchMetadata(context.Background(), nil, *u)
	assert.Assert(t, err)
	assert.Check(t, is.Equal("https://idp.testshib.org/idp/shibboleth", md.EntityID))
}

// Only a 2xx response is taken as metadata: the body of a redirect the
// client does not follow is refused even if it looks like metadata.
func TestFetchMetadataRejectsNon2xx(t *testing.T) {
	test := NewMiddlewareTest(t)
	for _, status := range []int{http.StatusFound, http.StatusNotModified, http.StatusNotFound} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(status)
			_, _ = w.Write(test.IDPMetadata)
		}))
		client := server.Client()
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

		u, err := url.Parse(server.URL + "/metadata")
		assert.Assert(t, err)
		_, err = FetchMetadata(context.Background(), client, *u)
		assert.Check(t, err != nil && strings.Contains(err.Error(), "unexpected status code"), "status %d: %v", status, err)
		server.Close()
	}
}
