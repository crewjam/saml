package samlsp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"gotest.tools/v3/assert"
)

type metadataProviderResult struct {
	metadata *saml.EntityDescriptor
	err      error
}

func TestMetadataRefreshScheduling(t *testing.T) {
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	retrievedAt := now

	t.Run("default interval without a deadline", func(t *testing.T) {
		got := metadataRefreshAt(&saml.EntityDescriptor{}, retrievedAt, now)
		assert.Equal(t, got, now.Add(defaultMetadataRefreshInterval))
	})

	t.Run("early refresh before a future deadline", func(t *testing.T) {
		metadata := &saml.EntityDescriptor{CacheDuration: 10 * time.Hour}
		got := metadataRefreshAt(metadata, retrievedAt, now)
		assert.Equal(t, got, now.Add(9*time.Hour+55*time.Minute))
	})

	t.Run("minimum interval for zero cache duration", func(t *testing.T) {
		data := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test" cacheDuration="PT0S"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`)
		metadata, err := ParseMetadata(data)
		assert.NilError(t, err)
		got := metadataRefreshAt(metadata, retrievedAt, now)
		assert.Equal(t, got, now.Add(minimumMetadataRefreshInterval))
	})

	t.Run("minimum interval for an elapsed deadline", func(t *testing.T) {
		metadata := &saml.EntityDescriptor{ValidUntil: now.Add(-time.Hour)}
		got := metadataRefreshAt(metadata, retrievedAt, now)
		assert.Equal(t, got, now.Add(minimumMetadataRefreshInterval))
	})
}

func TestMetadataProviderFallsBackAfterRefreshFailure(t *testing.T) {
	metadataXML := providerTestMetadata()
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requestCount.Add(1) == 1 {
			_, _ = w.Write(metadataXML)
			return
		}
		http.Error(w, "temporary upstream error", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	provider := newTestMetadataProvider(t, server)
	ctx := context.Background()
	first, err := provider.Metadata(ctx)
	assert.NilError(t, err)

	err = provider.Refresh(ctx)
	assert.Assert(t, err != nil)
	assert.Assert(t, provider.LastRefreshError() != nil)

	fallback, err := provider.Metadata(ctx)
	assert.NilError(t, err)
	assert.Assert(t, fallback == first, "provider should return the last still-valid metadata document")
	assert.Equal(t, requestCount.Load(), int32(2))
}

func TestMetadataProviderSharesConcurrentFetch(t *testing.T) {
	metadataXML := providerTestMetadata()
	requestStarted := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	defer func() {
		select {
		case <-releaseResponse:
		default:
			close(releaseResponse)
		}
	}()
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		<-releaseResponse
		_, _ = w.Write(metadataXML)
	}))
	defer server.Close()

	provider := newTestMetadataProvider(t, server)
	results := make(chan metadataProviderResult, 2)
	go func() {
		metadata, err := provider.Metadata(context.Background())
		results <- metadataProviderResult{metadata: metadata, err: err}
	}()
	<-requestStarted
	go func() {
		metadata, err := provider.Metadata(context.Background())
		results <- metadataProviderResult{metadata: metadata, err: err}
	}()
	// Give the second caller a chance to join the blocked refresh before it is
	// released. A second HTTP request would expose a missed single-flight join.
	time.Sleep(25 * time.Millisecond)
	close(releaseResponse)

	first, second := <-results, <-results
	assert.NilError(t, first.err)
	assert.NilError(t, second.err)
	assert.Assert(t, first.metadata == second.metadata, "callers should receive the same cached document")
	assert.Equal(t, requestCount.Load(), int32(1))
}

func TestMetadataProviderCallerCancellationDoesNotCancelRefresh(t *testing.T) {
	metadataXML := providerTestMetadata()
	requestStarted := make(chan struct{}, 1)
	releaseResponse := make(chan struct{})
	defer func() {
		select {
		case <-releaseResponse:
		default:
			close(releaseResponse)
		}
	}()
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		select {
		case requestStarted <- struct{}{}:
		default:
		}
		<-releaseResponse
		_, _ = w.Write(metadataXML)
	}))
	defer server.Close()

	provider := newTestMetadataProvider(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	firstResult := make(chan error, 1)
	go func() {
		_, err := provider.Metadata(ctx)
		firstResult <- err
	}()
	<-requestStarted
	cancel()
	select {
	case err := <-firstResult:
		assert.Assert(t, errors.Is(err, context.Canceled), "%v", err)
	case <-time.After(time.Second):
		t.Fatal("cancelled caller did not stop waiting for the refresh")
	}

	secondResult := make(chan metadataProviderResult, 1)
	go func() {
		metadata, err := provider.Metadata(context.Background())
		secondResult <- metadataProviderResult{metadata: metadata, err: err}
	}()
	close(releaseResponse)
	select {
	case got := <-secondResult:
		assert.NilError(t, got.err)
		assert.Assert(t, got.metadata != nil)
	case <-time.After(2 * time.Second):
		t.Fatal("shared refresh did not complete for the remaining caller")
	}
	assert.Assert(t, provider.LastRefreshError() == nil)
	assert.Equal(t, requestCount.Load(), int32(1))
}

func newTestMetadataProvider(t *testing.T, server *httptest.Server) *MetadataProvider {
	t.Helper()
	metadataURL, err := url.Parse(server.URL + "/metadata")
	assert.NilError(t, err)
	return NewMetadataProvider(server.Client(), *metadataURL, "")
}

func providerTestMetadata() []byte {
	validUntil := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	return []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test" validUntil=%q><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`, validUntil))
}
