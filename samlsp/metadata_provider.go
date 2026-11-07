package samlsp

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml"
)

// IDPMetadataProvider supplies the current metadata for an identity provider.
// Middleware calls it before starting authentication or handling an ACS or
// SLO message, allowing the caller to refresh metadata without mutating a
// shared ServiceProvider.
type IDPMetadataProvider interface {
	Metadata(context.Context) (*saml.EntityDescriptor, error)
}

const (
	defaultMetadataRefreshInterval = 12 * time.Hour
	metadataRefreshRetryInterval   = 30 * time.Second
	maximumMetadataRefreshLead     = 5 * time.Minute
)

// MetadataProvider fetches and caches one IdP EntityDescriptor. It refreshes
// the document before the earliest validUntil or cacheDuration deadline. If a
// refresh fails, it can continue returning the previous document until its
// validUntil bound; after that, it returns the fetch or expiry error.
//
// Metadata is fetched on demand rather than in a background goroutine. Call
// Metadata from the application's normal request or refresh path so that a
// provider that stays idle does not retain expired metadata indefinitely.
// Returned EntityDescriptor values are shared and must be treated as
// read-only.
type MetadataProvider struct {
	client      *http.Client
	metadataURL url.URL
	entityID    string
	signingCerts []*x509.Certificate

	mu            sync.Mutex
	current       *saml.EntityDescriptor
	nextRefreshAt time.Time
	refreshing    chan struct{}
	lastError     error
}

// NewMetadataProvider creates an on-demand metadata provider. If entityID is
// empty, the source must contain exactly one IdP entity and ParseMetadata is
// used. Otherwise the matching entity is selected from an aggregate. This
// constructor does not verify an XML signature; use an HTTPS URL you trust or
// NewSignedMetadataProvider with independently trusted signing certificates.
func NewMetadataProvider(httpClient *http.Client, metadataURL url.URL, entityID string) *MetadataProvider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &MetadataProvider{
		client:      httpClient,
		metadataURL: metadataURL,
		entityID:    entityID,
	}
}

// NewSignedMetadataProvider creates a provider that requires every fetched
// document to carry a valid root signature made by one of certs. The
// certificates must come from a source trusted independently of metadataURL.
func NewSignedMetadataProvider(httpClient *http.Client, metadataURL url.URL, entityID string, certs []*x509.Certificate) (*MetadataProvider, error) {
	if len(certs) == 0 {
		return nil, errors.New("samlsp: signed metadata provider needs at least one trusted certificate")
	}
	trustedCerts := append([]*x509.Certificate(nil), certs...)
	for _, cert := range trustedCerts {
		if cert == nil {
			return nil, errors.New("samlsp: signed metadata provider received a nil trusted certificate")
		}
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &MetadataProvider{
		client:       httpClient,
		metadataURL:  metadataURL,
		entityID:     entityID,
		signingCerts: trustedCerts,
	}, nil
}

// Metadata returns the current metadata, fetching it if this is the first
// call or its refresh time has arrived. The provider derives the refresh time
// from the effective metadata refresh deadline and refreshes at least one
// tenth of the remaining time early, up to five minutes. Metadata without a
// calculable deadline is refreshed every twelve hours.
func (p *MetadataProvider) Metadata(ctx context.Context) (*saml.EntityDescriptor, error) {
	return p.get(ctx, false)
}

// Refresh forces a fetch even if the cached metadata is still fresh. On
// failure it returns the fetch error; Metadata may still serve the previous
// document while its validUntil bound has not passed.
func (p *MetadataProvider) Refresh(ctx context.Context) error {
	_, err := p.get(ctx, true)
	return err
}

// LastRefreshError returns the most recent refresh error, or nil if the last
// refresh succeeded. A still-valid cached document may be returned by
// Metadata while this error is non-nil.
func (p *MetadataProvider) LastRefreshError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastError
}

func (p *MetadataProvider) get(ctx context.Context, force bool) (*saml.EntityDescriptor, error) {
	for {
		p.mu.Lock()
		now := saml.TimeNow()
		if !force && now.Before(p.nextRefreshAt) {
			if p.current != nil && p.current.ValidateMetadataAt(now) == nil {
				metadata := p.current
				p.mu.Unlock()
				return metadata, nil
			}
			if p.lastError != nil {
				err := p.lastError
				p.mu.Unlock()
				return nil, err
			}
		}
		if p.refreshing != nil {
			wait := p.refreshing
			p.mu.Unlock()
			select {
			case <-wait:
				if force {
					p.mu.Lock()
					err := p.lastError
					p.mu.Unlock()
					return nil, err
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		wait := make(chan struct{})
		p.refreshing = wait
		previous := p.current
		p.mu.Unlock()

		updated, err := p.fetch(ctx)
		now = saml.TimeNow()

		p.mu.Lock()
		var result *saml.EntityDescriptor
		if err == nil {
			p.current = updated
			p.nextRefreshAt = metadataRefreshAt(updated, now)
			p.lastError = nil
			result = updated
		} else {
			p.lastError = err
			p.nextRefreshAt = metadataRetryAt(previous, now)
			if !force && previous != nil && previous.ValidateMetadataAt(now) == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				result = previous
				err = nil
			}
		}
		p.refreshing = nil
		close(wait)
		p.mu.Unlock()
		return result, err
	}
}

func (p *MetadataProvider) fetch(ctx context.Context) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, p.client, p.metadataURL)
	if err != nil {
		return nil, err
	}
	retrievedAt := saml.TimeNow()
	var metadata *saml.EntityDescriptor
	switch {
	case len(p.signingCerts) > 0 && p.entityID == "":
		metadata, err = ParseSignedMetadataAt(data, p.signingCerts, retrievedAt)
	case len(p.signingCerts) > 0:
		metadata, err = ParseSignedMetadataByEntityIDAt(data, p.entityID, p.signingCerts, retrievedAt)
	case p.entityID == "":
		metadata, err = ParseMetadataAt(data, retrievedAt)
	default:
		metadata, err = ParseMetadataByEntityIDAt(data, p.entityID, retrievedAt)
	}
	if err != nil {
		return nil, err
	}
	if err := metadata.ValidateMetadataAt(retrievedAt); err != nil {
		return nil, err
	}
	return metadata, nil
}

func metadataRefreshAt(metadata *saml.EntityDescriptor, now time.Time) time.Time {
	refreshAt := metadata.MetadataRefreshAt()
	if refreshAt.IsZero() {
		return now.Add(defaultMetadataRefreshInterval)
	}
	lifetime := refreshAt.Sub(now)
	lead := lifetime / 10
	if lead > maximumMetadataRefreshLead {
		lead = maximumMetadataRefreshLead
	}
	refreshAt = refreshAt.Add(-lead)
	if !refreshAt.After(now) {
		return now
	}
	return refreshAt
}

func metadataRetryAt(metadata *saml.EntityDescriptor, now time.Time) time.Time {
	retryAt := now.Add(metadataRefreshRetryInterval)
	if metadata == nil {
		return retryAt
	}
	if expiresAt := metadata.MetadataExpiresAt(); expiresAt.After(now) && expiresAt.Before(retryAt) {
		return expiresAt
	}
	return retryAt
}
