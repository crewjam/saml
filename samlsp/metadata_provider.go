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
	minimumMetadataRefreshInterval = time.Minute
	metadataRefreshFetchTimeout    = 2 * time.Minute
)

// MetadataProvider fetches and caches one IdP EntityDescriptor. It refreshes
// the document before the earliest validUntil or cacheDuration deadline, with
// at least a minute between successful refreshes. If a
// refresh fails, it can continue returning the previous document until its
// validUntil bound; after that, it returns the fetch or expiry error.
//
// Refreshes start on demand and continue independently of the request that
// triggered them. An idle provider does not refresh in the background.
// Returned EntityDescriptor values are shared and must be treated as
// read-only.
type MetadataProvider struct {
	client       *http.Client
	metadataURL  url.URL
	entityID     string
	signingCerts []*x509.Certificate

	mu                 sync.Mutex
	current            *saml.EntityDescriptor
	currentRetrievedAt time.Time
	nextRefreshAt      time.Time
	refreshing         *metadataRefreshCall
	lastError          error
}

type metadataRefreshCall struct {
	done chan struct{}
	err  error
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
// tenth of the remaining time early, up to five minutes, with a one-minute
// minimum interval. Metadata without a calculable deadline is refreshed
// every twelve hours.
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
			case <-wait.done:
				if force || errors.Is(wait.err, context.Canceled) {
					return nil, wait.err
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		wait := &metadataRefreshCall{done: make(chan struct{})}
		p.refreshing = wait
		previous := p.current
		previousRetrievedAt := p.currentRetrievedAt
		p.mu.Unlock()

		go p.runRefresh(ctx, wait, previous, previousRetrievedAt)
		select {
		case <-wait.done:
			if force || errors.Is(wait.err, context.Canceled) {
				return nil, wait.err
			}
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (p *MetadataProvider) runRefresh(callerCtx context.Context, call *metadataRefreshCall, previous *saml.EntityDescriptor, previousRetrievedAt time.Time) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), metadataRefreshFetchTimeout)
	defer cancel()

	updated, retrievedAt, err := p.fetch(ctx)
	now := saml.TimeNow()

	p.mu.Lock()
	if err == nil {
		p.current = updated
		p.currentRetrievedAt = retrievedAt
		p.nextRefreshAt = metadataRefreshAt(updated, retrievedAt, now)
		p.lastError = nil
	} else if errors.Is(err, context.Canceled) {
		p.lastError = nil
		p.nextRefreshAt = now
		call.err = err
	} else {
		p.lastError = err
		p.nextRefreshAt = metadataRetryAt(previous, now)
		if previous != nil && previous.ValidateMetadataAt(now) == nil {
			p.current = previous
			p.currentRetrievedAt = previousRetrievedAt
		}
		call.err = err
	}
	p.refreshing = nil
	close(call.done)
	p.mu.Unlock()
}

func (p *MetadataProvider) fetch(ctx context.Context) (*saml.EntityDescriptor, time.Time, error) {
	data, err := fetchMetadataBytes(ctx, p.client, p.metadataURL)
	if err != nil {
		return nil, time.Time{}, err
	}
	retrievedAt := saml.TimeNow()
	var metadata *saml.EntityDescriptor
	switch {
	case len(p.signingCerts) > 0 && p.entityID == "":
		metadata, err = ParseSignedMetadata(data, p.signingCerts)
	case len(p.signingCerts) > 0:
		metadata, err = ParseSignedMetadataByEntityID(data, p.entityID, p.signingCerts)
	case p.entityID == "":
		metadata, err = ParseMetadata(data)
	default:
		metadata, err = ParseMetadataByEntityID(data, p.entityID)
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := metadata.ValidateMetadataAt(retrievedAt); err != nil {
		return nil, time.Time{}, err
	}
	return metadata, retrievedAt, nil
}

func metadataRefreshAt(metadata *saml.EntityDescriptor, retrievedAt, now time.Time) time.Time {
	refreshAt := metadata.MetadataRefreshAt(retrievedAt)
	if refreshAt.IsZero() {
		return now.Add(defaultMetadataRefreshInterval)
	}
	lifetime := refreshAt.Sub(now)
	lead := lifetime / 10
	if lead > maximumMetadataRefreshLead {
		lead = maximumMetadataRefreshLead
	}
	refreshAt = refreshAt.Add(-lead)
	minimumRefreshAt := now.Add(minimumMetadataRefreshInterval)
	if refreshAt.Before(minimumRefreshAt) {
		return minimumRefreshAt
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
