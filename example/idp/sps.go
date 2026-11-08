package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
)

// remoteServiceProviders is the samlidp.ServiceProviderFunc of the example:
// it trusts the service providers whose entity IDs it was given, and
// fetches the metadata of each from its entity ID, which by convention is
// the URL of the metadata. It keeps metadata for a few minutes, so that an
// SP that changes its keys is picked up.
//
// A real IdP would rather keep the metadata of the SPs it serves in its
// database, checked by an administrator when the SP is registered (see
// samlidp.ParseMetadata), or fetch it over https and check its signature
// with samlidp.WithMetadataSigners.
type remoteServiceProviders struct {
	trusted []string
	client  *http.Client

	mu    sync.Mutex
	cache map[string]cachedMetadata
}

type cachedMetadata struct {
	md      *saml.EntityDescriptor
	fetched time.Time
}

const (
	metadataCacheTime   = 5 * time.Minute
	maxSPMetadataLength = 1 << 20
)

func newRemoteServiceProviders(trusted []string, client *http.Client) *remoteServiceProviders {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &remoteServiceProviders{trusted: trusted, client: client, cache: map[string]cachedMetadata{}}
}

// lookup implements samlidp.ServiceProviderFunc.
func (s *remoteServiceProviders) lookup(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
	if !slices.Contains(s.trusted, entityID) {
		return nil, fmt.Errorf("%q is not a trusted service provider: %w", entityID, samlidp.ErrUnknownServiceProvider)
	}
	s.mu.Lock()
	c, ok := s.cache[entityID]
	s.mu.Unlock()
	if ok && time.Since(c.fetched) < metadataCacheTime {
		return c.md, nil
	}

	md, err := s.fetch(ctx, entityID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[entityID] = cachedMetadata{md: md, fetched: time.Now()}
	s.mu.Unlock()
	return md, nil
}

func (s *remoteServiceProviders) fetch(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, entityID, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req) //nolint:gosec // G704: entityID is one of the trusted SPs given with -sp
	if err != nil {
		return nil, fmt.Errorf("cannot fetch the metadata of %s: %w", entityID, err)
	}
	defer resp.Body.Close() //nolint:errcheck // nothing useful to do with a close error here
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot fetch the metadata of %s: %s", entityID, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSPMetadataLength))
	if err != nil {
		return nil, fmt.Errorf("cannot fetch the metadata of %s: %w", entityID, err)
	}
	md, err := samlidp.ParseMetadata(data, samlidp.WithServiceProviderEntityID(entityID))
	if err != nil {
		return nil, err
	}
	return md, nil
}
