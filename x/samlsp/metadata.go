package samlsp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml"
	legacy "github.com/crewjam/saml/samlsp"
)

// MetadataFunc returns the metadata of the identity provider (IdP) that a
// Config trusts. The metadata names the IdP's endpoints and the
// certificates trusted to sign its messages.
//
// Config calls it every time it builds or verifies a message, with that
// call's context, so it must be cheap and safe for concurrent use. Use
// StaticMetadata, ParseMetadata or RemoteMetadata, or write your own: for
// example, to read metadata from a database, or to pick the IdP of a tenant
// named in ctx.
//
// The returned metadata must not be modified afterwards.
type MetadataFunc func(ctx context.Context) (*saml.EntityDescriptor, error)

// StaticMetadata returns a MetadataFunc that always returns md.
func StaticMetadata(md *saml.EntityDescriptor) MetadataFunc {
	return func(context.Context) (*saml.EntityDescriptor, error) {
		if md == nil {
			return nil, errors.New("samlsp: nil identity provider metadata")
		}
		return md, nil
	}
}

// MetadataOption configures ParseMetadata and RemoteMetadata.
type MetadataOption func(*metadataOptions)

type metadataOptions struct {
	entityID        string
	certs           []*x509.Certificate
	client          *http.Client
	refreshInterval time.Duration
}

// WithIdentityProviderEntityID selects the identity provider with this entityID from
// metadata that is an EntitiesDescriptor aggregate, such as a federation
// feed. It is required when the aggregate holds more than one IdP.
func WithIdentityProviderEntityID(entityID string) MetadataOption {
	return func(o *metadataOptions) { o.entityID = entityID }
}

// WithMetadataSigners makes metadata acceptable only if it carries a valid
// XML signature by one of certs. Use it whenever the metadata comes over a
// channel that is not otherwise trusted.
func WithMetadataSigners(certs ...*x509.Certificate) MetadataOption {
	return func(o *metadataOptions) { o.certs = append(o.certs, certs...) }
}

// WithHTTPClient sets the HTTP client that RemoteMetadata fetches metadata
// with. The default client times out after two minutes.
func WithHTTPClient(client *http.Client) MetadataOption {
	return func(o *metadataOptions) { o.client = client }
}

// WithRefreshInterval sets how long RemoteMetadata keeps metadata before it
// fetches it again. The default is DefaultMetadataRefreshInterval. A
// shorter cacheDuration or an earlier validUntil in the metadata takes
// precedence.
func WithRefreshInterval(d time.Duration) MetadataOption {
	return func(o *metadataOptions) { o.refreshInterval = d }
}

// DefaultMetadataRefreshInterval is how long RemoteMetadata keeps metadata
// by default.
const DefaultMetadataRefreshInterval = time.Hour

// metadataRetryInterval is how long RemoteMetadata keeps serving metadata
// it could not refresh before it tries again.
const metadataRetryInterval = time.Minute

// ParseMetadata parses identity provider metadata in data, such as metadata
// loaded from a file, and returns a MetadataFunc that returns it.
func ParseMetadata(data []byte, opts ...MetadataOption) (MetadataFunc, error) {
	o := newMetadataOptions(opts)
	md, err := parseMetadata(data, o)
	if err != nil {
		return nil, err
	}
	return StaticMetadata(md), nil
}

func newMetadataOptions(opts []MetadataOption) metadataOptions {
	o := metadataOptions{refreshInterval: DefaultMetadataRefreshInterval}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func parseMetadata(data []byte, o metadataOptions) (*saml.EntityDescriptor, error) {
	switch {
	case len(o.certs) > 0 && o.entityID != "":
		return legacy.ParseSignedMetadataByEntityID(data, o.entityID, o.certs)
	case len(o.certs) > 0:
		return legacy.ParseSignedMetadata(data, o.certs)
	case o.entityID != "":
		return legacy.ParseMetadataByEntityID(data, o.entityID)
	default:
		return legacy.ParseMetadata(data)
	}
}

func fetchMetadata(ctx context.Context, metadataURL url.URL, o metadataOptions) (*saml.EntityDescriptor, error) {
	switch {
	case len(o.certs) > 0 && o.entityID != "":
		return legacy.FetchSignedMetadataByEntityID(ctx, o.client, metadataURL, o.entityID, o.certs)
	case len(o.certs) > 0:
		return legacy.FetchSignedMetadata(ctx, o.client, metadataURL, o.certs)
	case o.entityID != "":
		return legacy.FetchMetadataByEntityID(ctx, o.client, metadataURL, o.entityID)
	default:
		return legacy.FetchMetadata(ctx, o.client, metadataURL)
	}
}

// RemoteMetadata returns a MetadataFunc that fetches identity provider
// metadata from metadataURL and caches it.
//
// The metadata is fetched on first use, with the caller's context. It is
// fetched again once the refresh interval (see WithRefreshInterval), its
// cacheDuration or its validUntil has passed. This picks up rotated
// signing certificates. If a refresh fails, the cached metadata is still
// returned until its validUntil, and the fetch is retried a minute later.
// Callers wait while a fetch is in progress.
func RemoteMetadata(metadataURL string, opts ...MetadataOption) MetadataFunc {
	r := &remoteMetadata{url: metadataURL, opts: newMetadataOptions(opts), now: time.Now}
	return r.get
}

type remoteMetadata struct {
	url  string
	opts metadataOptions
	now  func() time.Time

	mu        sync.Mutex
	md        *saml.EntityDescriptor
	refreshAt time.Time
}

func (r *remoteMetadata) get(ctx context.Context) (*saml.EntityDescriptor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	if r.md != nil && now.Before(r.refreshAt) {
		return r.md, nil
	}

	u, err := url.Parse(r.url)
	if err != nil {
		return nil, fmt.Errorf("samlsp: invalid metadata URL: %w", err)
	}
	md, err := fetchMetadata(ctx, *u, r.opts)
	if err == nil {
		err = checkIDPMetadata(md)
	}
	if err != nil {
		if r.md != nil && (r.md.ValidUntil.IsZero() || now.Before(r.md.ValidUntil)) {
			r.refreshAt = now.Add(min(r.opts.refreshInterval, metadataRetryInterval))
			return r.md, nil
		}
		return nil, err
	}

	r.md = md
	r.refreshAt = now.Add(r.opts.refreshInterval)
	if md.CacheDuration > 0 && md.CacheDuration < r.opts.refreshInterval {
		r.refreshAt = now.Add(md.CacheDuration)
	}
	if !md.ValidUntil.IsZero() && md.ValidUntil.Before(r.refreshAt) {
		r.refreshAt = md.ValidUntil
	}
	return md, nil
}

// checkIDPMetadata returns an error if md does not describe an identity
// provider.
func checkIDPMetadata(md *saml.EntityDescriptor) error {
	if md == nil {
		return errors.New("samlsp: nil identity provider metadata")
	}
	if len(md.IDPSSODescriptors) == 0 {
		return fmt.Errorf("samlsp: metadata for %q has no IDPSSODescriptor", md.EntityID)
	}
	return nil
}

type clientContextKey struct{}

// ClientContext returns a copy of ctx that carries client. Config.ParseResponse
// uses client to resolve HTTP-Artifact responses with the IdP (the artifact
// resolution protocol). To set the client that RemoteMetadata uses, pass
// WithHTTPClient.
func ClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, clientContextKey{}, client)
}

func clientFromContext(ctx context.Context) *http.Client {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(clientContextKey{}).(*http.Client)
	return c
}
