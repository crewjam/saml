package samlsp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/idpmetadata"
)

// MetadataFunc returns the metadata of the identity provider (IdP) that a
// Config trusts. The metadata names the IdP's endpoints and the
// certificates trusted to sign its messages.
//
// Config calls it every time it builds or verifies a message, with that
// call's context, so it must be cheap and safe for concurrent use. Use
// StaticMetadata, StaticMetadataBytes or RemoteMetadata, or write your own: for
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

// MetadataOption configures StaticMetadataBytes and RemoteMetadata.
type MetadataOption interface {
	applyMetadata(*metadataOptions)
}

type metadataOptionFunc func(*metadataOptions)

func (f metadataOptionFunc) applyMetadata(o *metadataOptions) { f(o) }

type metadataOptions struct {
	entityID        string
	certs           []*x509.Certificate
	client          *http.Client
	refreshInterval time.Duration
	clock           *dsig.Clock
	accept          string
}

// WithIdentityProviderEntityID selects the identity provider with this entityID from
// metadata that is an EntitiesDescriptor aggregate, such as a federation
// feed. It is required when the aggregate holds more than one IdP.
func WithIdentityProviderEntityID(entityID string) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.entityID = entityID })
}

// WithMetadataSigners makes metadata acceptable only if it carries a valid
// XML signature by one of certs. Use it whenever the metadata comes over a
// channel that is not otherwise trusted.
func WithMetadataSigners(certs ...*x509.Certificate) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.certs = append(o.certs, certs...) })
}

// HTTPClientOption is the option that WithHTTPClient returns. It is both an
// Option, for New, and a MetadataOption, for RemoteMetadata.
type HTTPClientOption struct{ client *http.Client }

// WithHTTPClient sets the HTTP client for requests to the IdP. Passed to
// New, it is used to resolve HTTP-Artifact responses, for back-channel
// logout and for attribute queries; passed to RemoteMetadata, to fetch
// metadata. Use it for timeouts, proxies, or a TLS client certificate.
//
// Without it, New uses http.DefaultClient, and RemoteMetadata a client
// that times out after two minutes.
func WithHTTPClient(client *http.Client) HTTPClientOption { return HTTPClientOption{client} }

func (h HTTPClientOption) applyMetadata(o *metadataOptions) { o.client = h.client }

func (h HTTPClientOption) applyConfig(c *Config, _ *configOptions) { c.httpClient = h.client }

// WithRefreshInterval sets how long RemoteMetadata keeps metadata before it
// fetches it again. The default is DefaultMetadataRefreshInterval. A
// shorter cacheDuration or an earlier validUntil in the metadata takes
// precedence.
func WithRefreshInterval(d time.Duration) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.refreshInterval = d })
}

// DefaultMetadataRefreshInterval is how long RemoteMetadata keeps metadata
// by default.
const DefaultMetadataRefreshInterval = time.Hour

// metadataRetryInterval is how long RemoteMetadata keeps serving metadata
// it could not refresh before it tries again.
const metadataRetryInterval = time.Minute

// StaticMetadataBytes returns a MetadataFunc that always returns the
// identity provider metadata in data, such as a file the IdP administrator
// sent or one embedded with go:embed. The options WithIdentityProviderEntityID
// and WithMetadataSigners apply; the others are for RemoteMetadata.
//
// data is parsed once, now. If it is not valid metadata, every call of the
// MetadataFunc returns the error, so every Config method that uses it fails.
func StaticMetadataBytes(data []byte, opts ...MetadataOption) MetadataFunc {
	md, err := parseMetadata(data, newMetadataOptions(opts))
	if err == nil {
		err = checkIDPMetadata(md)
	}
	if err != nil {
		err = fmt.Errorf("samlsp: invalid identity provider metadata: %w", err)
		return func(context.Context) (*saml.EntityDescriptor, error) { return nil, err }
	}
	return StaticMetadata(md)
}

func newMetadataOptions(opts []MetadataOption) metadataOptions {
	o := metadataOptions{refreshInterval: DefaultMetadataRefreshInterval}
	for _, opt := range opts {
		opt.applyMetadata(&o)
	}
	return o
}

func parseMetadata(data []byte, o metadataOptions) (*saml.EntityDescriptor, error) {
	if len(o.certs) > 0 {
		signed, err := saml.VerifyMetadataSignature(data, o.certs)
		if err != nil {
			return nil, err
		}
		data = signed
	}
	if o.entityID != "" {
		return idpmetadata.ParseByEntityID(data, o.entityID)
	}
	md, err := idpmetadata.Parse(data)
	var multiple *idpmetadata.MultipleIDPsError
	if errors.As(err, &multiple) {
		return nil, fmt.Errorf("samlsp: %s; use WithIdentityProviderEntityID to choose one", multiple)
	}
	return md, err
}

// maxMetadataSize is the size in bytes of the largest metadata document
// RemoteMetadata reads. It leaves room for federation aggregates.
const maxMetadataSize = 256 << 20

func fetchMetadata(ctx context.Context, metadataURL url.URL, o metadataOptions) (*saml.EntityDescriptor, error) {
	data, err := idpmetadata.Fetch(ctx, o.client, metadataURL, maxMetadataSize, o.accept)
	if err != nil {
		return nil, err
	}
	return parseMetadata(data, o)
}

// RemoteMetadata returns a MetadataFunc that fetches identity provider
// metadata from metadataURL and caches it.
//
// The metadata is fetched when first needed. It is due again once the
// refresh interval (see WithRefreshInterval), its cacheDuration or its
// validUntil has passed, which picks up rotated signing certificates.
// While the cached metadata is still valid, callers get it at once and a
// single refresh runs in the background; callers wait only when there is
// no valid metadata, and then share one fetch. If a refresh fails, the
// cached metadata is kept until its validUntil, and the fetch is retried a
// minute later.
//
// Fetches are not cancelled with the context of the call that started
// them, since other calls may be waiting for them, but time out after two
// minutes. A caller that stops waiting gets its context's error.
func RemoteMetadata(metadataURL string, opts ...MetadataOption) MetadataFunc {
	o := newMetadataOptions(opts)
	r := &remoteMetadata{url: metadataURL, opts: o, now: o.clock.Now}
	return r.get
}

// MDQMetadata returns a MetadataFunc for the identity provider entityID,
// fetched from a Metadata Query service at baseURL (the SAML MDQ protocol,
// draft-young-md-query-saml): from baseURL/entities/{entityID}, URL-encoded.
// Federations publish MDQ services so that each SP need not download the
// whole aggregate. It caches and refreshes like RemoteMetadata, and takes
// the same options. Their responses are signed: pass WithMetadataSigners
// with the federation's certificate.
func MDQMetadata(baseURL, entityID string, opts ...MetadataOption) MetadataFunc {
	u := strings.TrimSuffix(baseURL, "/") + "/entities/" + url.PathEscape(entityID)
	o := newMetadataOptions(append(opts, WithIdentityProviderEntityID(entityID)))
	o.accept = "application/samlmetadata+xml"
	r := &remoteMetadata{url: u, opts: o, now: o.clock.Now}
	return r.get
}

// metadataFetchTimeout bounds a fetch that RemoteMetadata makes, which no
// caller's context cancels.
const metadataFetchTimeout = 2 * time.Minute

type remoteMetadata struct {
	url  string
	opts metadataOptions
	now  func() time.Time

	mu        sync.Mutex
	md        *saml.EntityDescriptor
	refreshAt time.Time
	inflight  *metadataFetch // the fetch in progress, or nil
}

// metadataFetch is a fetch in progress; done is closed when it ends.
type metadataFetch struct {
	done chan struct{}
	md   *saml.EntityDescriptor
	err  error
}

func (r *remoteMetadata) get(ctx context.Context) (*saml.EntityDescriptor, error) {
	r.mu.Lock()
	now := r.now()
	if r.md != nil && now.Before(r.refreshAt) {
		md := r.md
		r.mu.Unlock()
		return md, nil
	}
	f := r.startFetch(ctx)
	if r.md != nil && r.usable(now) {
		// Due for a refresh, but still valid: refresh in the background.
		md := r.md
		r.mu.Unlock()
		return md, nil
	}
	r.mu.Unlock()

	select {
	case <-f.done:
		return f.md, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// usable reports whether the cached metadata may still be used at now.
// r.mu must be held.
func (r *remoteMetadata) usable(now time.Time) bool {
	return r.md.ValidUntil.IsZero() || now.Before(r.md.ValidUntil)
}

// startFetch returns the fetch in progress, starting one if there is none.
// r.mu must be held.
func (r *remoteMetadata) startFetch(ctx context.Context) *metadataFetch {
	if r.inflight != nil {
		return r.inflight
	}
	f := &metadataFetch{done: make(chan struct{})}
	r.inflight = f
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), metadataFetchTimeout)
	go func() {
		defer cancel()
		md, err := r.fetch(fetchCtx)

		r.mu.Lock()
		now := r.now()
		switch {
		case err == nil:
			r.md = md
			r.refreshAt = r.nextRefresh(md, now)
		case r.md != nil && r.usable(now):
			// Keep the cached metadata and retry later.
			r.refreshAt = now.Add(min(r.opts.refreshInterval, metadataRetryInterval))
			md, err = r.md, nil
		}
		r.inflight = nil
		r.mu.Unlock()

		f.md, f.err = md, err
		close(f.done)
	}()
	return f
}

func (r *remoteMetadata) fetch(ctx context.Context) (*saml.EntityDescriptor, error) {
	u, err := url.Parse(r.url)
	if err != nil {
		return nil, fmt.Errorf("samlsp: invalid metadata URL: %w", err)
	}
	md, err := fetchMetadata(ctx, *u, r.opts)
	if err != nil {
		return nil, err
	}
	if err := checkIDPMetadata(md); err != nil {
		return nil, err
	}
	return md, nil
}

// nextRefresh returns when md, fetched at now, is due to be fetched again.
func (r *remoteMetadata) nextRefresh(md *saml.EntityDescriptor, now time.Time) time.Time {
	next := now.Add(r.opts.refreshInterval)
	if md.CacheDuration > 0 && md.CacheDuration < r.opts.refreshInterval {
		next = now.Add(md.CacheDuration)
	}
	if !md.ValidUntil.IsZero() && md.ValidUntil.Before(next) {
		next = md.ValidUntil
	}
	return next
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
