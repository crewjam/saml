package samlidp

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/samlmd"
)

// WithHTTPClient sets the HTTP client MDQServiceProviders fetches metadata
// with. Use it for timeouts, proxies, or a TLS client certificate. Without
// it, MDQServiceProviders uses a client that times out after two minutes
// and connects only to public addresses (see package
// github.com/crewjam/saml/x/samlsp, WithHTTPClient, for why, and for how
// to guard a client of your own). A client you give is used as it is,
// except that without WithMetadataSigners, a redirect is not followed to a
// URL that is not https.
func WithHTTPClient(client *http.Client) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.client = client })
}

// WithRefreshInterval sets how long MDQServiceProviders keeps the metadata
// of a service provider before it fetches it again. The default is
// DefaultMetadataRefreshInterval. A shorter cacheDuration or an earlier
// validUntil in the metadata takes precedence. A d that is not positive
// means the default.
func WithRefreshInterval(d time.Duration) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if d <= 0 {
			d = DefaultMetadataRefreshInterval
		}
		o.refreshInterval = d
	})
}

// DefaultMetadataRefreshInterval is how long MDQServiceProviders keeps
// metadata by default.
const DefaultMetadataRefreshInterval = time.Hour

// WithMaxStale bounds how long MDQServiceProviders keeps using metadata
// that sets no validUntil while fetches of it fail. Metadata with a
// validUntil (on the SP's entity, its SPSSODescriptor, or an
// EntitiesDescriptor around it) is used until then instead. The default is
// DefaultMetadataMaxStale. A d that is not positive means the default.
func WithMaxStale(d time.Duration) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if d <= 0 {
			d = DefaultMetadataMaxStale
		}
		o.maxStale = d
	})
}

// DefaultMetadataMaxStale is how long, by default, MDQServiceProviders
// uses metadata without a validUntil after fetching it, when it cannot
// fetch it again.
const DefaultMetadataMaxStale = 24 * time.Hour

// WithFetchErrorHandler makes MDQServiceProviders call f with the error of
// every fetch that fails, including a refresh that fails while callers
// still get the cached metadata. Use it to log or to alert. f is called
// from the goroutine of the fetch and must not block for long; it may be
// called concurrently for fetches of different service providers.
func WithFetchErrorHandler(f func(error)) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.onFetchError = f })
}

// WithMaxMetadataSize sets the size in bytes of the largest metadata
// document MDQServiceProviders reads; a larger one fails the fetch. The
// default is DefaultMaxMetadataSize. An n that is not positive means the
// default.
func WithMaxMetadataSize(n int64) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if n <= 0 {
			n = DefaultMaxMetadataSize
		}
		o.maxSize = n
	})
}

// DefaultMaxMetadataSize is the size in bytes of the largest metadata
// document MDQServiceProviders reads by default.
const DefaultMaxMetadataSize = 10 << 20

// WithMaxCachedServiceProviders sets how many service providers
// MDQServiceProviders keeps the metadata (or the failed lookup) of; past
// that, the one used least recently is forgotten, and fetched again when
// next needed. The default is DefaultMaxCachedServiceProviders. An n that
// is not positive means the default.
func WithMaxCachedServiceProviders(n int) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if n <= 0 {
			n = DefaultMaxCachedServiceProviders
		}
		o.maxCached = n
	})
}

// DefaultMaxCachedServiceProviders is how many service providers
// MDQServiceProviders keeps by default.
const DefaultMaxCachedServiceProviders = 10000

// maxEntityIDLength is the longest entityID (saml-metadata §2.2.1).
const maxEntityIDLength = 1024

// MDQServiceProviders returns a ServiceProviderFunc that fetches the
// metadata of each service provider from a Metadata Query service at
// baseURL (the SAML MDQ protocol, draft-young-md-query-saml): from
// baseURL/entities/{entityID}, URL-encoded. Federations publish MDQ
// services so that an IdP need not download the whole aggregate. An SP the
// service answers 404 Not Found for is unknown (ErrUnknownServiceProvider).
//
// The metadata of each SP is cached and refreshed as
// github.com/crewjam/saml/x/samlsp.RemoteMetadata does: it is due again
// once WithRefreshInterval, or its cacheDuration or validUntil, has passed;
// a refresh runs in the background while the cached metadata is still
// valid; a failed refresh keeps the cached metadata until its validUntil
// (or WithMaxStale); and fetches of one SP are at least a minute apart, so
// that a failed lookup, an unknown SP included, is remembered for a
// minute. At most WithMaxCachedServiceProviders SPs are kept. Fetched
// metadata is checked as ParseMetadata checks it: it must describe the SP
// asked for and not be expired.
//
// MDQ responses are signed: pass WithMetadataSigners with the federation's
// certificate. Signed metadata must then have a validUntil, so that an old
// signed copy cannot be served in place of the current one. Without it,
// nothing but TLS vouches for the metadata, so baseURL must be https, and
// a redirect to a URL that is not is not followed. The options WithMetadataSigners, WithClock, WithHTTPClient,
// WithRefreshInterval, WithMaxStale, WithFetchErrorHandler,
// WithMaxMetadataSize and WithMaxCachedServiceProviders apply;
// WithServiceProviderEntityID does not.
//
// The entityID comes from the request, so anyone can make the IdP query
// the service for an entityID of their choosing; each unknown one costs a
// fetch, and can push a known SP out of the cache. An entityID longer than
// 1024 characters is unknown without a fetch.
//
// Fetches are not cancelled with the context of the call that started
// them, since other calls may be waiting for them, but time out after two
// minutes. A caller that stops waiting gets its context's error.
func MDQServiceProviders(baseURL string, opts ...MetadataOption) ServiceProviderFunc {
	o := metadataOptions{
		refreshInterval: DefaultMetadataRefreshInterval,
		maxStale:        DefaultMetadataMaxStale,
		maxSize:         DefaultMaxMetadataSize,
		maxCached:       DefaultMaxCachedServiceProviders,
	}
	for _, opt := range opts {
		if opt != nil {
			opt.applyMetadata(&o)
		}
	}
	c := &mdqCache{
		baseURL: strings.TrimSuffix(baseURL, "/") + "/entities/",
		opts:    o,
		byID:    make(map[string]*list.Element),
		lru:     list.New(),
	}
	return c.get
}

// mdqCache is the cache of MDQServiceProviders: a samlmd.Remote per
// service provider, the one used most recently at the front of lru.
type mdqCache struct {
	baseURL string
	opts    metadataOptions

	mu   sync.Mutex
	byID map[string]*list.Element // of *mdqEntry
	lru  *list.List
}

type mdqEntry struct {
	entityID string
	remote   *samlmd.Remote
}

func (c *mdqCache) get(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
	if entityID == "" || len(entityID) > maxEntityIDLength {
		return nil, unknownServiceProvider(entityID)
	}
	md, err := c.remote(entityID).Get(ctx)
	if status := (*samlmd.StatusError)(nil); errors.As(err, &status) && status.Code == http.StatusNotFound {
		return nil, unknownServiceProvider(entityID)
	}
	if err != nil {
		return nil, err
	}
	return md, nil
}

// remote returns the samlmd.Remote of entityID, making one if there is
// none, and marks it used.
func (c *mdqCache) remote(entityID string) *samlmd.Remote {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byID[entityID]; ok {
		c.lru.MoveToFront(e)
		return e.Value.(*mdqEntry).remote
	}
	for c.lru.Len() >= c.opts.maxCached {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.byID, oldest.Value.(*mdqEntry).entityID)
	}
	r := c.newRemote(entityID)
	c.byID[entityID] = c.lru.PushFront(&mdqEntry{entityID: entityID, remote: r})
	return r
}

func (c *mdqCache) newRemote(entityID string) *samlmd.Remote {
	o := c.opts
	o.entityID = entityID
	return &samlmd.Remote{
		URL:    c.baseURL + url.PathEscape(entityID),
		Prefix: "samlidp",
		Parse: func(data []byte, now time.Time) (*saml.EntityDescriptor, error) {
			md, err := parseMetadata(data, o)
			if err == nil {
				err = checkNotExpired(md, now)
			}
			if err != nil {
				return nil, fmt.Errorf("samlidp: invalid metadata for service provider %q: %w", entityID, err)
			}
			return md, nil
		},
		Roles:           samlmd.SPRoles,
		Signed:          len(o.certs) > 0,
		Client:          o.client,
		Accept:          "application/samlmetadata+xml",
		MaxSize:         o.maxSize,
		RefreshInterval: o.refreshInterval,
		MaxStale:        o.maxStale,
		OnFetchError:    o.onFetchError,
		Now:             func() time.Time { return clockNow(o.clock) },
	}
}
