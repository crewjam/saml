package samlidp

import (
	"container/list"
	"context"
	"crypto/sha1" //nolint:gosec // the MDQ transformed identifier is defined with SHA-1 (draft-young-md-query §2.5)
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
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
// MDQServiceProviders keeps the metadata of; past that, the one used least
// recently is forgotten, and fetched again when next needed. As many
// failed lookups, unknown SPs included, are kept apart from them, so that
// they never push the metadata of an SP out. The default is
// DefaultMaxCachedServiceProviders. An n that is not positive means the
// default.
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

// WithMaxConcurrentFetches sets how many fetches of the metadata of a
// service provider that MDQServiceProviders has none of may be in
// progress at once. While that many are, an SP it has no metadata for, nor
// a failed lookup of, is unknown (ErrUnknownServiceProvider) without a
// fetch, and the next lookup of it tries again. Refreshes of metadata
// already cached do not count. The default is
// DefaultMaxConcurrentFetches. An n that is not positive means the
// default.
func WithMaxConcurrentFetches(n int) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if n <= 0 {
			n = DefaultMaxConcurrentFetches
		}
		o.maxFetches = n
	})
}

// DefaultMaxConcurrentFetches is how many fetches of the metadata of new
// service providers MDQServiceProviders makes at once by default.
const DefaultMaxConcurrentFetches = 32

// WithSHA1Identifiers makes MDQServiceProviders ask the service for each
// service provider by the transformed identifier "{sha1}" followed by the
// lowercase hex SHA-1 hash of its entityID (draft-young-md-query §2.5),
// rather than by the entityID itself, for services that support only
// that, or that sit behind proxies that mangle URLs. The metadata
// returned must still be that of the entityID asked for.
func WithSHA1Identifiers() MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.sha1IDs = true })
}

// maxEntityIDLength is the longest entityID (saml-metadata §2.2.1).
const maxEntityIDLength = 1024

// MDQServiceProviders returns a ServiceProviderFunc that fetches the
// metadata of each service provider from a Metadata Query service at
// baseURL (the SAML MDQ protocol, draft-young-md-query-saml): from
// baseURL/entities/{entityID}, with every character of the entityID but
// the unreserved ones of RFC 3986 percent-encoded (draft-young-md-query
// §3), or, with WithSHA1Identifiers, by its SHA-1 hash. Federations
// publish MDQ services so that an IdP need not download the whole
// aggregate. An SP the service answers 404 Not Found for is unknown
// (ErrUnknownServiceProvider).
//
// The metadata of each SP is cached and refreshed as
// github.com/crewjam/saml/x/samlsp.RemoteMetadata does: it is due again
// once WithRefreshInterval, or its cacheDuration or validUntil, has passed;
// a refresh runs in the background while the cached metadata is still
// valid; a failed refresh keeps the cached metadata until its validUntil
// (or WithMaxStale); and fetches of one SP are at least a minute apart, so
// that a failed lookup, an unknown SP included, is remembered for a
// minute. At most WithMaxCachedServiceProviders SPs are kept, and as many
// failed lookups apart from them. Fetched metadata is checked as
// ParseMetadata checks it: it must describe the SP asked for and not be
// expired.
//
// MDQ responses are signed: pass WithMetadataSigners with the federation's
// certificate. Signed metadata must then have a validUntil, so that an old
// signed copy cannot be served in place of the current one. Without it,
// nothing but TLS vouches for the metadata, so baseURL must be https, and
// a redirect to a URL that is not is not followed. The options
// WithMetadataSigners, WithClock, WithHTTPClient, WithRefreshInterval,
// WithMaxStale, WithFetchErrorHandler, WithMaxMetadataSize,
// WithMaxCachedServiceProviders, WithMaxConcurrentFetches and
// WithSHA1Identifiers apply; WithServiceProviderEntityID does not.
//
// The entityID comes from the request, so anyone can make the IdP query
// the service for an entityID of their choosing. Each unknown one costs a
// fetch, but at most WithMaxConcurrentFetches are in progress at once, and
// a failed lookup does not push a known SP out of the cache. An entityID
// longer than 1024 characters is unknown without a fetch.
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
		maxFetches:      DefaultMaxConcurrentFetches,
	}
	for _, opt := range opts {
		if opt != nil {
			opt.applyMetadata(&o)
		}
	}
	c := &mdqCache{
		baseURL: strings.TrimSuffix(baseURL, "/") + "/entities/",
		opts:    o,
		byID:    make(map[string]*mdqEntry),
		known:   list.New(),
		failed:  list.New(),
		fetches: make(chan struct{}, o.maxFetches),
	}
	return c.get
}

// mdqCache is the cache of MDQServiceProviders: a samlmd.Remote per
// service provider. An entry starts in failed, and moves to known once it
// has returned metadata; each list has the entry used most recently at
// its front, and holds at most opts.maxCached entries. The entries in
// failed fetch only with a token of fetches, so that lookups of unknown
// SPs make at most opts.maxFetches fetches at once.
type mdqCache struct {
	baseURL string
	opts    metadataOptions

	// fetches holds a token for each lookup in progress of an entry in
	// failed.
	fetches chan struct{}

	mu     sync.Mutex
	byID   map[string]*mdqEntry
	known  *list.List // of *mdqEntry
	failed *list.List // of *mdqEntry
}

type mdqEntry struct {
	entityID string
	remote   *samlmd.Remote
	list     *list.List // known or failed
	elem     *list.Element
}

func (c *mdqCache) get(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
	if entityID == "" || len(entityID) > maxEntityIDLength {
		return nil, unknownServiceProvider(entityID)
	}
	e, token := c.entry(entityID)
	if e == nil {
		return nil, fmt.Errorf("samlidp: too many metadata fetches in progress to look up service provider %q: %w",
			entityID, errors.Join(ErrUnknownServiceProvider, os.ErrNotExist))
	}
	var md *saml.EntityDescriptor
	var err error
	if token {
		md, err = c.getWithToken(ctx, e)
	} else {
		md, err = e.remote.Get(ctx)
	}
	if err == nil {
		c.markKnown(e)
	}
	if status := (*samlmd.StatusError)(nil); errors.As(err, &status) && status.Code == http.StatusNotFound {
		return nil, unknownServiceProvider(entityID)
	}
	if err != nil {
		return nil, err
	}
	return md, nil
}

// entry returns the entry of entityID, marked used, making one in failed
// if there is none, and whether it took a token of c.fetches for it. An
// entry that has never returned metadata, in failed, may fetch only with a
// token, which getWithToken gives back; if there is none to take, entry
// returns nil, and makes no entry.
func (c *mdqCache) entry(entityID string) (*mdqEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byID[entityID]
	if ok && e.list == c.known {
		e.list.MoveToFront(e.elem)
		return e, false
	}
	select {
	case c.fetches <- struct{}{}:
	default:
		return nil, false
	}
	if ok {
		e.list.MoveToFront(e.elem)
		return e, true
	}
	e = &mdqEntry{entityID: entityID, remote: c.newRemote(entityID)}
	c.push(c.failed, e)
	return e, true
}

// getWithToken gets the metadata of e, for which entry took a token of
// c.fetches, and gives the token back once the fetch, if any, ends,
// whether or not ctx ends first.
func (c *mdqCache) getWithToken(ctx context.Context, e *mdqEntry) (*saml.EntityDescriptor, error) {
	type result struct {
		md  *saml.EntityDescriptor
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-c.fetches }()
		md, err := e.remote.Get(context.WithoutCancel(ctx))
		done <- result{md, err}
	}()
	select {
	case r := <-done:
		return r.md, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// markKnown moves e, which has returned metadata, to known, unless it has
// been forgotten. Only entries in known push others out of it.
func (c *mdqCache) markKnown(e *mdqEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.list == c.known || c.byID[e.entityID] != e {
		return
	}
	e.list.Remove(e.elem)
	c.push(c.known, e)
}

// push puts e at the front of l, after forgetting the entries at its back
// that it has no room for. c.mu must be held.
func (c *mdqCache) push(l *list.List, e *mdqEntry) {
	for l.Len() >= c.opts.maxCached {
		oldest := l.Remove(l.Back()).(*mdqEntry)
		delete(c.byID, oldest.entityID)
	}
	e.list, e.elem = l, l.PushFront(e)
	c.byID[e.entityID] = e
}

// mdqPath returns the path segment that names entityID to the MDQ
// service: entityID, or with sha1, its transformed identifier
// (draft-young-md-query §2.5), percent-encoded.
func mdqPath(entityID string, sha1IDs bool) string {
	if sha1IDs {
		sum := sha1.Sum([]byte(entityID)) //nolint:gosec // the MDQ transformed identifier is defined with SHA-1, not used for security
		entityID = "{sha1}" + hex.EncodeToString(sum[:])
	}
	return percentEncode(entityID)
}

// percentEncode returns s with every byte but the unreserved characters
// of RFC 3986 §2.3 (ALPHA, DIGIT, "-", ".", "_" and "~") percent-encoded,
// as the MDQ protocol requires of identifiers (draft-young-md-query §3).
// url.PathEscape is not enough: it leaves sub-delimiters such as ":", "+"
// and "&" as they are.
func percentEncode(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case 'A' <= ch && ch <= 'Z', 'a' <= ch && ch <= 'z', '0' <= ch && ch <= '9',
			ch == '-', ch == '.', ch == '_', ch == '~':
			b.WriteByte(ch)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[ch>>4])
			b.WriteByte(hexDigits[ch&15])
		}
	}
	return b.String()
}

func (c *mdqCache) newRemote(entityID string) *samlmd.Remote {
	o := c.opts
	o.entityID = entityID
	return &samlmd.Remote{
		URL:    c.baseURL + mdqPath(entityID, o.sha1IDs),
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
