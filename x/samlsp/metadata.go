package samlsp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/samlmd"
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
	maxStale        time.Duration
	maxSize         int64
	onFetchError    func(error)
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
// XML signature by one of certs, made without SHA-1. Use it whenever the metadata comes over a
// channel that is not otherwise trusted. With it, RemoteMetadata and
// MDQMetadata also fetch from plain http URLs, since the signature, not
// the channel, then vouches for the metadata.
func WithMetadataSigners(certs ...*x509.Certificate) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.certs = append(o.certs, certs...) })
}

// HTTPClientOption is the option that WithHTTPClient returns. It is both an
// Option, for New, and a MetadataOption, for RemoteMetadata.
type HTTPClientOption struct{ client *http.Client }

// WithHTTPClient sets the HTTP client for requests to the IdP. Passed to
// New, it is used to resolve HTTP-Artifact responses, for back-channel
// logout and for attribute queries; passed to RemoteMetadata or
// MDQMetadata, to fetch metadata. Use it for timeouts, proxies, a TLS
// client certificate, or to limit the addresses requests may reach.
//
// Without it, New uses a client that times out after 10 seconds and
// follows no redirects (see saml.ServiceProvider.HTTPClient), and
// RemoteMetadata and MDQMetadata one that times out after two minutes.
// Both connect only to public addresses: the requests go to the URLs in
// the IdP metadata, and to the metadata URL itself, and if either comes
// from someone you do not fully trust, such as a tenant's administrator,
// they could otherwise point them at services on your own network
// (server-side request forgery). Give a client of your own to reach an
// IdP on your own network, such as on localhost during development.
//
// A client you give is used as it is. If it may be sent to URLs from
// others, guard its dialer, which checks the address actually connected
// to after DNS resolution, as the default clients do with
// code.dny.dev/ssrf:
//
//	guard := ssrf.New()
//	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
//		DialContext: (&net.Dialer{Control: guard.Safe}).DialContext,
//	}}
//
// Whichever client is used, a redirect is not followed to a URL that the
// request could not have been sent to in the first place: one that is not
// https, unless that is allowed.
func WithHTTPClient(client *http.Client) HTTPClientOption { return HTTPClientOption{client} }

func (h HTTPClientOption) applyMetadata(o *metadataOptions) { o.client = h.client }

func (h HTTPClientOption) applyConfig(c *Config, _ *configOptions) { c.httpClient = h.client }

// WithRefreshInterval sets how long RemoteMetadata keeps metadata before it
// fetches it again. The default is DefaultMetadataRefreshInterval. A
// shorter cacheDuration or an earlier validUntil in the metadata takes
// precedence. A d that is not positive means the default.
func WithRefreshInterval(d time.Duration) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if d <= 0 {
			d = DefaultMetadataRefreshInterval
		}
		o.refreshInterval = d
	})
}

// DefaultMetadataRefreshInterval is how long RemoteMetadata keeps metadata
// by default.
const DefaultMetadataRefreshInterval = time.Hour

// WithMaxStale bounds how long RemoteMetadata and MDQMetadata keep using
// metadata that sets no validUntil while fetches of it fail: once d has
// passed since it was fetched, callers wait for a fetch and get its error.
// Metadata with a validUntil (on the IdP's entity, its IDPSSODescriptor or
// AttributeAuthorityDescriptor roles, or an EntitiesDescriptor around it)
// is used until then instead, as its publisher allows. The default is
// DefaultMetadataMaxStale. A d that is not positive means the default.
func WithMaxStale(d time.Duration) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if d <= 0 {
			d = DefaultMetadataMaxStale
		}
		o.maxStale = d
	})
}

// DefaultMetadataMaxStale is how long, by default, RemoteMetadata uses
// metadata without a validUntil after fetching it, when it cannot fetch it
// again.
const DefaultMetadataMaxStale = 24 * time.Hour

// WithFetchErrorHandler makes RemoteMetadata and MDQMetadata call f with
// the error of every fetch that fails, including a refresh that fails
// while callers still get the cached metadata, which would otherwise go
// unnoticed. Use it to log or to alert. f is called from the goroutine of
// the fetch, never concurrently for one MetadataFunc, and must not block
// for long.
func WithFetchErrorHandler(f func(error)) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.onFetchError = f })
}

// WithMaxMetadataSize sets the size in bytes of the largest metadata
// document RemoteMetadata and MDQMetadata read; a larger one fails the
// fetch. The default, DefaultMaxMetadataSize, is ample for the metadata of
// one IdP or an MDQ response, but not for a large federation aggregate:
// use MDQMetadata for those if the federation offers it, or raise the
// limit. An n that is not positive means the default.
func WithMaxMetadataSize(n int64) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) {
		if n <= 0 {
			n = DefaultMaxMetadataSize
		}
		o.maxSize = n
	})
}

// DefaultMaxMetadataSize is the size in bytes of the largest metadata
// document RemoteMetadata and MDQMetadata read by default.
const DefaultMaxMetadataSize = 10 << 20

// StaticMetadataBytes returns a MetadataFunc that always returns the
// identity provider metadata in data, such as a file the IdP administrator
// sent or one embedded with go:embed. The options WithIdentityProviderEntityID,
// WithMetadataSigners and WithClock apply; the others are for
// RemoteMetadata.
//
// data is parsed once, now. If it is not valid metadata, every call of the
// MetadataFunc returns the error, so every Config method that uses it fails.
func StaticMetadataBytes(data []byte, opts ...MetadataOption) MetadataFunc {
	md, err := ParseMetadata(data, opts...)
	if err != nil {
		return func(context.Context) (*saml.EntityDescriptor, error) { return nil, err }
	}
	return StaticMetadata(md)
}

// ParseMetadata parses identity provider metadata and checks it as
// StaticMetadataBytes does, for an application that keeps or validates it
// itself: for example, to refuse an IdP's metadata when an administrator
// uploads it, rather than at the next login. The options
// WithIdentityProviderEntityID, WithMetadataSigners and WithClock apply;
// the others are for RemoteMetadata.
//
// data may be an EntityDescriptor or an EntitiesDescriptor aggregate; the
// result is the IdP's EntityDescriptor. It returns an error if data is not
// metadata, is not signed by one of the WithMetadataSigners certificates,
// or describes no single identity provider; and one that matches
// saml.ErrExpired if, by the clock of WithClock, the validUntil
// (saml-metadata §2.2.1) has passed of the IdP's entity, of its
// IDPSSODescriptor or AttributeAuthorityDescriptor roles, or of an
// EntitiesDescriptor around it.
func ParseMetadata(data []byte, opts ...MetadataOption) (*saml.EntityDescriptor, error) {
	o := newMetadataOptions(opts)
	md, err := parseMetadata(data, o)
	if err == nil {
		err = checkIDPMetadata(md)
	}
	if err == nil {
		err = checkNotExpired(md, o.clock.Now())
	}
	if err != nil {
		return nil, fmt.Errorf("samlsp: invalid identity provider metadata: %w", err)
	}
	return md, nil
}

func newMetadataOptions(opts []MetadataOption) metadataOptions {
	o := metadataOptions{
		refreshInterval: DefaultMetadataRefreshInterval,
		maxStale:        DefaultMetadataMaxStale,
		maxSize:         DefaultMaxMetadataSize,
	}
	for _, opt := range opts {
		if opt != nil {
			opt.applyMetadata(&o)
		}
	}
	return o
}

func parseMetadata(data []byte, o metadataOptions) (*saml.EntityDescriptor, error) {
	if len(o.certs) > 0 {
		signed, err := saml.VerifyMetadataSignatureRejectSHA1(data, o.certs)
		if err != nil {
			return nil, err
		}
		data = signed
	}
	if o.entityID != "" {
		return samlmd.ParseByEntityID(data, o.entityID)
	}
	md, err := samlmd.Parse(data)
	var multiple *samlmd.MultipleIDPsError
	if errors.As(err, &multiple) {
		return nil, fmt.Errorf("samlsp: %s; use WithIdentityProviderEntityID to choose one", multiple)
	}
	return md, err
}

// RemoteMetadata returns a MetadataFunc that fetches identity provider
// metadata from metadataURL and caches it.
//
// The metadata is fetched when first needed. It is due again once the
// refresh interval (see WithRefreshInterval), its cacheDuration or its
// validUntil has passed, which picks up rotated signing certificates; the
// cacheDuration and validUntil of its IDPSSODescriptor and
// AttributeAuthorityDescriptor roles count too. While the cached metadata
// is still valid, callers get it at once and a single refresh runs in the
// background; callers wait only when there is no valid metadata, and then
// share one fetch. If a refresh fails, the cached metadata is kept until
// its validUntil (or, if it has none, for WithMaxStale after it was
// fetched), and the fetch is retried a minute later. Fetches are at least
// a minute apart: when a fetch fails and there is no valid metadata, calls
// in the next minute get its error without fetching again, and metadata
// whose cacheDuration has (nearly) run out when it arrives is kept for a
// minute. WithFetchErrorHandler hears of every failed fetch.
//
// Fetched metadata is checked as ParseMetadata checks it, and refused, as
// a failed fetch, if it is expired. Without WithMetadataSigners,
// metadataURL must be https, and a redirect to a URL that is not is not
// followed, so that TLS vouches for the metadata. A document larger than
// WithMaxMetadataSize allows is refused too.
//
// With WithMetadataSigners, the signature vouches for the metadata
// instead, whatever the channel, and the signers, such as a federation's,
// may sign many entities. So WithIdentityProviderEntityID is then required,
// so that one of the others cannot be served in place of the IdP, and the
// metadata must have a validUntil, so that an old signed copy cannot be
// served after it. Without that option the MetadataFunc returns an error.
//
// Fetches are not cancelled with the context of the call that started
// them, since other calls may be waiting for them, but time out after two
// minutes. A caller that stops waiting gets its context's error.
//
// The metadata names the certificates trusted to sign the IdP's messages,
// so whoever controls metadataURL controls who can log in. Take the URL
// from an untrusted party, such as the administrator of a tenant, only
// with WithMetadataSigners, or for that party's own IdP. Fetching such a
// URL is also a request from your server to wherever it points, internal
// services included (server-side request forgery). The default client
// connects only to public addresses; a client given with WithHTTPClient
// is used as it is.
//
// To report a bad URL when the IdP is configured, rather than at the first
// login, call the returned MetadataFunc once and check its error: the
// metadata it fetches is cached for the calls that follow. Keep the
// MetadataFunc as long as the IdP is configured, rather than making a new
// one with each Config, so that its cache is kept too.
func RemoteMetadata(metadataURL string, opts ...MetadataOption) MetadataFunc {
	o := newMetadataOptions(opts)
	if len(o.certs) > 0 && o.entityID == "" {
		err := errors.New("samlsp: RemoteMetadata with WithMetadataSigners needs WithIdentityProviderEntityID, so that another entity signed by the same signers is not accepted in place of the IdP")
		return func(context.Context) (*saml.EntityDescriptor, error) { return nil, err }
	}
	return newRemote(metadataURL, o).Get
}

// MDQMetadata returns a MetadataFunc for the identity provider entityID,
// fetched from a Metadata Query service at baseURL (the SAML MDQ protocol,
// draft-young-md-query-saml): from baseURL/entities/{entityID}, URL-encoded.
// Federations publish MDQ services so that each SP need not download the
// whole aggregate. It caches, refreshes and checks like RemoteMetadata, and
// takes the same options. Their responses are signed: pass
// WithMetadataSigners with the federation's certificate. The entity is
// pinned to entityID, and signed responses must have a validUntil.
func MDQMetadata(baseURL, entityID string, opts ...MetadataOption) MetadataFunc {
	u := strings.TrimSuffix(baseURL, "/") + "/entities/" + url.PathEscape(entityID)
	o := newMetadataOptions(append(slices.Clip(opts), WithIdentityProviderEntityID(entityID)))
	o.accept = "application/samlmetadata+xml"
	return newRemote(u, o).Get
}

// newRemote returns the samlmd.Remote of RemoteMetadata and MDQMetadata.
func newRemote(metadataURL string, o metadataOptions) *samlmd.Remote {
	return &samlmd.Remote{
		URL:    metadataURL,
		Prefix: "samlsp",
		Parse: func(data []byte, now time.Time) (*saml.EntityDescriptor, error) {
			md, err := parseMetadata(data, o)
			if err == nil {
				err = checkIDPMetadata(md)
			}
			if err == nil {
				err = checkNotExpired(md, now)
			}
			return md, err
		},
		Roles:           samlmd.IDPRoles,
		Signed:          len(o.certs) > 0,
		Client:          o.client,
		Accept:          o.accept,
		MaxSize:         o.maxSize,
		RefreshInterval: o.refreshInterval,
		MaxStale:        o.maxStale,
		OnFetchError:    o.onFetchError,
		Now:             o.clock.Now,
	}
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

// checkNotExpired returns an error that matches saml.ErrExpired if md,
// identity provider metadata, is expired at now: if the validUntil of its
// entity or of its IDPSSODescriptor or AttributeAuthorityDescriptor roles
// has passed.
func checkNotExpired(md *saml.EntityDescriptor, now time.Time) error {
	if err := samlmd.Expired(md, samlmd.IDPRoles, now); err != nil {
		return fmt.Errorf("samlsp: %w", err)
	}
	return nil
}
