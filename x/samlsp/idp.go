package samlsp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	legacy "github.com/crewjam/saml/samlsp"
)

// IdentityProvider is a SAML identity provider (IdP), described by its
// metadata. It is immutable and safe for concurrent use.
type IdentityProvider struct {
	metadata *saml.EntityDescriptor
}

// IdentityProviderOption configures NewIdentityProvider and
// ParseIdentityProviderMetadata.
type IdentityProviderOption func(*identityProviderOptions)

type identityProviderOptions struct {
	entityID string
	certs    []*x509.Certificate
}

// WithEntityID selects the identity provider with this entityID from
// metadata that is an EntitiesDescriptor aggregate, such as a federation
// feed. It is required when the aggregate holds more than one IdP.
func WithEntityID(entityID string) IdentityProviderOption {
	return func(o *identityProviderOptions) { o.entityID = entityID }
}

// WithMetadataSigners makes metadata acceptable only if it carries a valid
// XML signature by one of certs. Use it whenever the metadata is fetched
// over a channel that is not otherwise trusted.
func WithMetadataSigners(certs ...*x509.Certificate) IdentityProviderOption {
	return func(o *identityProviderOptions) { o.certs = append(o.certs, certs...) }
}

// NewIdentityProvider fetches the identity provider's metadata from
// metadataURL and returns an IdentityProvider. It uses the HTTP client from
// ClientContext, if any.
//
// The metadata is read once. To pick up certificate rotation, call
// NewIdentityProvider again and replace Config.IdentityProvider.
func NewIdentityProvider(ctx context.Context, metadataURL string, opts ...IdentityProviderOption) (*IdentityProvider, error) {
	u, err := url.Parse(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("samlsp: invalid metadata URL: %w", err)
	}
	var o identityProviderOptions
	for _, opt := range opts {
		opt(&o)
	}
	client := clientFromContext(ctx)

	var md *saml.EntityDescriptor
	switch {
	case len(o.certs) > 0 && o.entityID != "":
		md, err = legacy.FetchSignedMetadataByEntityID(ctx, client, *u, o.entityID, o.certs)
	case len(o.certs) > 0:
		md, err = legacy.FetchSignedMetadata(ctx, client, *u, o.certs)
	case o.entityID != "":
		md, err = legacy.FetchMetadataByEntityID(ctx, client, *u, o.entityID)
	default:
		md, err = legacy.FetchMetadata(ctx, client, *u)
	}
	if err != nil {
		return nil, err
	}
	return NewIdentityProviderFromMetadata(md)
}

// ParseIdentityProviderMetadata parses identity provider metadata in data and
// returns an IdentityProvider. Use it for metadata loaded from a file or
// configuration rather than from a URL.
func ParseIdentityProviderMetadata(data []byte, opts ...IdentityProviderOption) (*IdentityProvider, error) {
	var o identityProviderOptions
	for _, opt := range opts {
		opt(&o)
	}
	var (
		md  *saml.EntityDescriptor
		err error
	)
	switch {
	case len(o.certs) > 0 && o.entityID != "":
		md, err = legacy.ParseSignedMetadataByEntityID(data, o.entityID, o.certs)
	case len(o.certs) > 0:
		md, err = legacy.ParseSignedMetadata(data, o.certs)
	case o.entityID != "":
		md, err = legacy.ParseMetadataByEntityID(data, o.entityID)
	default:
		md, err = legacy.ParseMetadata(data)
	}
	if err != nil {
		return nil, err
	}
	return NewIdentityProviderFromMetadata(md)
}

// NewIdentityProviderFromMetadata returns an IdentityProvider for metadata that has already
// been parsed. The caller must not modify md afterwards.
func NewIdentityProviderFromMetadata(md *saml.EntityDescriptor) (*IdentityProvider, error) {
	if md == nil {
		return nil, errors.New("samlsp: nil identity provider metadata")
	}
	if len(md.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("samlsp: metadata for %q has no IDPSSODescriptor", md.EntityID)
	}
	return &IdentityProvider{metadata: md}, nil
}

// EntityID returns the entityID of the identity provider. It is the Issuer
// of the assertions the provider sends.
func (p *IdentityProvider) EntityID() string { return p.metadata.EntityID }

// Metadata returns the identity provider's metadata. It must not be
// modified.
func (p *IdentityProvider) Metadata() *saml.EntityDescriptor { return p.metadata }

type clientContextKey struct{}

// ClientContext returns a copy of ctx that carries client. NewIdentityProvider uses
// client to fetch metadata, and Config.ParseResponse uses it to resolve
// HTTP-Artifact responses (the artifact resolution protocol).
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
