package samlidp

import (
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// ServiceProviderFunc returns the metadata of the service provider (SP)
// whose entity ID is entityID, which names the SP's assertion consumer
// services, where Responses may be sent, and the certificates trusted to
// sign its requests and to encrypt assertions to.
//
// If the IdP does not serve that SP, it must return an error that matches
// ErrUnknownServiceProvider (saml.ErrUnknownServiceProvider) or
// os.ErrNotExist. Any other error is reported as a failure to look the SP
// up.
//
// Config calls it every time it handles a request or makes a Response for
// an SP, with that call's context, so it must be cheap and safe for
// concurrent use. Use StaticServiceProviders, or write your own: for
// example, to read metadata from a database. The returned metadata must not
// be modified afterwards.
type ServiceProviderFunc func(ctx context.Context, entityID string) (*saml.EntityDescriptor, error)

// ErrUnknownServiceProvider matches the errors of a request from, or a
// Response to, a service provider the ServiceProviderFunc does not know.
// It is saml.ErrUnknownServiceProvider.
var ErrUnknownServiceProvider = saml.ErrUnknownServiceProvider

// StaticServiceProviders returns a ServiceProviderFunc that serves the
// service providers mds, looked up by their EntityID. Metadata that lists
// no SPSSODescriptor is left out; of several with the same EntityID, the
// last is kept.
func StaticServiceProviders(mds ...*saml.EntityDescriptor) ServiceProviderFunc {
	byID := make(map[string]*saml.EntityDescriptor, len(mds))
	for _, md := range mds {
		if md != nil && len(md.SPSSODescriptors) > 0 {
			byID[md.EntityID] = md
		}
	}
	return func(_ context.Context, entityID string) (*saml.EntityDescriptor, error) {
		if md, ok := byID[entityID]; ok {
			return md, nil
		}
		return nil, unknownServiceProvider(entityID)
	}
}

// unknownServiceProvider returns the error of a lookup of entityID that
// found nothing.
func unknownServiceProvider(entityID string) error {
	return fmt.Errorf("samlidp: service provider %q: %w", entityID, errors.Join(ErrUnknownServiceProvider, os.ErrNotExist))
}

// lookupServiceProvider calls lookup and checks what it returns.
func lookupServiceProvider(ctx context.Context, lookup ServiceProviderFunc, entityID string) (*saml.EntityDescriptor, error) {
	md, err := lookup(ctx, entityID)
	switch {
	case errors.Is(err, ErrUnknownServiceProvider) || errors.Is(err, os.ErrNotExist):
		return nil, unknownServiceProvider(entityID)
	case err != nil:
		return nil, fmt.Errorf("samlidp: cannot get the metadata of service provider %q: %w", entityID, err)
	case md == nil:
		return nil, unknownServiceProvider(entityID)
	case md.EntityID != entityID:
		return nil, fmt.Errorf("samlidp: the metadata for service provider %q is that of %q", entityID, md.EntityID)
	case len(md.SPSSODescriptors) == 0:
		return nil, fmt.Errorf("samlidp: the metadata of %q has no SPSSODescriptor", entityID)
	}
	return md, nil
}

// ServiceProvider returns the metadata of the service provider entityID,
// from the ServiceProviderFunc passed to New. The error matches
// ErrUnknownServiceProvider if it does not know the SP.
func (c *Config) ServiceProvider(ctx context.Context, entityID string) (*saml.EntityDescriptor, error) {
	return lookupServiceProvider(ctx, c.serviceProviders, entityID)
}

// serviceProviderProvider is the saml.ServiceProviderProvider of the
// IdentityProviders a Config builds. It calls the ServiceProviderFunc with
// the context of the request.
type serviceProviderProvider ServiceProviderFunc

func (p serviceProviderProvider) GetServiceProvider(r *http.Request, entityID string) (*saml.EntityDescriptor, error) {
	// Package saml recognises an unknown SP by os.ErrNotExist, which the
	// error of lookupServiceProvider then matches.
	return lookupServiceProvider(r.Context(), ServiceProviderFunc(p), entityID)
}

// MetadataOption configures ParseMetadata.
type MetadataOption interface {
	applyMetadata(*metadataOptions)
}

type metadataOptionFunc func(*metadataOptions)

func (f metadataOptionFunc) applyMetadata(o *metadataOptions) { f(o) }

type metadataOptions struct {
	entityID string
	certs    []*x509.Certificate
}

// WithServiceProviderEntityID selects the service provider with this
// entityID from metadata that is an EntitiesDescriptor aggregate. It is
// required when the aggregate holds more than one SP.
func WithServiceProviderEntityID(entityID string) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.entityID = entityID })
}

// WithMetadataSigners makes metadata acceptable only if it carries a valid
// XML signature by one of certs. Use it whenever the metadata comes over a
// channel that is not otherwise trusted.
func WithMetadataSigners(certs ...*x509.Certificate) MetadataOption {
	return metadataOptionFunc(func(o *metadataOptions) { o.certs = append(o.certs, certs...) })
}

// ParseMetadata parses service provider metadata, for an application that
// registers SPs: for example, to refuse an SP's metadata when an
// administrator uploads it, rather than at its first login.
//
// data may be an EntityDescriptor or an EntitiesDescriptor aggregate; the
// result is the SP's EntityDescriptor. It returns an error if data is not
// metadata, is not signed by one of the WithMetadataSigners certificates,
// or describes no single service provider.
func ParseMetadata(data []byte, opts ...MetadataOption) (*saml.EntityDescriptor, error) {
	var o metadataOptions
	for _, opt := range opts {
		opt.applyMetadata(&o)
	}
	md, err := parseMetadata(data, o)
	if err != nil {
		return nil, fmt.Errorf("samlidp: invalid service provider metadata: %w", err)
	}
	return md, nil
}

func parseMetadata(data []byte, o metadataOptions) (*saml.EntityDescriptor, error) {
	if len(o.certs) > 0 {
		signed, err := saml.VerifyMetadataSignature(data, o.certs)
		if err != nil {
			return nil, err
		}
		data = signed
	}
	if err := xmlroundtrip.Validate(data); err != nil {
		return nil, err
	}
	var root struct{ XMLName xml.Name }
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	var candidates []*saml.EntityDescriptor
	switch root.XMLName {
	case xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "EntityDescriptor"}:
		md := &saml.EntityDescriptor{}
		if err := xml.Unmarshal(data, md); err != nil {
			return nil, err
		}
		candidates = []*saml.EntityDescriptor{md}
	case xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "EntitiesDescriptor"}:
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		candidates = spEntities(entities)
	default:
		return nil, fmt.Errorf("the root element is %s %s, not a metadata EntityDescriptor", root.XMLName.Space, root.XMLName.Local)
	}

	var found []*saml.EntityDescriptor
	for _, md := range candidates {
		if len(md.SPSSODescriptors) > 0 && (o.entityID == "" || md.EntityID == o.entityID) {
			found = append(found, md)
		}
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0 && o.entityID != "":
		return nil, fmt.Errorf("no service provider %q in the metadata", o.entityID)
	case len(found) == 0:
		return nil, errors.New("the metadata describes no service provider")
	default:
		return nil, fmt.Errorf("the metadata describes %d service providers; use WithServiceProviderEntityID to choose one", len(found))
	}
}

// spEntities returns the entities in entities and in any EntitiesDescriptor
// nested in it.
func spEntities(entities *saml.EntitiesDescriptor) []*saml.EntityDescriptor {
	out := make([]*saml.EntityDescriptor, 0, len(entities.EntityDescriptors))
	for i := range entities.EntityDescriptors {
		out = append(out, &entities.EntityDescriptors[i])
	}
	for i := range entities.EntitiesDescriptors {
		out = append(out, spEntities(&entities.EntitiesDescriptors[i])...)
	}
	return out
}
