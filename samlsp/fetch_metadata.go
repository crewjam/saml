package samlsp

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/samlmd"
)

// ParseMetadata parses arbitrary SAML IDP metadata.
//
// Note: this is needed because IDP metadata is sometimes wrapped in
// an <EntitiesDescriptor>, and sometimes the top level element is an
// <EntityDescriptor>.
//
// An <EntitiesDescriptor> must hold exactly one entity with an
// IDPSSODescriptor (nested <EntitiesDescriptor> elements included), which
// is returned: ParseMetadata cannot tell which of several IDPs the caller
// means to trust. Use ParseMetadataByEntityID to pick one out of an
// aggregate.
//
// When the entity is taken from an <EntitiesDescriptor>, the validUntil and
// cacheDuration of the enclosing <EntitiesDescriptor> elements are carried
// down to it, since the caching policy of a parent element takes precedence
// (saml-metadata-2.0-os §4.3.1): the returned ValidUntil is the earliest
// validUntil of the entity and of the aggregates that enclose it, and
// CacheDuration the shortest cacheDuration, among those that are set.
// ParseMetadataByEntityID and the signed and Fetch variants do the same.
// See saml.ServiceProvider.RejectExpiredIDPMetadata to refuse to rely on
// metadata whose validUntil has passed.
//
// ParseMetadata does not check a signature on the metadata, so the
// metadata must come from a source the caller trusts. See
// ParseSignedMetadata.
func ParseMetadata(data []byte) (*saml.EntityDescriptor, error) {
	entity, err := samlmd.Parse(data)
	var multiple *samlmd.MultipleIDPsError
	if errors.As(err, &multiple) {
		return nil, fmt.Errorf("%s; use ParseMetadataByEntityID to choose one", multiple)
	}
	return entity, err
}

// ParseMetadataByEntityID parses SAML metadata and returns the
// EntityDescriptor whose entityID is entityID.
//
// The metadata may be a single <EntityDescriptor> or an <EntitiesDescriptor>
// aggregate, such as the metadata published by a federation (e.g. eduGAIN or
// InCommon). Nested <EntitiesDescriptor> elements are searched too. Unlike
// ParseMetadata, which returns the first entity with an IDPSSODescriptor, this
// lets the caller pick a specific IDP out of an aggregate.
//
// Like ParseMetadata, it carries the validUntil and cacheDuration of the
// enclosing <EntitiesDescriptor> elements down to the returned entity.
//
// It returns an error if no entity with that entityID is found.
func ParseMetadataByEntityID(data []byte, entityID string) (*saml.EntityDescriptor, error) {
	return samlmd.ParseByEntityID(data, entityID)
}

// ParseSignedMetadata is ParseMetadata for metadata whose root element must
// carry a valid enveloped XML signature made with one of certs, the IDP's
// (or its federation's) metadata signing certificates, obtained from a
// source the caller trusts. Only the content the signature covers is
// parsed. See saml.VerifyMetadataSignature.
func ParseSignedMetadata(data []byte, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	signed, err := saml.VerifyMetadataSignature(data, certs)
	if err != nil {
		return nil, err
	}
	return ParseMetadata(signed)
}

// ParseSignedMetadataByEntityID is ParseMetadataByEntityID for metadata
// whose root element must carry a valid enveloped XML signature made with
// one of certs. See ParseSignedMetadata.
func ParseSignedMetadataByEntityID(data []byte, entityID string, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	signed, err := saml.VerifyMetadataSignature(data, certs)
	if err != nil {
		return nil, err
	}
	return ParseMetadataByEntityID(signed, entityID)
}

// FetchMetadata returns metadata from an IDP metadata URL.
//
// If httpClient is nil, a client with a two-minute timeout that connects
// only to public addresses is used: pass a client of your own to fetch
// metadata from your own network, such as from localhost. Only a 2xx
// response is accepted.
//
// The metadata names the certificates the service provider trusts to sign
// assertions, so whoever controls the response controls who can log in. It
// is not authenticated beyond what httpClient does: use an https URL, and
// prefer FetchSignedMetadata, or metadata kept with the application.
//
// If the URL comes from someone you do not fully trust and you pass an
// httpClient, guard its dialer against reaching your own network
// (server-side request forgery), as the default client does, such as with
// code.dny.dev/ssrf.
func FetchMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseMetadata(data)
}

// FetchMetadataByEntityID fetches metadata from metadataURL and returns the
// entity whose entityID is entityID. Use it to select an IDP from aggregate
// metadata, such as a federation's metadata feed. See ParseMetadataByEntityID.
func FetchMetadataByEntityID(ctx context.Context, httpClient *http.Client, metadataURL url.URL, entityID string) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseMetadataByEntityID(data, entityID)
}

// FetchSignedMetadata fetches metadata from metadataURL and parses it with
// ParseSignedMetadata: its root element must carry a valid signature made
// with one of certs.
func FetchSignedMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseSignedMetadata(data, certs)
}

// FetchSignedMetadataByEntityID fetches metadata from metadataURL and parses
// it with ParseSignedMetadataByEntityID.
func FetchSignedMetadataByEntityID(ctx context.Context, httpClient *http.Client, metadataURL url.URL, entityID string, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseSignedMetadataByEntityID(data, entityID, certs)
}

// MaxMetadataSize is the size in bytes of the largest metadata document that
// FetchMetadata and the other Fetch functions read. A larger response is
// refused rather than read into memory in full. The default leaves room for
// federation aggregates, which run to tens of megabytes; lower it when
// fetching a single IDP's metadata.
var MaxMetadataSize int64 = 256 << 20

func fetchMetadataBytes(ctx context.Context, httpClient *http.Client, metadataURL url.URL) ([]byte, error) {
	data, err := samlmd.Fetch(ctx, httpClient, metadataURL, MaxMetadataSize, "")
	var tooLarge *samlmd.TooLargeError
	if errors.As(err, &tooLarge) {
		return nil, fmt.Errorf("%s (MaxMetadataSize)", tooLarge)
	}
	return data, err
}
