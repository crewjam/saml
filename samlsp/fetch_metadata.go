package samlsp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/internal/xmlroundtrip"

	"github.com/crewjam/saml/logger"

	"github.com/crewjam/saml"
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
	if err := xmlroundtrip.Validate(data); err != nil {
		return nil, err
	}

	root, err := metadataRootElement(data)
	if err != nil {
		return nil, err
	}

	if root.Local != "EntitiesDescriptor" {
		entity := &saml.EntityDescriptor{}
		if err := xml.Unmarshal(data, entity); err != nil {
			return nil, err
		}
		return entity, nil
	}

	// Unmarshal the whole aggregate, so that malformed metadata is rejected
	// wherever the error is.
	entities := &saml.EntitiesDescriptor{}
	if err := xml.Unmarshal(data, entities); err != nil {
		return nil, err
	}
	if n := countIDPEntities(entities); n > 1 {
		return nil, fmt.Errorf("metadata holds %d entities with an IDPSSODescriptor; use ParseMetadataByEntityID to choose one", n)
	}
	// There is at most one IDP entity, so document order does not matter
	// and it can be found in the parsed aggregate.
	entity := findIDPEntity(entities, metadataValidity{})
	if entity == nil {
		return nil, errors.New("no entity found with IDPSSODescriptor")
	}
	return entity, nil
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
	if err := xmlroundtrip.Validate(data); err != nil {
		return nil, err
	}

	root, err := metadataRootElement(data)
	if err != nil {
		return nil, err
	}

	if root.Local == "EntitiesDescriptor" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		if entity := findEntityByID(entities, entityID, metadataValidity{}); entity != nil {
			return entity, nil
		}
	} else {
		entity := &saml.EntityDescriptor{}
		if err := xml.Unmarshal(data, entity); err != nil {
			return nil, err
		}
		if entity.EntityID == entityID {
			return entity, nil
		}
	}
	return nil, fmt.Errorf("no entity found with entityID %q", entityID)
}

// countIDPEntities returns the number of entities with an IDPSSODescriptor
// in entities and in any EntitiesDescriptor nested in it.
func countIDPEntities(entities *saml.EntitiesDescriptor) int {
	n := 0
	for _, e := range entities.EntityDescriptors {
		if len(e.IDPSSODescriptors) > 0 {
			n++
		}
	}
	for i := range entities.EntitiesDescriptors {
		n += countIDPEntities(&entities.EntitiesDescriptors[i])
	}
	return n
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

// metadataRootElement returns the name of the root element of data.
func metadataRootElement(data []byte) (xml.Name, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.Name{}, err
		}
		if start, ok := token.(xml.StartElement); ok {
			return start.Name, nil
		}
	}
}

// findEntityByID returns the first EntityDescriptor in entities, or in any
// EntitiesDescriptor nested in it, whose entityID is entityID, with the
// validity of entities and of the aggregates enclosing it (outer) applied.
func findEntityByID(entities *saml.EntitiesDescriptor, entityID string, outer metadataValidity) *saml.EntityDescriptor {
	validity := outer.narrow(entities.ValidUntil, entities.CacheDuration)
	for i := range entities.EntityDescriptors {
		if entities.EntityDescriptors[i].EntityID == entityID {
			// Copy the entity, so that it does not keep the rest of the
			// aggregate in memory.
			entity := entities.EntityDescriptors[i]
			validity.applyTo(&entity)
			return &entity
		}
	}
	for i := range entities.EntitiesDescriptors {
		if entity := findEntityByID(&entities.EntitiesDescriptors[i], entityID, validity); entity != nil {
			return entity
		}
	}
	return nil
}

// findIDPEntity returns an EntityDescriptor with an IDPSSODescriptor in
// entities, or in any EntitiesDescriptor nested in it, with the validity of
// entities and of the aggregates enclosing it (outer) applied, or nil if
// there is none.
func findIDPEntity(entities *saml.EntitiesDescriptor, outer metadataValidity) *saml.EntityDescriptor {
	validity := outer.narrow(entities.ValidUntil, entities.CacheDuration)
	for i := range entities.EntityDescriptors {
		if len(entities.EntityDescriptors[i].IDPSSODescriptors) > 0 {
			// Copy the entity, so that it does not keep the rest of the
			// aggregate in memory.
			entity := entities.EntityDescriptors[i]
			validity.applyTo(&entity)
			return &entity
		}
	}
	for i := range entities.EntitiesDescriptors {
		if entity := findIDPEntity(&entities.EntitiesDescriptors[i], validity); entity != nil {
			return entity
		}
	}
	return nil
}

// metadataValidity is the caching policy that enclosing EntitiesDescriptor
// elements impose on the entities in them: the earliest validUntil and the
// shortest cacheDuration among them, nil where none sets one.
type metadataValidity struct {
	validUntil    *time.Time
	cacheDuration *time.Duration
}

// narrow returns v further restricted by an EntitiesDescriptor's
// validUntil and cacheDuration, either of which may be nil.
func (v metadataValidity) narrow(validUntil *time.Time, cacheDuration *time.Duration) metadataValidity {
	if validUntil != nil && !validUntil.IsZero() && (v.validUntil == nil || validUntil.Before(*v.validUntil)) {
		v.validUntil = validUntil
	}
	if cacheDuration != nil && *cacheDuration > 0 && (v.cacheDuration == nil || *cacheDuration < *v.cacheDuration) {
		v.cacheDuration = cacheDuration
	}
	return v
}

// applyTo sets entity's ValidUntil and CacheDuration to the earliest and
// shortest of its own and v's, so that the parent's policy takes
// precedence (saml-metadata-2.0-os §4.3.1).
func (v metadataValidity) applyTo(entity *saml.EntityDescriptor) {
	if v.validUntil != nil && (entity.ValidUntil.IsZero() || v.validUntil.Before(entity.ValidUntil)) {
		entity.ValidUntil = *v.validUntil
	}
	if v.cacheDuration != nil && (entity.CacheDuration <= 0 || *v.cacheDuration < entity.CacheDuration) {
		entity.CacheDuration = *v.cacheDuration
	}
}

// FetchMetadata returns metadata from an IDP metadata URL.
//
// If httpClient is nil, a client with a two-minute timeout is used. Only a
// 2xx response is accepted.
//
// The metadata names the certificates the service provider trusts to sign
// assertions, so whoever controls the response controls who can log in. It
// is not authenticated beyond what httpClient does: use an https URL, and
// prefer FetchSignedMetadata, or metadata kept with the application.
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

// defaultMetadataHTTPClient fetches metadata when the caller passes no
// client. Unlike http.DefaultClient it gives up on a server that stops
// responding.
var defaultMetadataHTTPClient = &http.Client{Timeout: 2 * time.Minute}

func fetchMetadataBytes(ctx context.Context, httpClient *http.Client, metadataURL url.URL) ([]byte, error) {
	if httpClient == nil {
		httpClient = defaultMetadataHTTPClient
	}
	req, err := http.NewRequest("GET", metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.DefaultLogger.Printf("Error while closing response body during fetch metadata: %v", err)
		}
	}()
	// Only a successful response holds the metadata: the body of a redirect
	// the client did not follow (or of any other status) is not it.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("failed to fetch metadata: unexpected status code %d", resp.StatusCode)
	}

	limit := MaxMetadataSize
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("failed to fetch metadata: response is larger than %d bytes (MaxMetadataSize)", limit)
	}
	return data, nil
}
