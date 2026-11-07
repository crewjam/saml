// Package idpmetadata parses and fetches the metadata of SAML identity
// providers. It is shared by samlsp and x/samlsp.
package idpmetadata

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/xmlroundtrip"
	"github.com/crewjam/saml/logger"
)

// MultipleIDPsError is returned by Parse for an aggregate that holds more
// than one entity with an IDPSSODescriptor.
type MultipleIDPsError struct{ N int }

func (e *MultipleIDPsError) Error() string {
	return fmt.Sprintf("metadata holds %d entities with an IDPSSODescriptor", e.N)
}

// TooLargeError is returned by Fetch for a response larger than its limit.
type TooLargeError struct{ Limit int64 }

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("failed to fetch metadata: response is larger than %d bytes", e.Limit)
}

// Parse returns the IdP entity in data: an EntityDescriptor, or the one
// entity with an IDPSSODescriptor in an EntitiesDescriptor, which inherits
// the validUntil and cacheDuration of the aggregates around it. It does not
// check signatures.
func Parse(data []byte) (*saml.EntityDescriptor, error) {
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
		return nil, &MultipleIDPsError{N: n}
	}
	// There is at most one IDP entity, so document order does not matter
	// and it can be found in the parsed aggregate.
	entity := findIDPEntity(entities, metadataValidity{})
	if entity == nil {
		return nil, errors.New("no entity found with IDPSSODescriptor")
	}
	return entity, nil
}

// ParseByEntityID returns the entity with entityID in data, an
// EntityDescriptor or an EntitiesDescriptor. It does not check signatures.
func ParseByEntityID(data []byte, entityID string) (*saml.EntityDescriptor, error) {
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

func (v metadataValidity) narrow(validUntil *time.Time, cacheDuration *time.Duration) metadataValidity {
	if validUntil != nil && !validUntil.IsZero() && (v.validUntil == nil || validUntil.Before(*v.validUntil)) {
		v.validUntil = validUntil
	}
	if cacheDuration != nil && *cacheDuration > 0 && (v.cacheDuration == nil || *cacheDuration < *v.cacheDuration) {
		v.cacheDuration = cacheDuration
	}
	return v
}

func (v metadataValidity) applyTo(entity *saml.EntityDescriptor) {
	if v.validUntil != nil && (entity.ValidUntil.IsZero() || v.validUntil.Before(entity.ValidUntil)) {
		entity.ValidUntil = *v.validUntil
	}
	if v.cacheDuration != nil && (entity.CacheDuration <= 0 || *v.cacheDuration < entity.CacheDuration) {
		entity.CacheDuration = *v.cacheDuration
	}
}

var defaultHTTPClient = &http.Client{Timeout: 2 * time.Minute}

// Fetch returns the body of a GET of metadataURL, refusing a response that
// is not 2xx or is larger than limit bytes (a *TooLargeError). If
// httpClient is nil, a client with a two-minute timeout is used.
func Fetch(ctx context.Context, httpClient *http.Client, metadataURL url.URL, limit int64) ([]byte, error) {
	if httpClient == nil {
		httpClient = defaultHTTPClient
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &TooLargeError{Limit: limit}
	}
	return data, nil
}
