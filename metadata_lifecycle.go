package saml

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrMetadataExpired means a metadata document or entity is no longer
	// within its advertised validity period.
	ErrMetadataExpired = errors.New("saml: metadata expired")
)

// MetadataExpiresAt returns the earliest expiry that can be calculated from
// the entity's validUntil attributes. cacheDuration is a refresh deadline,
// not a hard validity limit; use MetadataRefreshAt to include it. A zero time
// means the metadata has no validUntil bound.
func (m *EntityDescriptor) MetadataExpiresAt() time.Time {
	if m == nil {
		return time.Time{}
	}
	expiry := m.ValidUntil
	for _, role := range allRoleDescriptors(m) {
		expiry = earlierTime(expiry, roleValidUntil(role))
	}
	return expiry
}

// MetadataRefreshAt returns the earliest deadline requested by validUntil or
// cacheDuration. cacheDuration deadlines are relative to MetadataRetrievedAt;
// if that time is unknown, only validUntil deadlines can be calculated.
// cacheDuration signals when metadata should be refreshed, but does not by
// itself make otherwise usable cached metadata invalid.
func (m *EntityDescriptor) MetadataRefreshAt() time.Time {
	if m == nil {
		return time.Time{}
	}
	refreshAt := m.MetadataExpiresAt()
	refreshAt = earlierTime(refreshAt, cacheDeadline(m.CacheDuration, m.MetadataCacheDurationSet || m.CacheDuration != 0, m.MetadataRetrievedAt))
	for _, role := range allRoleDescriptors(m) {
		refreshAt = earlierTime(refreshAt, cacheDeadline(role.CacheDuration, role.MetadataCacheDurationSet || role.CacheDuration != 0, m.MetadataRetrievedAt))
	}
	return refreshAt
}

// ValidateMetadataAt reports whether metadata is still within its advertised
// hard validity period at now. cacheDuration is only a refresh deadline and
// does not make cached metadata invalid when the deadline passes.
func (m *EntityDescriptor) ValidateMetadataAt(now time.Time) error {
	if m == nil {
		return errors.New("saml: metadata is nil")
	}
	if expiry := m.MetadataExpiresAt(); !expiry.IsZero() && !now.Before(expiry) {
		return fmt.Errorf("%w: entity %q expired at %s", ErrMetadataExpired, m.EntityID, expiry.Format(time.RFC3339))
	}
	return nil
}

func cacheDeadline(cacheDuration time.Duration, cacheDurationSet bool, retrievedAt time.Time) time.Time {
	if cacheDurationSet && !retrievedAt.IsZero() {
		return retrievedAt.Add(cacheDuration)
	}
	return time.Time{}
}

func earlierTime(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func allRoleDescriptors(m *EntityDescriptor) []RoleDescriptor {
	roles := make([]RoleDescriptor, 0, len(m.IDPSSODescriptors)+len(m.SPSSODescriptors)+len(m.AuthnAuthorityDescriptors)+len(m.AttributeAuthorityDescriptors)+len(m.PDPDescriptors))
	roles = append(roles, m.RoleDescriptors...)
	for _, role := range m.IDPSSODescriptors {
		roles = append(roles, role.RoleDescriptor)
	}
	for _, role := range m.SPSSODescriptors {
		roles = append(roles, role.RoleDescriptor)
	}
	for _, role := range m.AuthnAuthorityDescriptors {
		roles = append(roles, role.RoleDescriptor)
	}
	for _, role := range m.AttributeAuthorityDescriptors {
		roles = append(roles, role.RoleDescriptor)
	}
	for _, role := range m.PDPDescriptors {
		roles = append(roles, role.RoleDescriptor)
	}
	return roles
}

func roleValidUntil(m RoleDescriptor) time.Time {
	if m.ValidUntil == nil {
		return time.Time{}
	}
	return *m.ValidUntil
}

// FindEntityDescriptor returns the entity with entityID from this aggregate
// and applies all enclosing cache policies to the returned copy. retrievedAt
// is the time the aggregate document was obtained.
func (m *EntitiesDescriptor) FindEntityDescriptor(entityID string, retrievedAt time.Time) *EntityDescriptor {
	if m == nil {
		return nil
	}
	return findEntityDescriptor(m, entityID, metadataCachePolicy{}, retrievedAt)
}

type metadataCachePolicy struct {
	validUntil    time.Time
	cacheDuration time.Duration
	cacheSet      bool
}

func findEntityDescriptor(aggregate *EntitiesDescriptor, entityID string, parent metadataCachePolicy, retrievedAt time.Time) *EntityDescriptor {
	policy := parent
	if aggregate.ValidUntil != nil {
		policy.validUntil = earlierTime(policy.validUntil, *aggregate.ValidUntil)
	}
	if aggregate.CacheDuration != nil && (!policy.cacheSet || *aggregate.CacheDuration < policy.cacheDuration) {
		policy.cacheDuration = *aggregate.CacheDuration
		policy.cacheSet = true
	}
	for i := range aggregate.EntityDescriptors {
		if aggregate.EntityDescriptors[i].EntityID != entityID {
			continue
		}
		entity := aggregate.EntityDescriptors[i]
		applyMetadataCachePolicy(&entity, policy, retrievedAt)
		return &entity
	}
	for i := range aggregate.EntitiesDescriptors {
		if entity := findEntityDescriptor(&aggregate.EntitiesDescriptors[i], entityID, policy, retrievedAt); entity != nil {
			return entity
		}
	}
	return nil
}

func applyMetadataCachePolicy(entity *EntityDescriptor, policy metadataCachePolicy, retrievedAt time.Time) {
	entity.ValidUntil = earlierTime(entity.ValidUntil, policy.validUntil)
	if policy.cacheSet && (!entity.MetadataCacheDurationSet && entity.CacheDuration == 0 || policy.cacheDuration < entity.CacheDuration) {
		entity.CacheDuration = policy.cacheDuration
		entity.MetadataCacheDurationSet = policy.cacheDuration == 0
	}
	entity.MetadataRetrievedAt = retrievedAt
}
