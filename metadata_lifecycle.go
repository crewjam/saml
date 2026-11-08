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

// MetadataExpiresAt returns the entity's validUntil value. A zero time means
// the entity has no hard validity bound. Role descriptors have their own
// validity periods and must be checked only when that role is used.
func (m *EntityDescriptor) MetadataExpiresAt() time.Time {
	if m == nil {
		return time.Time{}
	}
	return m.ValidUntil
}

// MetadataRefreshAt returns the earliest deadline requested by validUntil or
// cacheDuration. retrievedAt is when this metadata document was obtained;
// cacheDuration deadlines are relative to that time.
// cacheDuration signals when metadata should be refreshed, but does not by
// itself make otherwise usable cached metadata invalid.
func (m *EntityDescriptor) MetadataRefreshAt(retrievedAt time.Time) time.Time {
	if m == nil {
		return time.Time{}
	}
	refreshAt := m.MetadataExpiresAt()
	refreshAt = earlierTime(refreshAt, cacheDeadline(m.CacheDuration, m.metadataCacheDurationSet || m.CacheDuration != 0, retrievedAt))
	for _, role := range allRoleDescriptors(m) {
		refreshAt = earlierTime(refreshAt, roleValidUntil(role))
		refreshAt = earlierTime(refreshAt, cacheDeadline(role.CacheDuration, role.metadataCacheDurationSet || role.CacheDuration != 0, retrievedAt))
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
	if expiry := m.ValidUntil; !expiry.IsZero() && !now.Before(expiry) {
		return fmt.Errorf("%w: entity %q expired at %s", ErrMetadataExpired, m.EntityID, expiry.Format(time.RFC3339))
	}
	return nil
}

// ValidateMetadataAt reports whether a role descriptor is still within its
// advertised validity period at now.
func (m RoleDescriptor) ValidateMetadataAt(now time.Time) error {
	if expiry := roleValidUntil(m); !expiry.IsZero() && !now.Before(expiry) {
		return fmt.Errorf("%w: role descriptor expired at %s", ErrMetadataExpired, expiry.Format(time.RFC3339))
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
// and applies all enclosing cache policies to the returned copy.
func (m *EntitiesDescriptor) FindEntityDescriptor(entityID string) *EntityDescriptor {
	if m == nil {
		return nil
	}
	return findEntityDescriptor(m, entityID, metadataCachePolicy{})
}

type metadataCachePolicy struct {
	validUntil    time.Time
	cacheDuration time.Duration
	cacheSet      bool
}

func findEntityDescriptor(aggregate *EntitiesDescriptor, entityID string, parent metadataCachePolicy) *EntityDescriptor {
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
		applyMetadataCachePolicy(&entity, policy)
		return &entity
	}
	for i := range aggregate.EntitiesDescriptors {
		if entity := findEntityDescriptor(&aggregate.EntitiesDescriptors[i], entityID, policy); entity != nil {
			return entity
		}
	}
	return nil
}

func applyMetadataCachePolicy(entity *EntityDescriptor, policy metadataCachePolicy) {
	entity.ValidUntil = earlierTime(entity.ValidUntil, policy.validUntil)
	if policy.cacheSet && (!entity.metadataCacheDurationSet && entity.CacheDuration == 0 || policy.cacheDuration < entity.CacheDuration) {
		entity.CacheDuration = policy.cacheDuration
		entity.metadataCacheDurationSet = policy.cacheDuration == 0
	}
}
