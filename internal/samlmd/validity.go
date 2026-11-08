package samlmd

import (
	"fmt"
	"time"

	"github.com/crewjam/saml"
)

// Roles returns the role descriptors of an entity whose validity a caller
// relies on, besides the entity's own.
type Roles func(md *saml.EntityDescriptor) []*saml.RoleDescriptor

// IDPRoles are the roles of an identity provider whose expiry a
// saml.ServiceProvider with RejectExpiredIDPMetadata checks: its
// IDPSSODescriptors and AttributeAuthorityDescriptors.
func IDPRoles(md *saml.EntityDescriptor) []*saml.RoleDescriptor {
	roles := make([]*saml.RoleDescriptor, 0, len(md.IDPSSODescriptors)+len(md.AttributeAuthorityDescriptors))
	for i := range md.IDPSSODescriptors {
		roles = append(roles, &md.IDPSSODescriptors[i].RoleDescriptor)
	}
	for i := range md.AttributeAuthorityDescriptors {
		roles = append(roles, &md.AttributeAuthorityDescriptors[i].RoleDescriptor)
	}
	return roles
}

// SPRoles are the roles of a service provider: its SPSSODescriptors.
func SPRoles(md *saml.EntityDescriptor) []*saml.RoleDescriptor {
	roles := make([]*saml.RoleDescriptor, 0, len(md.SPSSODescriptors))
	for i := range md.SPSSODescriptors {
		roles = append(roles, &md.SPSSODescriptors[i].RoleDescriptor)
	}
	return roles
}

// Validity returns the earliest validUntil and the shortest cacheDuration
// (saml-metadata §2.2.1) of md and of its roles. Each is zero if none sets
// one. md carries those of the EntitiesDescriptors around it if it came
// from Parse, ParseByEntityID or Entities.
func Validity(md *saml.EntityDescriptor, roles Roles) (validUntil time.Time, cacheDuration time.Duration) {
	validUntil, cacheDuration = md.ValidUntil, md.CacheDuration
	for _, role := range roles(md) {
		if role.ValidUntil != nil && !role.ValidUntil.IsZero() && (validUntil.IsZero() || role.ValidUntil.Before(validUntil)) {
			validUntil = *role.ValidUntil
		}
		if role.CacheDuration > 0 && (cacheDuration <= 0 || role.CacheDuration < cacheDuration) {
			cacheDuration = role.CacheDuration
		}
	}
	return validUntil, cacheDuration
}

// Expired returns an error that matches saml.ErrExpired if the validUntil
// of md or of one of its roles has passed at now.
func Expired(md *saml.EntityDescriptor, roles Roles, now time.Time) error {
	if validUntil, _ := Validity(md, roles); !validUntil.IsZero() && !now.Before(validUntil) {
		return fmt.Errorf("metadata for %q expired at %s: %w", md.EntityID, validUntil.UTC().Format(time.RFC3339), saml.ErrExpired)
	}
	return nil
}
