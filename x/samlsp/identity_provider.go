package samlsp

import (
	"context"
	"errors"
)

// ErrNoIdentityProvider is returned by a method that needs the identity
// provider's metadata when the Config was made without a MetadataFunc and
// the call names no identity provider (see WithIdentityProvider).
var ErrNoIdentityProvider = errors.New("samlsp: no identity provider: pass one to New, or to the call with WithIdentityProvider")

// IdentityProviderOption is the option that WithIdentityProvider returns.
// It is a MessageOption, so it applies to AuthnRequest, Send and Prepare
// (and so to the messages of x/samlsp/slo), a ResponseOption and a
// QueryOption.
type IdentityProviderOption struct{ idp MetadataFunc }

// WithIdentityProvider makes a single call use idp, rather than the
// MetadataFunc passed to New, for the identity provider's metadata. Use it
// when one SP serves several IdPs, such as one per tenant, and the
// application already knows which one a call is for:
//
//	msg, err := config.AuthnRequest(ctx, relayState,
//		samlsp.WithIdentityProvider(samlsp.StaticMetadata(tenant.IdPMetadata)))
//
// The call's methods see the IdP through its context (see
// IdentityProviderContext), so a custom Binding that the call uses gets it
// too. Pass the same IdP to ParseResponse as to AuthnRequest.
func WithIdentityProvider(idp MetadataFunc) IdentityProviderOption {
	return IdentityProviderOption{idp}
}

func (o IdentityProviderOption) applyAuthn(a *authnOptions)       { a.idp = o.idp }
func (o IdentityProviderOption) applyMessage(m *messageOptions)   { m.idp = o.idp }
func (o IdentityProviderOption) applyResponse(r *responseOptions) { r.idp = o.idp }
func (o IdentityProviderOption) applyQuery(q *queryOptions)       { q.idp = o.idp }

type identityProviderKey struct{}

// IdentityProviderContext returns a copy of ctx in which the Config
// methods called with it use idp, rather than the MetadataFunc passed to
// New, for the identity provider's metadata. It is what
// WithIdentityProvider does for one call; use it for calls that take no
// such option, such as Config.ServiceProvider and the methods of
// x/samlsp/slo that parse messages, or around a handler that serves one
// tenant, such as an artifact resolution service.
func IdentityProviderContext(ctx context.Context, idp MetadataFunc) context.Context {
	if idp == nil {
		return ctx
	}
	return context.WithValue(ctx, identityProviderKey{}, idp)
}

// identityProviderFor returns the MetadataFunc that a call with ctx uses.
func (c *Config) identityProviderFor(ctx context.Context) (MetadataFunc, error) {
	if idp, ok := ctx.Value(identityProviderKey{}).(MetadataFunc); ok {
		return idp, nil
	}
	if c.identityProvider == nil {
		return nil, ErrNoIdentityProvider
	}
	return c.identityProvider, nil
}
