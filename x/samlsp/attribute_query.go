package samlsp

import (
	"context"
	"errors"
	"fmt"

	"github.com/crewjam/saml"
)

// QueryOption customizes QueryAttributes.
type QueryOption interface {
	applyQuery(*queryOptions)
}

type queryOptions struct {
	attributes []saml.Attribute
	sp         []ServiceProviderOption
	idp        MetadataFunc
}

type queryOptionFunc func(*queryOptions)

func (f queryOptionFunc) applyQuery(o *queryOptions) { f(o) }

func (f ServiceProviderOption) applyQuery(o *queryOptions) { o.sp = append(o.sp, f) }

// WithQueriedAttributes limits QueryAttributes to the attributes with these
// Names. A Name that is a URI or an OID is sent with the URI NameFormat.
// Without it, the IdP returns every attribute it releases to this SP.
func WithQueriedAttributes(names ...string) QueryOption {
	return queryOptionFunc(func(o *queryOptions) {
		for _, name := range names {
			o.attributes = append(o.attributes, RequestedAttribute{Name: name}.saml().Attribute)
		}
	})
}

// QueryAttributes asks the identity provider's attribute authority for the
// current attributes of the user identified by nameID, with an
// AttributeQuery sent directly to it with the SOAP binding (saml-profiles
// §6, saml-core §3.3.2.3). Pass the NameID of the user's login
// (Assertion.NameID), so that the IdP knows who it names. The IdP
// metadata may describe an attribute authority alone: an entity with an
// AttributeAuthorityDescriptor and no IDPSSODescriptor.
//
// The answer is verified as a login is, except that it need not answer a
// browser request. It describes the user; it does not say the user is
// present, and must never be used to start a session. Decode it into a
// struct with Attributes.Decode.
//
// It returns an error matching ErrNoEndpoint if the IdP metadata has no
// SOAP AttributeService, and one matching saml.ErrBadStatus if the IdP
// refused the query. The query is sent with the HTTP client of
// WithHTTPClient, to an https endpoint only. It is signed with the key of
// WithSigningKey, by which most attribute authorities decide what to
// release. Without one it is sent unsigned, as the profile allows
// (saml-profiles §6), for an attribute authority that authenticates the
// SP some other way, such as by a TLS client certificate.
func (c *Config) QueryAttributes(ctx context.Context, nameID saml.NameID, opts ...QueryOption) (Attributes, error) {
	var o queryOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyQuery(&o)
		}
	}
	ctx = IdentityProviderContext(ctx, o.idp)
	sp, err := c.serviceProvider(ctx, o.sp)
	if err != nil {
		return nil, err
	}
	c.signWithGeneralMethod(sp)
	result, err := sp.QueryAttributes(ctx, nameID, o.attributes...)
	if errors.Is(err, saml.ErrNoAttributeService) {
		return nil, fmt.Errorf("%w %s for attribute queries", ErrNoEndpoint, saml.SOAPBinding)
	}
	if err != nil {
		return nil, err
	}
	return convertAttributes(result.Attributes), nil
}
