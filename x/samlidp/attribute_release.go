package samlidp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/attrname"
)

// ErrUnknownAttributeConsumingService matches the error of a request whose
// AttributeConsumingServiceIndex names no AttributeConsumingService of the
// service provider's metadata (saml-core §3.4.1, saml-metadata §2.4.4.1).
var ErrUnknownAttributeConsumingService = errors.New("samlidp: unknown attribute consuming service")

// RequestedAttributes returns the attributes that the service provider of
// req asks for: the RequestedAttributes of the AttributeConsumingService
// of its metadata (saml-metadata §2.4.4.1, §2.4.4.2) that
// req.AttributeConsumingServiceIndex names, or, if it is empty, of its
// default one, the first marked isDefault="true", else the first one. The
// service is looked for in the SPSSODescriptor that lists req.ACSURL, as
// indexes are unique only within one. It returns nil, and no error, if
// the request names no index and the SP lists no AttributeConsumingService.
//
// An index that the SP's metadata does not list is an error that matches
// both ErrUnknownAttributeConsumingService and a *saml.StatusError, with
// saml.StatusRequester and saml.StatusRequestUnsupported, to send to the
// SP with ErrorResponse. It does not fall back to the default service: the
// index is the SP's choice of which attributes it needs (saml-core
// §3.4.1), and the default may ask for others, more or fewer, so that the
// SP would get attributes it did not ask for, or miss ones it needs,
// without being told. An unknown index most often means that the IdP has
// stale metadata for the SP, which is better found out than hidden.
//
// The application may use the result to decide what to release, to ask
// the user's consent, or, with MissingRequiredAttributes, to check that it
// can satisfy the SP. ReleaseRequestedAttributesOnly makes Response
// release only what it lists. The result is a copy that the caller may
// change.
func (c *Config) RequestedAttributes(ctx context.Context, req *AuthnRequest) ([]saml.RequestedAttribute, error) {
	if req == nil {
		return nil, errors.New("samlidp: nil AuthnRequest")
	}
	md, err := lookupServiceProvider(ctx, c.serviceProviders, req.ServiceProvider, c.clock)
	if err != nil {
		return nil, err
	}
	d, _ := findACS(md, req.ACSURL, req.ACSBinding)
	if d == nil {
		return nil, fmt.Errorf("samlidp: service provider %q has no assertion consumer service %s with binding %s: %w",
			req.ServiceProvider, req.ACSURL, req.ACSBinding, saml.ErrUnknownAssertionConsumerService)
	}
	return requestedAttributes(d, req.ServiceProvider, req.AttributeConsumingServiceIndex)
}

// requestedAttributes returns a copy of the RequestedAttributes of the
// AttributeConsumingService of d, of service provider entityID, that
// index names, or of its default one if index is empty.
func requestedAttributes(d *saml.SPSSODescriptor, entityID, index string) ([]saml.RequestedAttribute, error) {
	services := d.AttributeConsumingServices
	var service *saml.AttributeConsumingService
	if index == "" {
		service = defaultAttributeConsumingService(services)
	} else {
		// The index is an xs:unsignedShort (saml-core §3.4.1), whose
		// whitespace is collapsed, and which may have a leading "+".
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.Trim(index, " \t\r\n"), "+"), 10, 16)
		if err == nil {
			for i := range services {
				if services[i].Index == int(n) {
					service = &services[i]
					break
				}
			}
		}
		if service == nil {
			return nil, fmt.Errorf("samlidp: service provider %q has no attribute consuming service with index %q: %w: %w",
				entityID, index, ErrUnknownAttributeConsumingService, &saml.StatusError{
					TopLevel:    saml.StatusRequester,
					SecondLevel: saml.StatusRequestUnsupported,
					Message:     "the requested attribute consuming service is not in the service provider's metadata",
				})
		}
	}
	if service == nil {
		return nil, nil
	}
	out := make([]saml.RequestedAttribute, len(service.RequestedAttributes))
	for i, ra := range service.RequestedAttributes {
		out[i] = ra
		out[i].Values = slices.Clone(ra.Values)
		if ra.IsRequired != nil {
			required := *ra.IsRequired
			out[i].IsRequired = &required
		}
	}
	return out, nil
}

// defaultAttributeConsumingService returns the first of services marked
// isDefault="true", else the first, else nil (saml-metadata §2.4.4.1).
func defaultAttributeConsumingService(services []saml.AttributeConsumingService) *saml.AttributeConsumingService {
	for i := range services {
		if services[i].IsDefault != nil && *services[i].IsDefault {
			return &services[i]
		}
	}
	if len(services) > 0 {
		return &services[0]
	}
	return nil
}

// ReleaseRequestedAttributesOnly makes Response release, of the Subject's
// Attributes, only those that the service provider's metadata asks for, as
// RequestedAttributes returns them, and filters them as
// FilterAttributes does: an SP whose metadata lists no
// AttributeConsumingService gets none. Without it, Response sends every
// attribute of the Subject to every SP, and the application must choose
// them for each one.
//
// Response fails, as RequestedAttributes does, if the request names an
// AttributeConsumingServiceIndex that the SP's metadata does not list. It
// does not fail for a required attribute that the Subject lacks: check
// that with MissingRequiredAttributes before. Attributes that a
// WithAssertion adds are not filtered; it sees those that are released.
func ReleaseRequestedAttributesOnly() ResponseOption {
	return responseOptionFunc(func(o *responseOptions) { o.requestedOnly = true })
}

// FilterAttributes returns those of attrs that one of requested asks for,
// in their order, each with only the values that it asks for.
//
// An attribute is asked for by a RequestedAttribute with the same Name,
// compared exactly (saml-core §1.3.1), and the same NameFormat, an empty
// one being urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified
// (saml-core §2.7.3.1). A RequestedAttribute whose NameFormat is
// unspecified, which leaves the interpretation of the Name to the parties
// (saml-core §8.2.1), asks for the attribute of that Name with any
// NameFormat; one of another NameFormat asks only for the attribute of
// that NameFormat.
//
// A RequestedAttribute that lists AttributeValues asks only for those
// values (saml-metadata §2.4.4.2): the attribute keeps only the values
// equal to one of them, and is left out if it has none. One that lists
// none asks for every value. If several RequestedAttributes ask for an
// attribute, it keeps the values that any of them asks for.
func FilterAttributes(requested []saml.RequestedAttribute, attrs []Attribute) []Attribute {
	var out []Attribute
	for _, attr := range attrs {
		if released, ok := filterAttribute(requested, attr); ok {
			out = append(out, released)
		}
	}
	return out
}

// filterAttribute returns attr with the values that requested asks for,
// and whether requested asks for attr at all with those values.
func filterAttribute(requested []saml.RequestedAttribute, attr Attribute) (Attribute, bool) {
	asked, anyValue := false, false
	allowed := map[string]bool{}
	for i := range requested {
		ra := &requested[i]
		if !requestedAttributeMatches(ra, attr) {
			continue
		}
		asked = true
		if len(ra.Values) == 0 {
			anyValue = true
		}
		for _, v := range ra.Values {
			allowed[v.Value] = true
		}
	}
	switch {
	case !asked:
		return Attribute{}, false
	case anyValue:
		return attr, true
	}
	var values []string
	for _, v := range attr.Values {
		if allowed[v] {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		return Attribute{}, false
	}
	attr.Values = values
	return attr, true
}

// requestedAttributeMatches reports whether ra asks for attr, by Name and
// NameFormat, regardless of values.
func requestedAttributeMatches(ra *saml.RequestedAttribute, attr Attribute) bool {
	if ra.Name != attr.Name {
		return false
	}
	want := nameFormat(ra.NameFormat)
	return want == attrname.FormatUnspecified || want == nameFormat(attr.NameFormat)
}

// nameFormat returns format, or the unspecified NameFormat if it is empty
// (saml-core §2.7.3.1).
func nameFormat(format string) string {
	if format == "" {
		return attrname.FormatUnspecified
	}
	return format
}

// MissingRequiredAttributes returns those of requested marked
// isRequired="true" (saml-metadata §2.4.4.2) for which attrs has no
// attribute that FilterAttributes would release: none with its Name and
// NameFormat, or, if it lists AttributeValues, none with one of them.
// It returns nil if attrs satisfy them all.
//
// What to do about a missing attribute is the application's to decide:
// to answer the SP with ErrorResponse, for example with
// saml.StatusResponder and saml.StatusRequestDenied, to ask the user, or
// to send the Response all the same and leave the SP to refuse it.
func MissingRequiredAttributes(requested []saml.RequestedAttribute, attrs []Attribute) []saml.RequestedAttribute {
	var missing []saml.RequestedAttribute
	for _, ra := range requested {
		if ra.IsRequired == nil || !*ra.IsRequired {
			continue
		}
		found := false
		for _, attr := range attrs {
			if _, ok := filterAttribute([]saml.RequestedAttribute{ra}, attr); ok {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, ra)
		}
	}
	return missing
}
