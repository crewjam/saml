package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// This file implements back-channel single logout at the IdP: the SAML
// SOAP binding (saml-bindings §3.2) for the LogoutRequests the IdP sends to
// session participants (saml-profiles §4.4.3.3 and §4.4.4.2).

// errNoSOAPLogoutEndpoint is returned by logoutParticipantSOAP when the
// service provider's metadata lists no SOAP SingleLogoutService.
var errNoSOAPLogoutEndpoint = errors.New("the service provider metadata has no SOAP SingleLogoutService endpoint")

// httpClient returns the client the IdP sends SOAP messages with.
func (idp *IdentityProvider) httpClient() *http.Client {
	if idp.HTTPClient != nil {
		return idp.HTTPClient
	}
	return defaultSOAPHTTPClient
}

// soapLogoutEndpoint returns the first SingleLogoutService of metadata with
// the SOAP binding and an https Location (or an http one, if
// AllowInsecureSOAPEndpoints is set), or nil. An endpoint skipped because it
// is not https is logged.
func (idp *IdentityProvider) soapLogoutEndpoint(metadata *EntityDescriptor) *Endpoint {
	for _, spssoDescriptor := range metadata.SPSSODescriptors {
		for _, endpoint := range spssoDescriptor.SingleLogoutServices {
			if endpoint.Binding != SOAPBinding {
				continue
			}
			if location, err := checkEndpointLocation(endpoint.Binding, endpoint.Location); err != nil || location == "" {
				continue
			}
			if err := checkSOAPEndpoint(endpoint.Location, idp.AllowInsecureSOAPEndpoints); err != nil {
				idp.Logger.Printf("ignoring the SOAP SingleLogoutService of %s: %s", metadata.EntityID, err)
				continue
			}
			return &endpoint
		}
	}
	return nil
}

// logoutParticipantSOAP logs participant out server to server: it sends a
// signed LogoutRequest to the SOAP SingleLogoutService that metadata, the
// metadata of the participant's service provider, lists, and checks the
// LogoutResponse that comes back (see parseSOAPLogoutResponse). It returns
// nil only if the service provider answered with a Success status. It
// returns errNoSOAPLogoutEndpoint if metadata lists no SOAP endpoint, or
// only ones that are not https (see AllowInsecureSOAPEndpoints).
func (idp *IdentityProvider) logoutParticipantSOAP(ctx context.Context, metadata *EntityDescriptor, participant SessionParticipant) error {
	endpoint := idp.soapLogoutEndpoint(metadata)
	if endpoint == nil {
		return errNoSOAPLogoutEndpoint
	}
	logoutRequest, err := idp.participantLogoutRequest(participant, endpoint.Location, metadata)
	if err != nil {
		return err
	}
	signingContext, err := idp.signingContext()
	if err != nil {
		return err
	}
	signed, err := signingContext.SignEnveloped(logoutRequest.Element())
	if err != nil {
		return err
	}

	body, err := postSOAPMessage(ctx, idp.httpClient(), endpoint.Location, soapEnvelope(signed), MaxSOAPLogoutMessageSize)
	if err != nil {
		return fmt.Errorf("logout request to %s: %w", endpoint.Location, err)
	}
	resp, err := idp.parseSOAPLogoutResponse(body, participant.ServiceProviderID, metadata, logoutRequest.ID)
	if err != nil {
		return err
	}
	if err := statusError(resp.Status); err != nil {
		return fmt.Errorf("logout response from %s: %w", participant.ServiceProviderID, err)
	}
	return nil
}

// parseSOAPLogoutResponse reads the LogoutResponse in body, the SOAP
// envelope that the service provider serviceProviderID, whose metadata is
// metadata, returned for the LogoutRequest requestID. It checks it as a
// LogoutResponse that comes back through the browser is checked, except
// for its Destination:
//
//   - it must be signed by the service provider with a key of its metadata,
//     with an algorithm RejectSHA1Signatures allows, and is read from what
//     the signature covers;
//   - its Issuer must be serviceProviderID, its InResponseTo requestID, and
//     it must be recently issued;
//   - its Destination may be absent, as a response returned over the
//     synchronous SOAP binding is not delivered to an endpoint
//     (saml-bindings §3.2.3); if it is present, it must name this IdP, by its
//     entity ID or LogoutURL.
//
// Its status is not checked.
func (idp *IdentityProvider) parseSOAPLogoutResponse(body []byte, serviceProviderID string, metadata *EntityDescriptor, requestID string) (*LogoutResponse, error) {
	el, err := soapBodyElement(body, "LogoutResponse")
	if err != nil {
		return nil, fmt.Errorf("logout response from %s: %w", serviceProviderID, err)
	}
	var resp LogoutResponse
	if err := unmarshalElement(el, &resp); err != nil {
		return nil, fmt.Errorf("cannot parse logout response from %s: %w", serviceProviderID, err)
	}
	if resp.Issuer == nil || resp.Issuer.Value != serviceProviderID {
		return nil, fmt.Errorf("expected logout response issuer to be %q", serviceProviderID)
	}

	certs, err := spSigningCerts(metadata)
	if err != nil {
		return nil, err
	}
	if err := checkEnvelopedSignatureNotSHA1(idp.RejectSHA1Signatures, el); err != nil {
		return nil, fmt.Errorf("logout response from %s: %w", serviceProviderID, err)
	}
	signed, err := verifiedEnvelopedElement(el, certs, Clock)
	if err != nil {
		return nil, fmt.Errorf("cannot verify signature of logout response from %s: %w", serviceProviderID, err)
	}
	// Read the response again from what the signature covers. The issuer it
	// names must be the one whose keys verified it.
	resp = LogoutResponse{}
	if err := unmarshalElement(signed, &resp); err != nil {
		return nil, fmt.Errorf("cannot parse logout response from %s: %w", serviceProviderID, err)
	}
	if resp.Issuer == nil || resp.Issuer.Value != serviceProviderID {
		return nil, fmt.Errorf("signed logout response is not from %s", serviceProviderID)
	}

	if err := validateLogoutResponseAnswer(&resp, requestID); err != nil {
		return nil, err
	}
	switch resp.Destination {
	case "", idp.MetadataURL.String(), idp.LogoutURL.String():
	default:
		return nil, fmt.Errorf("logout response destination %q is not this IdP", resp.Destination)
	}
	return &resp, nil
}
