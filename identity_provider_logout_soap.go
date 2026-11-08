package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/beevik/etree"
)

// This file implements back-channel single logout at the IdP: the SAML
// SOAP binding (saml-bindings §3.2) for the LogoutRequests the IdP sends to
// session participants (saml-profiles §4.4.3.3 and §4.4.4.2).

// ErrNoSOAPLogoutEndpoint is returned by SendSOAPLogoutRequest when the
// service provider's metadata lists no SOAP SingleLogoutService (or only
// ones that are not https; see AllowInsecureSOAPEndpoints).
var ErrNoSOAPLogoutEndpoint = errors.New("the service provider metadata has no SOAP SingleLogoutService endpoint")

// httpClient returns the client the IdP sends SOAP messages with: HTTPClient,
// or defaultSOAPHTTPClient, never following a redirect to a location that
// checkSOAPEndpoint refuses (see soapHTTPClient).
func (idp *IdentityProvider) httpClient() *http.Client {
	return soapHTTPClient(idp.HTTPClient, idp.AllowInsecureSOAPEndpoints)
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
// returns ErrNoSOAPLogoutEndpoint if metadata lists no SOAP endpoint, or
// only ones that are not https (see AllowInsecureSOAPEndpoints).
//
// encryptedID, if not nil, is the NameID of participant, already encrypted
// (see participantLogoutRequest).
func (idp *IdentityProvider) logoutParticipantSOAP(ctx context.Context, metadata *EntityDescriptor, participant SessionParticipant, encryptedID *etree.Element) error {
	logout, err := idp.prepareSOAPLogout(metadata, participant, encryptedID)
	if err != nil {
		return err
	}
	return logout.send(ctx)
}

// soapLogout is a signed LogoutRequest ready to be sent to a participant
// over the SOAP binding.
type soapLogout struct {
	idp         *IdentityProvider
	metadata    *EntityDescriptor
	participant SessionParticipant
	location    string
	requestID   string
	signed      *etree.Element
}

// prepareSOAPLogout makes and signs the LogoutRequest logoutParticipantSOAP
// sends, changed by opts before it is signed. It reads the
// IdentityProvider's Rand, so it is not run concurrently.
func (idp *IdentityProvider) prepareSOAPLogout(metadata *EntityDescriptor, participant SessionParticipant, encryptedID *etree.Element, opts ...LogoutRequestOption) (*soapLogout, error) {
	endpoint := idp.soapLogoutEndpoint(metadata)
	if endpoint == nil {
		return nil, ErrNoSOAPLogoutEndpoint
	}
	logoutRequest, err := idp.participantLogoutRequest(participant, encryptedID, endpoint.Location, metadata)
	if err != nil {
		return nil, err
	}
	for _, opt := range opts {
		opt(logoutRequest)
	}
	signingContext, err := idp.signingContext()
	if err != nil {
		return nil, err
	}
	signed, err := signingContext.SignEnveloped(logoutRequest.Element())
	if err != nil {
		return nil, err
	}
	return &soapLogout{
		idp:         idp,
		metadata:    metadata,
		participant: participant,
		location:    endpoint.Location,
		requestID:   logoutRequest.ID,
		signed:      signed,
	}, nil
}

// send sends the LogoutRequest and checks the LogoutResponse.
func (l *soapLogout) send(ctx context.Context) error {
	_, err := l.exchange(ctx)
	return err
}

// exchange sends the LogoutRequest and returns the checked LogoutResponse.
// The error matches ErrBadStatus if its status is not Success.
func (l *soapLogout) exchange(ctx context.Context) (*LogoutResponse, error) {
	body, err := postSOAPMessage(ctx, l.idp.httpClient(), l.location, soapEnvelope(l.signed), MaxSOAPLogoutMessageSize)
	if err != nil {
		return nil, fmt.Errorf("logout request to %s: %w", l.location, err)
	}
	resp, err := l.idp.parseSOAPLogoutResponse(body, l.participant.ServiceProviderID, l.metadata, l.requestID)
	if err != nil {
		return nil, err
	}
	if err := statusError(resp.Status); err != nil {
		return resp, fmt.Errorf("logout response from %s: %w", l.participant.ServiceProviderID, err)
	}
	return resp, nil
}

// SendSOAPLogoutRequest logs participant out server to server, without the
// browser: it sends a signed LogoutRequest (see MakeLogoutRequest) to the
// SOAP SingleLogoutService that metadata, the metadata of the
// participant's service provider, lists, with HTTPClient, and returns the
// LogoutResponse that comes back, once it has checked its signature,
// Issuer, InResponseTo and IssueInstant. It is what StartLogout and
// ServeSLO do for participants that offer the SOAP binding.
//
// It returns an error matching ErrNoSOAPLogoutEndpoint if metadata lists
// no SOAP endpoint (or only ones that are not https; see
// AllowInsecureSOAPEndpoints), and one matching ErrBadStatus, with the
// response, if the service provider did not answer with a Success status.
//
// opts change the LogoutRequest before it is signed, such as to set its
// Reason or NotOnOrAfter.
func (idp *IdentityProvider) SendSOAPLogoutRequest(ctx context.Context, metadata *EntityDescriptor, participant SessionParticipant, opts ...LogoutRequestOption) (*LogoutResponse, error) {
	if metadata == nil {
		return nil, errors.New("no service provider metadata")
	}
	logout, err := idp.prepareSOAPLogout(metadata, participant, nil, opts...)
	if err != nil {
		return nil, err
	}
	return logout.exchange(ctx)
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
	signed, err := verifiedEnvelopedElement(el, certs, idp.dsigClock())
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

	if err := validateLogoutResponseAnswer(&resp, requestID, idp.now(), idp.limits()); err != nil {
		return nil, err
	}
	switch resp.Destination {
	case "", idp.MetadataURL.String(), idp.LogoutURL.String():
	default:
		return nil, fmt.Errorf("logout response destination %q is not this IdP", resp.Destination)
	}
	return &resp, nil
}

// ValidateSPSignedElement verifies the enveloped XML signature of el, a
// message from the service provider whose metadata is metadata, against
// the signing certificates of that metadata, with an algorithm
// RejectSHA1Signatures allows, and returns what the signature covers: el
// without its Signature, which the caller reads the message from. el must
// be signed; the error then matches ErrInvalidSignature. As is usual for
// keys distributed in metadata, the certificates' validity periods are not
// checked. Use it for messages the IdP receives with the SOAP binding, such
// as an ArtifactResolve.
func (idp *IdentityProvider) ValidateSPSignedElement(el *etree.Element, metadata *EntityDescriptor) (*etree.Element, error) {
	if el == nil || metadata == nil {
		return nil, errors.New("no element or no service provider metadata")
	}
	certs, err := spSigningCerts(metadata)
	if err != nil {
		return nil, err
	}
	if err := checkEnvelopedSignatureNotSHA1(idp.RejectSHA1Signatures, el); err != nil {
		return nil, err
	}
	signed, err := verifiedEnvelopedElement(el, certs, idp.dsigClock())
	if errors.Is(err, errSignatureElementNotPresent) {
		return nil, classify(fmt.Errorf("the %s is not signed", el.Tag), ErrInvalidSignature)
	}
	if err != nil {
		return nil, classify(err, ErrInvalidSignature)
	}
	return signed, nil
}
